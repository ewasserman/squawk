"""A small JSON-RPC 2.0 server and client over unix sockets. Each message is
one line of JSON followed by "\\n".

Supported: requests (with an id, answered with a result or an error),
notifications in both directions (no id, never answered), and server code
pushing notifications to a connected client at any time. Batch requests (a
JSON array) are not supported and get an "invalid request" error.

This is the Python version of src/rpc.ts and speaks the same protocol, so a
client of either version can talk to a server of the other.
"""

import asyncio
import contextlib
import inspect
import sys
from collections.abc import Awaitable, Callable
from typing import Any

from squawk import jsontext


class RpcErrorCode:
    """Standard JSON-RPC 2.0 error codes, plus the one squawk uses for application errors."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    APPLICATION_ERROR = -32000
    """A well-formed call the server refused, such as sending to an unknown contact."""


MAX_LINE_BYTES = 16 * 1024 * 1024
"""Longest line accepted, in bytes. A peer that sends more is disconnected."""

CONNECTION_CLOSED = "connection to the server closed"


class RpcError(Exception):
    """An error carried in a JSON-RPC response. Raised by handlers and by `RpcClient.call`.

    `data` is optional extra information; None means there is none.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _is_object(value: object) -> bool:
    return isinstance(value, dict)


def _log_handler_error(where: str, err: BaseException) -> None:
    print(f"squawk rpc: {where} raised {type(err).__name__}: {err}", file=sys.stderr)


async def _read_lines(
    reader: asyncio.StreamReader,
    on_message: Callable[[Any], None],
    on_bad_line: Callable[[], object],
) -> None:
    """Reads lines until the connection ends and passes each parsed JSON value
    to `on_message`. Lines that are not JSON go to `on_bad_line`. Returns
    when the other side closes, or when it sends a line longer than
    `MAX_LINE_BYTES` (the caller then drops the connection)."""
    while True:
        try:
            raw = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError:
            return
        except asyncio.LimitOverrunError:
            # The line is too long.
            return
        except (ConnectionError, OSError):
            return
        line = jsontext.js_trim(raw.decode("utf-8", "replace"))
        if line == "":
            continue
        try:
            value = jsontext.parse(line)
        except ValueError:
            on_bad_line()
            continue
        on_message(value)


def _write_line(writer: asyncio.StreamWriter, value: object) -> bool:
    if writer.is_closing():
        return False
    writer.write((jsontext.stringify(value) + "\n").encode("utf-8"))
    return True


class RpcConnection:
    """One client connected to an `RpcServer`."""

    def __init__(self, id: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.id = id
        """A number unique among this server's connections."""
        self.reader = reader
        self.writer = writer
        self._close_handlers: list[Callable[[], object]] = []
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def notify(self, method: str, params: Any = None) -> bool:
        """Sends a notification to this client. Returns False if the connection is closed.

        `params` None means no params.
        """
        if self._closed:
            return False
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        return _write_line(self.writer, message)

    def on_close(self, handler: Callable[[], object]) -> None:
        """Runs `handler` once when the connection closes (immediately if it already has)."""
        if self._closed:
            handler()
        else:
            self._close_handlers.append(handler)

    def close(self) -> None:
        """Closes the connection after anything already written has been sent."""
        self.writer.close()

    def destroy(self) -> None:
        """Drops the connection at once, discarding anything not yet sent."""
        self.writer.transport.abort()

    def _mark_closed(self) -> None:
        if self._closed:
            return
        self._closed = True
        handlers, self._close_handlers = self._close_handlers, []
        for handler in handlers:
            try:
                handler()
            except Exception as err:
                _log_handler_error("a close handler", err)


RpcHandler = Callable[[Any, RpcConnection], Any]
"""Handles one method. `params` is whatever the client sent (None when it sent
none). Return the result (or an awaitable of it), or raise an `RpcError` to
send an error. Any other exception becomes an "internal error" response with
its message."""


class RpcServer:
    """A JSON-RPC 2.0 server listening on a unix socket.

    `on_call` is called before each request or notification from a client is
    handled; `on_connection` for each new connection.
    """

    def __init__(
        self,
        *,
        on_call: Callable[[RpcConnection, str], None] | None = None,
        on_connection: Callable[[RpcConnection], None] | None = None,
    ) -> None:
        self.connections: set[RpcConnection] = set()
        self._handlers: dict[str, RpcHandler] = {}
        self._on_call = on_call
        self._on_connection = on_connection
        self._server: asyncio.Server | None = None
        self._next_id = 1
        self._tasks: set[asyncio.Task[None]] = set()

    def handle(self, method: str, handler: RpcHandler) -> "RpcServer":
        """Registers the handler for `method`, replacing any earlier one."""
        self._handlers[method] = handler
        return self

    async def listen(self, path: str) -> None:
        """Starts listening on `path`. Raises if the path is in use."""
        self._server = await asyncio.start_unix_server(self._accept, path, limit=MAX_LINE_BYTES + 1)

    async def close(self) -> None:
        """Stops accepting connections and drops every open connection.

        Anything already written to a connection (such as the reply to a
        `stop` call) is still sent before it closes.
        """
        server = self._server
        self._server = None
        for connection in list(self.connections):
            connection.close()
        if server is not None:
            server.close()
            # wait_closed would also wait for every connection's handler to
            # end; the connections are closing anyway.
        for task in list(self._tasks):
            task.cancel()

    def _spawn(self, coro: Awaitable[None]) -> None:
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = RpcConnection(self._next_id, reader, writer)
        self._next_id += 1
        self.connections.add(connection)
        connection.on_close(lambda: self.connections.discard(connection))
        if self._on_connection is not None:
            self._on_connection(connection)

        def bad_line() -> None:
            _write_line(
                writer,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": RpcErrorCode.PARSE_ERROR, "message": "parse error"},
                },
            )

        try:
            await _read_lines(
                reader, lambda value: self._spawn(self._dispatch(connection, value)), bad_line
            )
        finally:
            writer.close()
            connection._mark_closed()

    async def _dispatch(self, connection: RpcConnection, message: Any) -> None:
        def reply(id: Any, body: dict[str, Any]) -> None:
            _write_line(connection.writer, {"jsonrpc": "2.0", "id": id, **body})

        if (
            not _is_object(message)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            id = message.get("id") if _is_object(message) else None
            if not (isinstance(id, str | int | float) and not isinstance(id, bool)):
                id = None
            reply(
                id,
                {"error": {"code": RpcErrorCode.INVALID_REQUEST, "message": "invalid request"}},
            )
            return
        has_id = "id" in message
        id = message.get("id")
        method: str = message["method"]
        handler = self._handlers.get(method)
        if handler is None:
            if has_id:
                reply(
                    id,
                    {
                        "error": {
                            "code": RpcErrorCode.METHOD_NOT_FOUND,
                            "message": f'unknown method "{method}"',
                        }
                    },
                )
            return
        try:
            if self._on_call is not None:
                self._on_call(connection, method)
            result = handler(message.get("params"), connection)
            if inspect.isawaitable(result):
                result = await result
            if has_id:
                reply(id, {"result": result})
        except asyncio.CancelledError:
            raise
        except Exception as err:
            if not has_id:
                return
            if isinstance(err, RpcError):
                error: dict[str, Any] = {"code": err.code, "message": err.message}
                if err.data is not None:
                    error["data"] = err.data
            else:
                error = {"code": RpcErrorCode.INTERNAL_ERROR, "message": str(err)}
            reply(id, {"error": error})


NotificationHandler = Callable[[Any], None]
"""Handles a notification sent by the server."""


class RpcClient:
    """A JSON-RPC 2.0 client for an `RpcServer`. Make one with `RpcClient.connect`."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._notification_handlers: dict[str, list[NotificationHandler]] = {}
        self._close_handlers: list[Callable[[], object]] = []
        self._next_id = 1
        self._closed = False
        self._reader_task = asyncio.ensure_future(self._read())

    @classmethod
    async def connect(cls, path: str) -> "RpcClient":
        """Connects to the server listening on `path`. Raises OSError if nothing is listening."""
        reader, writer = await asyncio.open_unix_connection(path, limit=MAX_LINE_BYTES + 1)
        return cls(reader, writer)

    @property
    def closed(self) -> bool:
        return self._closed

    async def call(self, method: str, params: Any = None) -> Any:
        """Calls `method` and returns its result, or raises an `RpcError`.

        `params` None means no params. Raises ConnectionError if the
        connection is closed before the answer arrives.
        """
        if self._closed:
            raise ConnectionError(CONNECTION_CLOSED)
        id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": id, "method": method}
        if params is not None:
            message["params"] = params
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        self._pending[id] = future
        _write_line(self.writer, message)
        try:
            return await future
        finally:
            self._pending.pop(id, None)

    def notify(self, method: str, params: Any = None) -> None:
        """Sends a notification (no response expected)."""
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        _write_line(self.writer, message)

    def on_notification(self, method: str, handler: NotificationHandler) -> Callable[[], object]:
        """Runs `handler` for each server notification named `method`.

        Returns a function that stops it.
        """
        handlers = self._notification_handlers.setdefault(method, [])
        handlers.append(handler)

        def stop() -> None:
            with contextlib.suppress(ValueError):
                handlers.remove(handler)

        return stop

    def on_close(self, handler: Callable[[], object]) -> None:
        """Runs `handler` once when the connection closes (immediately if it already has)."""
        if self._closed:
            handler()
        else:
            self._close_handlers.append(handler)

    async def close(self) -> None:
        """Closes the connection and waits until it is closed."""
        if not self.writer.is_closing():
            # Half-close, as Node's socket.end() does: the server sees the end
            # of input and closes its side, which ends our reader.
            with contextlib.suppress(OSError):
                if self.writer.can_write_eof():
                    self.writer.write_eof()
                else:
                    self.writer.close()
        try:
            await asyncio.wait_for(asyncio.shield(self._reader_task), 2)
        except TimeoutError:
            self.writer.transport.abort()
            await self._reader_task

    async def _read(self) -> None:
        try:
            await _read_lines(self.reader, self._receive, lambda: None)
        finally:
            self.writer.close()
            self._closed = True
            error = ConnectionError(CONNECTION_CLOSED)
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(error)
            self._pending.clear()
            handlers, self._close_handlers = self._close_handlers, []
            for handler in handlers:
                try:
                    handler()
                except Exception as err:
                    _log_handler_error("a close handler", err)

    def _receive(self, message: Any) -> None:
        if not _is_object(message):
            return
        if isinstance(message.get("method"), str) and "id" not in message:
            for handler in list(self._notification_handlers.get(message["method"], [])):
                try:
                    handler(message.get("params"))
                except Exception as err:
                    _log_handler_error(f'the handler for "{message["method"]}"', err)
            return
        id = message.get("id")
        if not isinstance(id, int) or isinstance(id, bool):
            return
        future = self._pending.pop(id, None)
        if future is None or future.done():
            return
        error = message.get("error")
        if _is_object(error):
            code = error.get("code")
            text = error.get("message")
            future.set_exception(
                RpcError(
                    int(code)
                    if isinstance(code, int | float) and not isinstance(code, bool)
                    else RpcErrorCode.INTERNAL_ERROR,
                    text if isinstance(text, str) else "unknown error",
                    error.get("data"),
                )
            )
        else:
            future.set_result(message.get("result"))
