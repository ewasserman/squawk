"""A client's lasting connection to the local background service (squawkd).

`DaemonLink` connects to the service's socket, registers a session with a
label, and passes on the `message` notifications the service pushes to that
session. If the connection drops (for example because the service was
restarted), it reconnects with exponential backoff and registers the session
again. While it is disconnected, `call` fails with `DaemonUnavailableError`.

This is the Python version of src/daemon-link.ts. It is not tied to any one
kind of client: a command that waits for messages can use it as well as a
long-running session.
"""

import asyncio
import contextlib
import sys
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, cast

from squawk.daemon import MessageNotification
from squawk.rpc import RpcClient


class DaemonApi(Protocol):
    """What a client needs from the service. Tests can supply their own."""

    async def call(self, method: str, params: Any = None) -> Any:
        """Calls a service method and returns its result."""
        ...

    def on_message(self, handler: Callable[[MessageNotification], None]) -> None:
        """Runs `handler` for each incoming message the service pushes to this session."""
        ...


class DaemonUnavailableError(Exception):
    """Raised by `DaemonLink.call` while there is no connection to the service."""

    def __init__(self) -> None:
        super().__init__(
            "not connected to squawkd (the squawk background service); retrying. "
            "If it keeps failing, run `squawk daemon start`."
        )


def _stderr_log(text: str) -> None:
    print(f"squawk: {text}", file=sys.stderr)


class DaemonLink:
    """See the module description.

    `home` is the squawk home directory and `label` the session label passed
    to `register_session`. The first reconnect delay is `min_backoff_ms`,
    doubling after each failure up to `max_backoff_ms`. `log` is where
    connection problems are reported (default: standard error). `connect`
    opens a connection; it defaults to `connect_to_daemon(home)`.
    """

    def __init__(
        self,
        home: str,
        label: str,
        *,
        min_backoff_ms: int = 250,
        max_backoff_ms: int = 10_000,
        log: Callable[[str], None] | None = None,
        connect: Callable[[], Awaitable[RpcClient | None]] | None = None,
    ) -> None:
        self.home = home
        self.label = label
        self._min_backoff_ms = min_backoff_ms
        self._max_backoff_ms = max_backoff_ms
        self._backoff_ms = min_backoff_ms
        self._log = _stderr_log if log is None else log
        self._connect = self._default_connect if connect is None else connect
        self._handlers: list[Callable[[MessageNotification], None]] = []
        self._early: list[MessageNotification] = []
        self._client: RpcClient | None = None
        self._closed = False
        self._retry: asyncio.TimerHandle | None = None
        self._retry_task: asyncio.Task[None] | None = None
        self._reconnected: list[asyncio.Future[None]] = []

    async def _default_connect(self) -> RpcClient | None:
        from squawk.daemon_control import connect_to_daemon

        return await connect_to_daemon(self.home)

    @property
    def connected(self) -> bool:
        """True while connected and registered."""
        return self._client is not None and not self._client.closed

    async def open(self) -> bool:
        """Connects and registers the session. Returns False (without retrying)
        if the service is not answering, so the caller can start it and try again."""
        return await self._attempt()

    async def call(self, method: str, params: Any = None) -> Any:
        client = self._client
        if client is None or client.closed:
            raise DaemonUnavailableError()
        return await client.call(method, params)

    def on_message(self, handler: Callable[[MessageNotification], None]) -> None:
        """Runs `handler` for each message the service pushes to this session.

        Messages that arrive before any handler is added (the service pushes
        queued messages right after registration) are kept and passed to the
        first handler.
        """
        self._handlers.append(handler)
        early, self._early = self._early, []
        for message in early:
            handler(message)

    async def when_reconnected(self) -> None:
        """Returns the next time the link connects and registers again."""
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._reconnected.append(future)
        await future

    async def close(self) -> None:
        """Closes the connection and stops reconnecting."""
        self._closed = True
        if self._retry is not None:
            self._retry.cancel()
        if self._retry_task is not None:
            self._retry_task.cancel()
        client = self._client
        self._client = None
        if client is not None and not client.closed:
            await client.close()

    async def _attempt(self) -> bool:
        client = await self._connect()
        if client is None:
            return False
        if self._closed:
            await client.close()
            return False

        def on_message(params: Any) -> None:
            message = cast(MessageNotification, params)
            if not self._handlers:
                self._early.append(message)
            for handler in list(self._handlers):
                handler(message)

        client.on_notification("message", on_message)
        try:
            await client.call("register_session", {"label": self.label})
        except Exception as err:
            self._log(f"could not register session: {err}")
            if not client.closed:
                await client.close()
            return False
        self._client = client
        self._backoff_ms = self._min_backoff_ms

        def on_close() -> None:
            if self._client is client:
                self._client = None
            if self._closed:
                return
            self._log("lost the connection to squawkd; reconnecting")
            self._schedule_retry()

        client.on_close(on_close)
        return True

    def _schedule_retry(self) -> None:
        if self._closed:
            return
        delay = self._backoff_ms
        self._backoff_ms = min(self._backoff_ms * 2, self._max_backoff_ms)
        self._retry = asyncio.get_running_loop().call_later(delay / 1000, self._start_retry)

    def _start_retry(self) -> None:
        self._retry_task = asyncio.ensure_future(self._retry_once())

    async def _retry_once(self) -> None:
        try:
            ok = await self._attempt()
        except Exception:
            ok = False
        if ok:
            self._log("reconnected to squawkd")
            waiting, self._reconnected = self._reconnected, []
            for future in waiting:
                with contextlib.suppress(asyncio.InvalidStateError):
                    future.set_result(None)
        else:
            self._schedule_retry()
