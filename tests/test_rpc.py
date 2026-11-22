"""Tests for squawk.rpc (the Python version of test/rpc.test.ts)."""

import asyncio
import json
import os
import shutil
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest

from squawk.rpc import RpcClient, RpcConnection, RpcError, RpcErrorCode, RpcServer


async def poll(check: Callable[[], bool], timeout: float = 2.0) -> None:
    """Waits until `check()` is true."""
    deadline = asyncio.get_running_loop().time() + timeout
    while not check():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.01)


class Fixture:
    def __init__(self, path: str, server: RpcServer) -> None:
        self.path = path
        self.server = server
        self.clients: list[RpcClient] = []

    async def connect(self) -> RpcClient:
        client = await RpcClient.connect(self.path)
        self.clients.append(client)
        return client

    async def raw_exchange(self, text: str) -> Any:
        """Sends raw text and returns the first line the server writes back."""
        reader, writer = await asyncio.open_unix_connection(self.path)
        writer.write(text.encode())
        line = await reader.readline()
        writer.close()
        return json.loads(line)


@pytest.fixture
async def rpc() -> AsyncIterator[Fixture]:
    # Unix socket paths are limited to about 104 bytes on macOS, so keep it short.
    directory = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    path = os.path.join(directory, "s.sock")
    server = RpcServer()
    await server.listen(path)
    fixture = Fixture(path, server)
    try:
        yield fixture
    finally:
        for client in fixture.clients:
            await client.close()
        await server.close()
        shutil.rmtree(directory, ignore_errors=True)


async def test_answers_requests_with_results_including_from_async_handlers(rpc: Fixture) -> None:
    rpc.server.handle("add", lambda params, _c: params["a"] + params["b"])

    async def later(_params: Any, _c: RpcConnection) -> Any:
        await asyncio.sleep(0.01)
        return {"done": True}

    rpc.server.handle("later", later)
    client = await rpc.connect()
    total, done = await asyncio.gather(client.call("add", {"a": 2, "b": 3}), client.call("later"))
    assert total == 5
    assert done == {"done": True}


async def test_returns_errors_raised_by_handlers_with_their_code_and_message(
    rpc: Fixture,
) -> None:
    def fail(_params: Any, _c: RpcConnection) -> None:
        raise RpcError(RpcErrorCode.APPLICATION_ERROR, "nope", {"why": 1})

    def crash(_params: Any, _c: RpcConnection) -> None:
        raise RuntimeError("boom")

    rpc.server.handle("fail", fail)
    rpc.server.handle("crash", crash)
    client = await rpc.connect()
    with pytest.raises(RpcError) as failed:
        await client.call("fail")
    assert failed.value.code == RpcErrorCode.APPLICATION_ERROR
    assert failed.value.message == "nope"
    assert failed.value.data == {"why": 1}
    with pytest.raises(RpcError) as crashed:
        await client.call("crash")
    assert crashed.value.code == RpcErrorCode.INTERNAL_ERROR
    assert crashed.value.message == "boom"
    with pytest.raises(RpcError) as missing:
        await client.call("missing")
    assert missing.value.code == RpcErrorCode.METHOD_NOT_FOUND


async def test_pushes_notifications_from_the_server_to_a_client(rpc: Fixture) -> None:
    connections: list[RpcConnection] = []

    def hello(_params: Any, connection: RpcConnection) -> str:
        connections.append(connection)
        return "hi"

    rpc.server.handle("hello", hello)
    client = await rpc.connect()
    received: list[Any] = []
    client.on_notification("tick", received.append)
    await client.call("hello")
    connections[0].notify("tick", {"n": 1})
    connections[0].notify("tick", {"n": 2})
    await poll(lambda: received == [{"n": 1}, {"n": 2}])


async def test_handles_client_notifications_without_replying(rpc: Fixture) -> None:
    seen: list[Any] = []
    rpc.server.handle("note", lambda params, _c: seen.append(params))
    rpc.server.handle("ping", lambda _p, _c: "pong")
    client = await rpc.connect()
    client.notify("note", {"x": 1})
    assert await client.call("ping") == "pong"
    assert seen == [{"x": 1}]


async def test_reports_parse_errors_and_invalid_requests(rpc: Fixture) -> None:
    parse_error = await rpc.raw_exchange("not json\n")
    assert parse_error["jsonrpc"] == "2.0"
    assert parse_error["id"] is None
    assert parse_error["error"]["code"] == RpcErrorCode.PARSE_ERROR
    invalid = await rpc.raw_exchange('{"id":4,"method":"x"}\n')
    assert invalid["id"] == 4
    assert invalid["error"]["code"] == RpcErrorCode.INVALID_REQUEST


async def test_handles_a_message_split_across_writes_and_several_in_one_write(
    rpc: Fixture,
) -> None:
    rpc.server.handle("echo", lambda params, _c: params)
    reply = await rpc.raw_exchange('{"jsonrpc":"2.0","id":1,"method":"echo","params":"a"}\n')
    assert reply == {"jsonrpc": "2.0", "id": 1, "result": "a"}

    reader, writer = await asyncio.open_unix_connection(rpc.path)
    writer.write(b'{"jsonrpc":"2.0","id":1,"me')
    await writer.drain()
    await asyncio.sleep(0.01)
    writer.write(b'thod":"echo","params":1}\n{"jsonrpc":"2.0","id":2,"method":"echo","params":2}\n')
    lines = [await reader.readline(), await reader.readline()]
    writer.close()
    assert sorted(json.loads(line)["result"] for line in lines) == [1, 2]


async def test_tells_both_sides_when_the_connection_closes_and_fails_pending_calls(
    rpc: Fixture,
) -> None:
    server_side: list[RpcConnection] = []

    def hang(_params: Any, connection: RpcConnection) -> Awaitable[None]:
        server_side.append(connection)
        return asyncio.get_running_loop().create_future()

    rpc.server.handle("hang", hang)
    client = await rpc.connect()
    pending = asyncio.ensure_future(client.call("hang"))
    await poll(lambda: len(server_side) == 1)
    server_closed = asyncio.Event()
    server_side[0].on_close(server_closed.set)
    server_side[0].destroy()
    with pytest.raises(ConnectionError, match="closed"):
        await pending
    await server_closed.wait()
    assert client.closed
    assert server_side[0].notify("x") is False


async def test_fails_to_connect_when_nothing_is_listening(rpc: Fixture) -> None:
    with pytest.raises(OSError):
        await RpcClient.connect(os.path.join(os.path.dirname(rpc.path), "none.sock"))
