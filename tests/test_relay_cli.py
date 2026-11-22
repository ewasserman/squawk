"""Tests for `squawk relay`."""

import asyncio
import os
import re
from typing import Any

from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.cli_relay import relay_data_dir
from squawk.relay.storage import DB_FILE


async def wait_for_text(out: list[str], pattern: str, timeout: float = 5.0) -> re.Match[str]:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        match = re.search(pattern, "".join(out))
        if match is not None:
            return match
        if loop.time() > deadline:
            raise AssertionError(f"timed out waiting for {pattern!r} in {''.join(out)!r}")
        await asyncio.sleep(0.02)


async def test_relay_serve_runs_until_stopped(tmp_path: Any) -> None:
    data = os.path.join(str(tmp_path), "data")
    out: list[str] = []
    err: list[str] = []
    stop = asyncio.Event()
    io = CliIo(stdout=out.append, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)}, stop=stop)
    task = asyncio.create_task(run(["relay", "serve", "--port", "0", "--data", data], io))
    match = await wait_for_text(out, r"listening on ws://127\.0\.0\.1:(\d+)\n")
    port = int(match.group(1))
    assert "Relay key: " in "".join(out)

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    await writer.drain()
    response = await reader.read()
    writer.close()
    assert response.startswith(b"HTTP/1.1 200")

    stop.set()
    assert await asyncio.wait_for(task, 5) == 0
    assert "squawk relay stopped\n" in "".join(out)
    assert os.path.exists(os.path.join(data, DB_FILE))
    assert err == []


async def test_relay_without_a_subcommand_prints_usage(tmp_path: Any) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    assert await run(["relay"], io) == 2
    assert await run(["relay", "dance"], io) == 2
    assert "Usage: squawk relay <subcommand>" in "".join(err)
    assert "serve" in "".join(err)


async def test_relay_serve_refuses_a_bad_port(tmp_path: Any) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    assert await run(["relay", "serve", "--port", "http"], io) == 2
    assert await run(["relay", "serve", "--port", "70000"], io) == 2
    assert "not a port number" in "".join(err)


def test_relay_data_directory_defaults() -> None:
    assert relay_data_dir({"SQUAWK_RELAY_DATA": "/srv/relay", "SQUAWK_HOME": "/h"}) == "/srv/relay"
    assert relay_data_dir({"SQUAWK_HOME": "/h"}) == os.path.join("/h", "relay")


async def test_relay_serve_refuses_a_port_that_is_not_ascii_digits(tmp_path: Any) -> None:
    out: list[str] = []
    err: list[str] = []
    io = CliIo(stdout=out.append, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    assert await run(["relay", "serve", "--port", "\u00b2"], io) == 2
    assert "is not a port number" in "".join(err)
