"""Tests for `squawk relay`, and for the relay in `squawk status` and `squawk contacts`."""

import asyncio
import json
import os
import re
import shutil
import socket
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast

import pytest

from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.cli_messages import format_service_status
from squawk.cli_relay import relay_data_dir
from squawk.config import db_path
from squawk.daemon import Daemon, StatusResult
from squawk.daemon_control import connect_to_daemon
from squawk.identity import init_identity
from squawk.network import NetworkTransport
from squawk.relay import RelayServer
from squawk.relay.storage import DB_FILE
from squawk.relay_client import RELAY_ALLOW_PLAIN_KEY, RELAY_URL_KEY, RelayClient
from squawk.rpc import RpcError
from squawk.store import Store


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


async def test_relay_serve_on_loopback_defaults_to_open_and_says_so(tmp_path: Any) -> None:
    out: list[str] = []
    stop = asyncio.Event()
    io = CliIo(
        stdout=out.append, stderr=lambda _: None, env={"SQUAWK_HOME": str(tmp_path)}, stop=stop
    )
    data = os.path.join(str(tmp_path), "data")
    task = asyncio.create_task(run(["relay", "serve", "--port", "0", "--data", data], io))
    await wait_for_text(out, r"Access: open\. Anyone who can reach this relay can open a mailbox")
    stop.set()
    assert await asyncio.wait_for(task, 5) == 0


async def test_relay_serve_with_access_open_on_every_address_starts(tmp_path: Any) -> None:
    out: list[str] = []
    stop = asyncio.Event()
    io = CliIo(
        stdout=out.append, stderr=lambda _: None, env={"SQUAWK_HOME": str(tmp_path)}, stop=stop
    )
    data = os.path.join(str(tmp_path), "data")
    args = ["relay", "serve", "--host", "0.0.0.0", "--port", "0", "--data", data]
    task = asyncio.create_task(run([*args, "--access", "open"], io))
    await wait_for_text(out, r"Access: open\.")
    stop.set()
    assert await asyncio.wait_for(task, 5) == 0


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        (["--host", "0.0.0.0"], "it listens on 0.0.0.0, which other machines can reach"),
        (["--host", "192.168.1.10"], "it listens on 192.168.1.10"),
        (["--trust-forwarded-for"], "it is behind a proxy (--trust-forwarded-for)"),
        (["--host", "::1", "--trust-forwarded-for"], "it is behind a proxy"),
    ],
)
async def test_relay_serve_refuses_to_start_without_access_unless_only_this_machine_can_reach_it(
    tmp_path: Any, extra: list[str], reason: str
) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    data = os.path.join(str(tmp_path), "data")
    assert await run(["relay", "serve", "--port", "0", "--data", data, *extra], io) == 2
    assert "choose who may use this relay with --access open|keys|github" in "".join(err)
    assert reason in "".join(err)
    assert not os.path.exists(data)


async def test_relay_serve_refuses_an_unknown_access_mode(tmp_path: Any) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    assert await run(["relay", "serve", "--access", "everyone"], io) == 2
    assert '"everyone" is not an access mode' in "".join(err)


async def test_relay_serve_checks_the_allowed_keys_options(tmp_path: Any) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    missing = os.path.join(str(tmp_path), "nope")
    assert await run(["relay", "serve", "--access", "keys"], io) == 2
    assert "--access keys needs --allowed-keys FILE" in "".join(err)
    assert await run(["relay", "serve", "--allowed-keys", missing], io) == 2
    assert "--allowed-keys is used only with --access keys" in "".join(err)
    assert await run(["relay", "serve", "--access", "keys", "--allowed-keys", missing], io) == 1
    assert f"squawk relay serve: cannot read {missing}" in "".join(err)


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (
            ["--access", "github", "--allowed-users", "f"],
            "--access github needs --github-client-id",
        ),
        (
            ["--access", "github", "--github-client-id", "x"],
            "--access github needs --allowed-users",
        ),
        (["--allowed-users", "f"], "--allowed-users is used only with --access github"),
        (["--github-client-id", "x"], "--github-client-id is used only with --access github"),
        (["--max-keys-per-user", "3"], "--max-keys-per-user is used only with --access github"),
        (
            ["--access", "keys", "--allowed-keys", "f", "--allowed-users", "f"],
            "--allowed-users is used only with --access github",
        ),
        (
            ["--access", "github", "--allowed-keys", "f"],
            "--allowed-keys is used only with --access keys",
        ),
        (
            [
                "--access",
                "github",
                "--github-client-id",
                "x",
                "--allowed-users",
                "f",
                "--max-keys-per-user",
                "0",
            ],
            '"0" is not a number of keys (1 or more)',
        ),
    ],
)
async def test_relay_serve_checks_the_github_options(
    tmp_path: Any, extra: list[str], message: str
) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    assert await run(["relay", "serve", *extra], io) == 2
    assert message in "".join(err)


async def test_relay_serve_in_github_mode_needs_a_readable_users_file(tmp_path: Any) -> None:
    err: list[str] = []
    io = CliIo(stdout=lambda _: None, stderr=err.append, env={"SQUAWK_HOME": str(tmp_path)})
    users = os.path.join(str(tmp_path), "users")
    args = ["relay", "serve", "--access", "github", "--github-client-id", "x"]
    assert await run([*args, "--allowed-users", users], io) == 1
    assert f"squawk relay serve: cannot read {users}" in "".join(err)
    with open(users, "w", encoding="utf-8") as file:
        file.write("alice\nnot a user\n")
    assert await run([*args, "--allowed-users", users], io) == 1
    assert f"squawk relay serve: {users}: line 2:" in "".join(err)


async def test_relay_serve_in_github_mode_says_how_many_users_it_admits(tmp_path: Any) -> None:
    out: list[str] = []
    stop = asyncio.Event()
    io = CliIo(
        stdout=out.append, stderr=lambda _: None, env={"SQUAWK_HOME": str(tmp_path)}, stop=stop
    )
    users = os.path.join(str(tmp_path), "users")
    with open(users, "w", encoding="utf-8") as file:
        file.write("# the team\nalice\nbob 202\n")
    data = os.path.join(str(tmp_path), "data")
    args = ["relay", "serve", "--port", "0", "--data", data, "--access", "github"]
    github = ["--github-client-id", "Iv1.abc", "--allowed-users", users]
    task = asyncio.create_task(run([*args, *github, "--max-keys-per-user", "3"], io))
    await wait_for_text(out, re.escape(f"Access:    github (2 users in {users})\n"))
    stop.set()
    assert await asyncio.wait_for(task, 5) == 0


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


# `squawk relay set` and `squawk relay status`, and the relay in `status` and `contacts`.


@dataclass
class Result:
    code: int
    out: str
    err: str


async def cli(home: str, *args: str) -> Result:
    out: list[str] = []
    err: list[str] = []
    io = CliIo(stdout=out.append, stderr=err.append, env={"SQUAWK_HOME": home})
    code = await run(list(args), io)
    return Result(code, "".join(out), "".join(err))


@pytest.fixture
async def home() -> AsyncIterator[str]:
    # Under /tmp: the service's socket path must stay short.
    path = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
async def relays(tmp_path: Any) -> AsyncIterator[list[RelayServer]]:
    """Two relays on this machine."""
    started = [RelayServer(os.path.join(str(tmp_path), f"relay{n}"), port=0) for n in (1, 2)]
    for relay in started:
        await relay.start()
    try:
        yield started
    finally:
        for relay in started:
            await relay.stop()


@pytest.fixture
async def service(home: str) -> AsyncIterator[Daemon]:
    init_identity(home, "alice")
    daemon = Daemon(home, transport=NetworkTransport(host="127.0.0.1", discovery=False))
    await daemon.start()
    try:
        yield daemon
    finally:
        await daemon.stop()


def url_of(relay: RelayServer) -> str:
    return f"ws://127.0.0.1:{relay.port}"


def stored_settings(home: str) -> tuple[str | None, str | None]:
    store = Store.open(db_path(home))
    try:
        return store.get_setting(RELAY_URL_KEY), store.get_setting(RELAY_ALLOW_PLAIN_KEY)
    finally:
        store.close()


async def test_relay_set_without_the_service_stores_the_relay_for_its_next_start(
    home: str,
) -> None:
    result = await cli(home, "relay", "set", "wss://relay.example.com/")
    assert result.code == 0, result.err
    assert result.out == (
        "Relay set to wss://relay.example.com.\n"
        "The squawk service is not running; it connects to the relay when it starts "
        "(`squawk daemon start`).\n"
    )
    assert stored_settings(home) == ("wss://relay.example.com", None)

    status = await cli(home, "relay", "status")
    assert status.code == 0
    assert status.out == (
        "Relay:           wss://relay.example.com\n"
        "Connected:       no (the squawk service is not running)\n"
        "Relay key:       unknown (not connected yet)\n"
        "Queued outbound: 0\n"
        "Held at relay:   0 (waiting for the recipient's receipt)\n"
    )

    off = await cli(home, "relay", "set", "--off")
    assert off.code == 0
    assert off.out == "Relay removed. Messages go only over the local network.\n"
    assert stored_settings(home) == (None, None)
    assert (await cli(home, "relay", "status")).out.startswith("Relay:           none")


async def test_relay_set_refuses_plain_ws_without_the_opt_in_and_bad_usage(home: str) -> None:
    plain = await cli(home, "relay", "set", "ws://localhost:8765")
    assert plain.code == 1
    assert "--allow-plain" in plain.err
    assert not os.path.exists(db_path(home))

    allowed = await cli(home, "relay", "set", "ws://localhost:8765", "--allow-plain")
    assert allowed.code == 0, allowed.err
    assert "not encrypted (ws://)" in allowed.out
    assert stored_settings(home) == ("ws://localhost:8765", "on")
    # Setting a wss:// relay drops the earlier opt-in.
    assert (await cli(home, "relay", "set", "wss://relay.example.com")).code == 0
    assert stored_settings(home) == ("wss://relay.example.com", None)

    bad = await cli(home, "relay", "set", "https://relay.example.com")
    assert bad.code == 1 and "is not a relay URL" in bad.err
    for args in (
        ["relay", "set"],
        ["relay", "set", "--off", "wss://a.example"],
        ["relay", "set", "--off", "--allow-plain"],
        ["relay", "set", "wss://a.example", "wss://b.example"],
    ):
        usage = await cli(home, *args)
        assert usage.code == 2, args
        assert "Usage: squawk relay set" in usage.err


async def test_relay_set_switches_the_running_service_without_a_restart(
    service: Daemon, relays: list[RelayServer]
) -> None:
    home = service.home
    first, second = relays
    transport = service.transport
    assert isinstance(transport, NetworkTransport)

    result = await cli(home, "relay", "set", url_of(first), "--allow-plain")
    assert result.code == 0, result.err
    assert f"Relay set to {url_of(first)}." in result.out
    assert f"Connected. Relay key: {first.key_id}" in result.out
    assert transport.relay is not None and transport.relay.connected

    status = await cli(home, "relay", "status")
    assert status.out == (
        f"Relay:           {url_of(first)}\n"
        "Connected:       yes\n"
        f"Relay key:       {first.key_id}\n"
        "Queued outbound: 0\n"
        "Held at relay:   0 (waiting for the recipient's receipt)\n"
    )
    service_status = await cli(home, "status")
    assert f"Relay:           {url_of(first)}  connected\n" in service_status.out
    assert "Held at relay:   0 (queued outbound messages" in service_status.out

    # Switching to another relay closes the first connection.
    old = transport.relay
    switched = await cli(home, "relay", "set", url_of(second), "--allow-plain")
    assert f"Connected. Relay key: {second.key_id}" in switched.out
    assert transport.relay is not old and not old.connected
    assert transport.relay is not None and transport.relay.url == url_of(second)

    off = await cli(home, "relay", "set", "--off")
    assert off.code == 0
    assert transport.relay is None
    assert service.status()["relay"] is None
    assert "Relay:           none (local network only" in (await cli(home, "status")).out


async def test_relay_status_shows_why_the_service_cannot_connect(service: Daemon) -> None:
    unused = socket.socket()
    unused.bind(("127.0.0.1", 0))
    url = f"ws://127.0.0.1:{unused.getsockname()[1]}"
    unused.close()

    result = await cli(service.home, "relay", "set", url, "--allow-plain")
    assert result.code == 0, result.err
    assert "Not connected yet: " in result.out
    status = await cli(service.home, "relay", "status")
    assert "Connected:       no\n" in status.out
    assert "Last error:      " in status.out
    assert f"Relay:           {url}  NOT connected (" in (await cli(service.home, "status")).out


async def test_the_running_service_refuses_a_bad_relay_url(service: Daemon) -> None:
    client = await connect_to_daemon(service.home)
    assert client is not None
    try:
        with pytest.raises(RpcError, match="not encrypted"):
            await client.call("set_relay", {"url": "ws://localhost:8765"})
        with pytest.raises(RpcError):
            await client.call("set_relay", {})
    finally:
        await client.close()
    assert service.store.get_setting(RELAY_URL_KEY) is None


async def test_switching_relays_keeps_the_callbacks_set_on_the_old_client() -> None:
    transport = NetworkTransport(host="127.0.0.1", discovery=False)
    first = RelayClient("wss://one.example")

    def on_live(_envelope: Any) -> None:
        pass

    def on_ready() -> None:
        pass

    first.on_live = on_live
    first.on_ready.append(on_ready)
    transport.relay = first
    second = RelayClient("wss://two.example")
    # The transport is not started, so the new client is only put in place.
    await transport.use_relay(second)
    assert transport.relay is second
    # The transport's own handler for live requests, whatever the old client had.
    assert second.on_live == transport._on_live
    assert second.on_ready == [on_ready]


async def test_a_relay_set_after_starting_without_one_answers_live_requests() -> None:
    transport = NetworkTransport(host="127.0.0.1", discovery=False)
    relay = RelayClient("wss://one.example")
    await transport.use_relay(relay)
    assert relay.on_live == transport._on_live


async def test_contacts_show_the_route_to_each_contact(service: Daemon) -> None:
    service.store.upsert_contact("A" * 43, "bob", trust="paired")
    service.store.upsert_contact(
        "Q" * 43, "carol", trust="paired", relay_url="wss://relay.example.com"
    )
    listed = await cli(service.home, "contacts")
    lines = listed.out.splitlines()
    assert lines[0].startswith("bob ") and lines[0].endswith("  route=local network")
    assert lines[1].startswith("carol ")
    assert lines[1].endswith("  route=relay wss://relay.example.com")
    contacts = json.loads((await cli(service.home, "contacts", "--json")).out)
    assert [c["relay_url"] for c in contacts] == [None, "wss://relay.example.com"]


def test_status_from_a_service_without_relay_fields_prints_no_relay_lines() -> None:
    status: dict[str, Any] = {
        "name": "alice",
        "key_id": "K",
        "fingerprint": "F",
        "pid": 1,
        "sessions": [],
        "queued_inbound": 0,
        "queued_outbound": 2,
        "port": 1234,
        "catch_all": None,
    }
    text = format_service_status(cast(StatusResult, status))
    assert "Relay" not in text and "Held at relay" not in text
    status["relay"] = {
        "url": "wss://relay.example.com",
        "connected": False,
        "relay_key": None,
        "last_error": None,
    }
    status["relayed_outbound"] = 1
    text = format_service_status(cast(StatusResult, status))
    assert "Relay:           wss://relay.example.com  NOT connected\n" in text
    assert "Held at relay:   1 (" in text
