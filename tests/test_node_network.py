"""Checks that a Python service and a Node service work together over the
real network code on 127.0.0.1: they pair in both directions (each side
initiating once), send messages each way, and acknowledge them.

Both services run as separate background processes, started the way a user
starts them (`node src/cli.ts daemon start` for Node, `start_daemon` for
Python), with mDNS turned off (SQUAWK_NO_MDNS=1); pairing uses host:port.
The test talks to each service through its local socket with the Python
RpcClient, so it also checks that the local control protocol matches.

Skipped when `node` is not installed or the Node dependencies have not been
installed with `pnpm install`.
"""

import asyncio
import contextlib
import os
import shutil
import signal
import subprocess
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from squawk.config import pid_path, socket_path
from squawk.daemon_control import start_daemon, stop_daemon
from squawk.identity import init_identity
from squawk.rpc import RpcClient, RpcError

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None or not (ROOT / "node_modules").is_dir(),
    reason="needs node and the Node dependencies (pnpm install)",
)

# Text outside ASCII and outside the Basic Multilingual Plane, a line break
# and a quote, to check the body arrives unchanged.
BODY_FROM_PYTHON = 'hello from python: caf\u00e9 \U0001f600\nsecond "line"'
BODY_FROM_NODE = "hello from node: \u2603 \u00fc"


def service_env(home: str) -> dict[str, str]:
    return {**os.environ, "SQUAWK_HOME": home, "SQUAWK_NO_MDNS": "1", "SQUAWK_PORT": "0"}


def node_cli(home: str, *args: str) -> subprocess.CompletedProcess[str]:
    assert NODE is not None
    return subprocess.run(
        [NODE, str(ROOT / "src" / "cli.ts"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=service_env(home),
        timeout=30,
        check=False,
    )


@dataclass
class Service:
    name: str
    home: str
    rpc: RpcClient
    key_id: str
    port: int
    notifications: list[Any]


async def connect(name: str, home: str) -> Service:
    rpc = await RpcClient.connect(socket_path(home))
    status = await rpc.call("status")
    notifications: list[Any] = []
    rpc.on_notification("message", notifications.append)
    assert await rpc.call("subscribe") == {"ok": True}
    return Service(name, home, rpc, status["key_id"], status["port"], notifications)


async def eventually(check: Callable[[], Awaitable[Any]], timeout: float = 10.0) -> Any:
    """Calls `check` until it returns something true without raising RpcError."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            value = await check()
            if value:
                return value
        except RpcError:
            pass
        if loop.time() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.05)


class Services:
    def __init__(self) -> None:
        self.homes: list[str] = []
        self.services: list[Service] = []

    def home(self) -> str:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        return home

    async def start_node(self, name: str) -> Service:
        home = self.home()
        init = node_cli(home, "init", "--name", name)
        assert init.returncode == 0, init.stderr
        started = node_cli(home, "daemon", "start")
        assert started.returncode == 0, started.stdout + started.stderr
        service = await connect(name, home)
        self.services.append(service)
        return service

    async def start_python(self, name: str) -> Service:
        home = self.home()
        init_identity(home, name)
        await start_daemon(home, service_env(home))
        service = await connect(name, home)
        self.services.append(service)
        return service

    async def close(self) -> None:
        for service in self.services:
            await service.rpc.close()
        for home in self.homes:
            pid = read_pid(home)
            try:
                await stop_daemon(home)
            finally:
                # If it did not stop, end that exact process.
                if pid is not None and alive(pid):
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(pid, signal.SIGTERM)
            shutil.rmtree(home, ignore_errors=True)


def read_pid(home: str) -> int | None:
    try:
        with open(pid_path(home)) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.fixture
async def services() -> AsyncIterator[Services]:
    s = Services()
    try:
        yield s
    finally:
        await s.close()


async def pair(initiator: Service, responder: Service) -> None:
    """Pairs two services through their sockets, as `squawk pair` would."""
    waiting = asyncio.ensure_future(responder.rpc.call("pair_accept"))
    # Give the responder a moment to start waiting.
    await asyncio.sleep(0.3)
    offer = await initiator.rpc.call("pair_start", {"peer": f"127.0.0.1:{responder.port}"})
    their_offer = await waiting
    assert offer["code"] == their_offer["code"]
    assert len(offer["code"]) == 6 and offer["code"].isdigit()
    assert offer["peer_key"] == responder.key_id
    assert offer["peer_name"] == responder.name
    assert their_offer["peer_key"] == initiator.key_id
    assert their_offer["peer_name"] == initiator.name
    mine, theirs = await asyncio.gather(
        initiator.rpc.call("pair_confirm", {"pairing_id": offer["pairing_id"], "match": True}),
        responder.rpc.call(
            "pair_confirm", {"pairing_id": their_offer["pairing_id"], "match": True}
        ),
    )
    assert mine["status"] == "paired" and mine["contact"]["key_id"] == responder.key_id
    assert theirs["status"] == "paired" and theirs["contact"]["key_id"] == initiator.key_id
    for side, other in ((initiator, responder), (responder, initiator)):
        contacts = (await side.rpc.call("contacts"))["contacts"]
        assert [(c["name"], c["key_id"], c["trust"]) for c in contacts] == [
            (other.name, other.key_id, "paired")
        ]


async def send_and_check(
    sender: Service, receiver: Service, body: str, in_reply_to: str | None = None
) -> dict[str, Any]:
    """Sends a message and checks that it arrives, is announced to the
    receiver's subscribers and is acknowledged. Returns the received message."""
    params: dict[str, Any] = {"to": receiver.name, "body": body}
    if in_reply_to is not None:
        params["in_reply_to"] = in_reply_to
    sent = await sender.rpc.call("send", params)
    assert sent["state"] == "queued"

    async def arrived() -> Any:
        return (await receiver.rpc.call("get_message", {"id": sent["id"]}))["message"]

    received = await eventually(arrived)
    assert received["direction"] == "in"
    assert received["body"] == body
    assert received["peer"] == sender.key_id
    assert received["peer_name"] == sender.name
    assert received["thread_id"] == sent["thread_id"]
    assert received["in_reply_to"] == in_reply_to

    async def acked() -> bool:
        message = (await sender.rpc.call("get_message", {"id": sent["id"]}))["message"]
        return bool(message["state"] == "acked")

    await eventually(acked)
    note = next(n for n in receiver.notifications if n["envelope"]["id"] == sent["id"])
    assert note["envelope"]["body"] == body
    assert note["envelope"]["from"] == sender.key_id
    assert note["from_name"] == sender.name
    assert note["policy"] == "show_first"
    status = await sender.rpc.call("status")
    assert status["queued_outbound"] == 0
    return dict(received)


async def test_python_pairs_with_node_and_messages_flow_both_ways(services: Services) -> None:
    node = await services.start_node("node-side")
    python = await services.start_python("python-side")

    await pair(initiator=python, responder=node)
    question = await send_and_check(python, node, BODY_FROM_PYTHON)
    answer = await send_and_check(node, python, BODY_FROM_NODE, in_reply_to=question["id"])
    # The reply joined the thread of the message it answers.
    assert answer["thread_id"] == question["thread_id"]


async def test_node_pairs_with_python_and_messages_flow_both_ways(services: Services) -> None:
    node = await services.start_node("node-side")
    python = await services.start_python("python-side")

    await pair(initiator=node, responder=python)
    question = await send_and_check(node, python, BODY_FROM_NODE)
    answer = await send_and_check(python, node, BODY_FROM_PYTHON, in_reply_to=question["id"])
    assert answer["thread_id"] == question["thread_id"]
