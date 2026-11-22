"""Tests for squawk.daemon_link (a client's lasting connection to the service).

The Node version has no separate test file for this class (its MCP tests
cover it); these check the same behaviour directly.
"""

import asyncio
import shutil
import tempfile
from collections.abc import AsyncIterator

import pytest

from squawk.crypto import ed25519_random_secret_key
from squawk.daemon import Daemon, MessageNotification
from squawk.daemon_link import DaemonLink, DaemonUnavailableError
from squawk.envelope import create_envelope
from squawk.identity import Identity, identity_from_secret_key, init_identity

alice = identity_from_secret_key("alice", ed25519_random_secret_key())


class Env:
    def __init__(self, home: str, me: Identity) -> None:
        self.home = home
        self.me = me
        self.daemon: Daemon | None = None
        self.logs: list[str] = []
        self.links: list[DaemonLink] = []

    async def start(self) -> Daemon:
        self.daemon = Daemon(self.home)
        await self.daemon.start()
        self.daemon.store.upsert_contact(alice.id, "alice")
        return self.daemon

    def link(self, label: str = "test") -> DaemonLink:
        link = DaemonLink(
            self.home, label, min_backoff_ms=20, max_backoff_ms=100, log=self.logs.append
        )
        self.links.append(link)
        return link


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    e = Env(home, init_identity(home, "me"))
    try:
        yield e
    finally:
        for link in e.links:
            await link.close()
        if e.daemon is not None:
            await e.daemon.stop()
        shutil.rmtree(home, ignore_errors=True)


async def test_open_returns_false_when_the_service_is_not_running(env: Env) -> None:
    link = env.link()
    assert await link.open() is False
    assert not link.connected
    with pytest.raises(DaemonUnavailableError, match="squawk daemon start"):
        await link.call("status")


async def test_registers_a_session_and_passes_on_messages_including_early_ones(
    env: Env,
) -> None:
    daemon = await env.start()
    queued = create_envelope(from_=alice.id, to=env.me.id, body="waiting")
    daemon.deliver_incoming(queued)
    link = env.link("worker")
    assert await link.open() is True
    assert link.connected
    status = await link.call("status")
    assert [s["label"] for s in status["sessions"]] == ["worker"]
    await link.call("status")  # the queued message has been pushed by now

    received: list[MessageNotification] = []
    link.on_message(received.append)
    assert [m["envelope"]["body"] for m in received] == ["waiting"]
    daemon.deliver_incoming(create_envelope(from_=alice.id, to=env.me.id, body="later"))
    await link.call("status")
    assert [m["envelope"]["body"] for m in received] == ["waiting", "later"]
    assert received[1]["from_name"] == "alice"


async def test_reconnects_and_registers_again_after_the_service_restarts(env: Env) -> None:
    daemon = await env.start()
    link = env.link("worker")
    assert await link.open()
    received: list[MessageNotification] = []
    link.on_message(received.append)

    await daemon.stop()
    reconnected = asyncio.ensure_future(link.when_reconnected())
    await asyncio.sleep(0.05)
    with pytest.raises(DaemonUnavailableError):
        await link.call("status")
    daemon = await env.start()
    await asyncio.wait_for(reconnected, 5)
    assert "lost the connection to squawkd; reconnecting" in env.logs
    assert "reconnected to squawkd" in env.logs

    daemon.deliver_incoming(create_envelope(from_=alice.id, to=env.me.id, body="after"))
    await link.call("status")
    assert [m["envelope"]["body"] for m in received] == ["after"]
