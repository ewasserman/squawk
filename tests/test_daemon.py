"""Tests for squawk.daemon (the Python version of test/daemon.test.ts)."""

import asyncio
import os
import re
import shutil
import stat
import tempfile
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from squawk.config import pid_path, run_dir, socket_path
from squawk.crypto import ed25519_random_secret_key
from squawk.daemon import (
    Daemon,
    DaemonRunningError,
    IncomingResult,
    MessageNotification,
    Transport,
)
from squawk.envelope import Envelope, create_envelope
from squawk.identity import Identity, identity_from_secret_key, init_identity
from squawk.rpc import RpcClient, RpcError, RpcErrorCode

alice = identity_from_secret_key("alice", ed25519_random_secret_key())


async def poll(check: Callable[[], bool], timeout: float = 3.0) -> None:
    """Waits until `check()` is true."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not check():
        if loop.time() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.01)


class RecordingTransport(Transport):
    def __init__(self) -> None:
        self.kicked: list[Envelope] = []

    def kick(self, envelope: Envelope) -> None:
        self.kicked.append(envelope)


class FakeSession:
    def __init__(self, client: RpcClient, label: str) -> None:
        self.client = client
        self.label = label
        self.messages: list[MessageNotification] = []

    def bodies(self) -> list[str]:
        return [m["envelope"]["body"] for m in self.messages]


class Env:
    def __init__(self, home: str, me: Identity, daemon: Daemon, transport: RecordingTransport):
        self.home = home
        self.me = me
        self.daemon = daemon
        self.transport = transport
        self.clients: list[RpcClient] = []

    async def connect(self) -> RpcClient:
        client = await RpcClient.connect(socket_path(self.home))
        self.clients.append(client)
        return client

    async def open_session(self, label: str) -> FakeSession:
        """Connects over the real socket and registers a session with `label`."""
        client = await self.connect()
        session = FakeSession(client, label)
        client.on_notification("message", session.messages.append)
        result = await client.call("register_session", {"label": label})
        assert result["label"] == label
        assert re.fullmatch(r"[0-9a-f-]{36}", result["session_id"])
        return session

    def incoming(self, body: str, session: str | None = None) -> Envelope:
        return create_envelope(from_=alice.id, to=self.me.id, body=body, session=session)


async def settle(*sessions: FakeSession) -> None:
    """Waits for notifications in flight by making a round trip on each client."""
    for s in sessions:
        await s.client.call("status")


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    # Unix socket paths are limited to about 104 bytes on macOS, so keep it short.
    home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    me = init_identity(home, "me")
    transport = RecordingTransport()
    daemon = Daemon(home, transport=transport)
    await daemon.start()
    daemon.store.upsert_contact(alice.id, "alice", inbound_policy="auto_answer")
    e = Env(home, me, daemon, transport)
    try:
        yield e
    finally:
        for client in e.clients:
            if not client.closed:
                await client.close()
        await e.daemon.stop()
        shutil.rmtree(home, ignore_errors=True)


# Routing


async def test_delivers_to_the_session_the_envelope_names(env: Env) -> None:
    a = await env.open_session("a")
    b = await env.open_session("b")
    await a.client.call("status")  # a is now the most recently active
    result = env.daemon.deliver_incoming(env.incoming("for b", "b"))
    assert result == IncomingResult(stored=True, delivered_to="b")
    await poll(lambda: b.bodies() == ["for b"])
    await settle(a)
    assert a.bodies() == []
    first = b.messages[0]
    assert first["from_name"] == "alice"
    assert first["policy"] == "auto_answer"
    assert first["envelope"]["from"] == alice.id
    assert first["envelope"]["to"] == env.me.id
    assert first["envelope"]["session"] == "b"


async def test_delivers_to_the_most_recently_active_session_when_none_is_named(
    env: Env,
) -> None:
    a = await env.open_session("a")
    b = await env.open_session("b")
    # b registered last, so it is the most recent until a makes a call.
    env.daemon.deliver_incoming(env.incoming("first"))
    await poll(lambda: b.bodies() == ["first"])

    await a.client.call("peers")
    env.daemon.deliver_incoming(env.incoming("second"))
    env.daemon.deliver_incoming(env.incoming("third", "nobody"))
    await poll(lambda: a.bodies() == ["second", "third"])
    await settle(b)
    assert b.bodies() == ["first"]


async def test_queues_messages_while_no_session_is_open_and_delivers_them_once(
    env: Env,
) -> None:
    first = env.incoming("queued one")
    assert env.daemon.deliver_incoming(first) == IncomingResult(stored=True, delivered_to=None)
    env.daemon.deliver_incoming(env.incoming("queued two", "elsewhere"))
    assert env.daemon.status()["queued_inbound"] == 2

    a = await env.open_session("a")
    await poll(lambda: a.bodies() == ["queued one", "queued two"])
    assert env.daemon.status()["queued_inbound"] == 0
    stored = env.daemon.store.get_message(first["id"])
    assert stored is not None and stored.delivered_at is not None

    b = await env.open_session("b")
    await settle(a, b)
    assert b.bodies() == []
    assert len(a.messages) == 2


async def test_delivers_a_queued_message_to_its_named_session_when_it_registers(
    env: Env,
) -> None:
    env.daemon.deliver_incoming(env.incoming("for b", "b"))
    b = await env.open_session("b")
    await poll(lambda: b.bodies() == ["for b"])


async def test_unregisters_a_session_when_its_connection_closes(env: Env) -> None:
    a = await env.open_session("a")
    await a.client.close()
    await poll(lambda: env.daemon.status()["sessions"] == [])
    assert env.daemon.deliver_incoming(env.incoming("later")).delivered_to is None


async def test_routes_to_the_newest_registration_when_labels_repeat(env: Env) -> None:
    old = await env.open_session("same")
    newer = await env.open_session("same")
    await old.client.call("status")
    env.daemon.deliver_incoming(env.incoming("hi", "same"))
    await poll(lambda: newer.bodies() == ["hi"])
    await settle(old)
    assert old.bodies() == []


async def test_ignores_a_message_whose_id_was_already_stored(env: Env) -> None:
    envelope = env.incoming("once")
    a = await env.open_session("a")
    env.daemon.deliver_incoming(envelope)
    assert env.daemon.deliver_incoming(envelope) == IncomingResult(stored=False, delivered_to=None)
    await settle(a)
    assert a.bodies() == ["once"]


async def test_sends_every_incoming_message_to_subscribers(env: Env) -> None:
    a = await env.open_session("a")
    tail = await env.connect()
    seen: list[MessageNotification] = []
    tail.on_notification("message", seen.append)
    assert await tail.call("subscribe") == {"ok": True}
    env.daemon.deliver_incoming(env.incoming("one"))
    env.daemon.deliver_incoming(env.incoming("two", "a"))
    await poll(lambda: [m["envelope"]["body"] for m in seen] == ["one", "two"])
    await poll(lambda: a.bodies() == ["one", "two"])


# Methods


async def test_send_queues_a_message_for_a_contact_by_name_and_kicks_the_transport(
    env: Env,
) -> None:
    client = await env.connect()
    result = await client.call(
        "send", {"to": "alice", "body": "hello", "kind": "question", "session": "x"}
    )
    assert result["state"] == "queued"
    assert result["thread_id"] == result["id"]
    item = env.daemon.store.get_outbound(result["id"])
    assert item is not None
    assert item.recipient == alice.id
    envelope: dict[str, Any] = dict(item.envelope)
    assert envelope["id"] == result["id"]
    assert envelope["from"] == env.me.id
    assert envelope["to"] == alice.id
    assert envelope["body"] == "hello"
    assert envelope["kind"] == "question"
    assert envelope["session"] == "x"
    assert env.transport.kicked == [item.envelope]
    stored = env.daemon.store.get_message(result["id"])
    assert stored is not None and stored.state == "queued"
    assert env.daemon.status()["queued_outbound"] == 1

    by_key = await client.call(
        "send",
        {
            "to": alice.id,
            "body": "again",
            "thread_id": result["thread_id"],
            "in_reply_to": result["id"],
        },
    )
    again = env.daemon.store.get_message(by_key["id"])
    assert again is not None and again.thread_id == result["thread_id"]


async def test_a_reply_joins_the_thread_of_the_message_it_answers(env: Env) -> None:
    first = await env.daemon.send({"to": "alice", "body": "first"})
    reply = await env.daemon.send({"to": "alice", "body": "reply", "in_reply_to": first["id"]})
    assert reply["thread_id"] == first["thread_id"]


async def test_send_to_an_unknown_contact_is_an_error_with_a_clear_message(env: Env) -> None:
    client = await env.connect()
    with pytest.raises(RpcError) as unknown:
        await client.call("send", {"to": "mallory", "body": "hi"})
    assert unknown.value.code == RpcErrorCode.APPLICATION_ERROR
    assert 'unknown contact "mallory"' in unknown.value.message
    with pytest.raises(RpcError) as no_to:
        await client.call("send", {"body": "no to"})
    assert no_to.value.code == RpcErrorCode.INVALID_PARAMS


async def test_inbox_lists_unread_messages_and_can_mark_them_read(env: Env) -> None:
    env.daemon.deliver_incoming(env.incoming("unread"))
    client = await env.connect()
    first = await client.call("inbox", {"mark_read": True})
    assert [m["envelope"]["body"] for m in first["messages"]] == ["unread"]
    assert first["messages"][0]["from_name"] == "alice"
    second = await client.call("inbox")
    assert second["messages"] == []


async def test_get_message_returns_a_stored_message_incoming_or_outgoing(env: Env) -> None:
    envelope = env.incoming("a question")
    env.daemon.deliver_incoming(envelope)
    client = await env.connect()
    got = await client.call("get_message", {"id": envelope["id"]})
    assert got["message"] == {
        "id": envelope["id"],
        "direction": "in",
        "peer": alice.id,
        "peer_name": "alice",
        "session": None,
        "thread_id": envelope["thread_id"],
        "in_reply_to": None,
        "kind": "text",
        "body": "a question",
        "created_at": envelope["created_at"],
        "state": "unread",
    }

    sent = await client.call("send", {"to": "alice", "body": "out"})
    out = await client.call("get_message", {"id": sent["id"]})
    assert out["message"]["direction"] == "out"
    assert out["message"]["peer"] == alice.id
    assert out["message"]["body"] == "out"

    with pytest.raises(RpcError) as nope:
        await client.call("get_message", {"id": "nope"})
    assert nope.value.code == RpcErrorCode.APPLICATION_ERROR
    assert 'no message with id "nope"' in nope.value.message
    with pytest.raises(RpcError) as empty:
        await client.call("get_message", {})
    assert empty.value.code == RpcErrorCode.INVALID_PARAMS


async def test_refuses_to_send_to_a_blocked_contact(env: Env) -> None:
    env.daemon.store.update_contact(alice.id, trust="blocked")
    with pytest.raises(RpcError, match="is blocked"):
        await env.daemon.send({"to": "alice", "body": "hi"})
    assert env.daemon.store.count_outbound() == 0


async def test_shuts_down_instead_of_running_half_started_when_the_transport_fails(
    env: Env,
) -> None:
    await env.daemon.stop()

    class Failing(Transport):
        async def start(self, daemon: Daemon) -> None:
            raise RuntimeError("port in use")

    failing = Daemon(env.home, transport=Failing())
    with pytest.raises(RuntimeError, match="port in use"):
        await failing.start()
    assert not os.path.exists(socket_path(env.home))
    assert not os.path.exists(pid_path(env.home))
    env.daemon = Daemon(env.home)
    await env.daemon.start()


async def test_contacts_lists_contacts_with_their_fingerprint_and_policy(env: Env) -> None:
    client = await env.connect()
    result = await client.call("contacts")
    assert result["default_auto_send"] is False
    contacts = result["contacts"]
    assert len(contacts) == 1
    assert isinstance(contacts[0].pop("fingerprint"), str)
    assert contacts == [
        {
            "name": "alice",
            "key_id": alice.id,
            "trust": "paired",
            "auto_send": False,
            "auto_send_is_default": True,
            "inbound_policy": "auto_answer",
            "policy_is_default": False,
        }
    ]


async def test_update_contact_and_set_default_policy(env: Env) -> None:
    client = await env.connect()
    updated = await client.call(
        "update_contact", {"contact": "alice", "auto_send": True, "inbound_policy": None}
    )
    assert updated["contact"]["auto_send"] is True
    assert updated["contact"]["inbound_policy"] == "show_first"
    assert updated["contact"]["policy_is_default"] is True
    assert await client.call("set_default_policy", {"policy": "auto_answer"}) == {
        "policy": "auto_answer"
    }
    contacts = await client.call("contacts")
    assert contacts["contacts"][0]["inbound_policy"] == "auto_answer"
    with pytest.raises(RpcError) as bad:
        await client.call("set_default_policy", {"policy": "anything"})
    assert bad.value.code == RpcErrorCode.INVALID_PARAMS


async def test_status_and_peers_report_the_service_state(env: Env) -> None:
    a = await env.open_session("a")
    status = await a.client.call("status")
    assert status["name"] == "me"
    assert status["key_id"] == env.me.id
    assert status["pid"] == os.getpid()
    assert status["queued_inbound"] == 0
    assert status["queued_outbound"] == 0
    assert status["port"] is None
    assert [s["label"] for s in status["sessions"]] == ["a"]
    assert isinstance(status["sessions"][0]["last_active"], str)
    assert await a.client.call("peers") == {"peers": []}


async def test_stop_over_the_socket_shuts_the_service_down(env: Env) -> None:
    client = await env.connect()
    assert await client.call("stop") == {"ok": True}
    await env.daemon.when_stopped()
    with pytest.raises(OSError):
        await RpcClient.connect(socket_path(env.home))
    assert not os.path.exists(pid_path(env.home))


# Socket


async def test_uses_mode_0700_for_run_and_0600_for_the_socket_and_writes_a_pid_file(
    env: Env,
) -> None:
    assert stat.S_IMODE(os.stat(run_dir(env.home)).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(socket_path(env.home)).st_mode) == 0o600
    assert os.path.isfile(pid_path(env.home))
    with open(pid_path(env.home)) as f:
        assert f.read() == f"{os.getpid()}\n"


async def test_refuses_to_start_a_second_service_on_the_same_socket(env: Env) -> None:
    second = Daemon(env.home)
    with pytest.raises(DaemonRunningError):
        await second.start()


async def test_replaces_a_stale_socket_file_when_nothing_is_listening(env: Env) -> None:
    await env.daemon.stop()
    os.makedirs(run_dir(env.home), exist_ok=True)
    with open(socket_path(env.home), "w"):
        pass
    env.daemon = Daemon(env.home)
    await env.daemon.start()
    client = await env.connect()
    assert await client.call("peers") == {"peers": []}


async def test_auto_send_follows_the_default_unless_the_contact_has_its_own_setting(
    env: Env,
) -> None:
    client = await env.connect()

    async def alice_auto_send() -> tuple[bool, bool]:
        contact = (await client.call("contacts"))["contacts"][0]
        return contact["auto_send"], contact["auto_send_is_default"]

    assert await alice_auto_send() == (False, True)
    assert await client.call("set_default_auto_send", {"auto_send": True}) == {"auto_send": True}
    assert (await client.call("contacts"))["default_auto_send"] is True
    assert await alice_auto_send() == (True, True)

    # The contact's own "off" wins over the default "on".
    updated = await client.call("update_contact", {"contact": "alice", "auto_send": False})
    assert updated["contact"]["auto_send"] is False
    assert updated["contact"]["auto_send_is_default"] is False
    # And its own "on" wins over the default "off".
    await client.call("set_default_auto_send", {"auto_send": False})
    await client.call("update_contact", {"contact": "alice", "auto_send": True})
    assert await alice_auto_send() == (True, False)

    # null clears the contact's own setting.
    await client.call("update_contact", {"contact": "alice", "auto_send": None})
    assert await alice_auto_send() == (False, True)
    contact = env.daemon.store.get_contact(alice.id)
    assert contact is not None and contact.auto_send is False

    for bad in ({}, {"auto_send": "yes"}, {"auto_send": None}):
        with pytest.raises(RpcError) as error:
            await client.call("set_default_auto_send", bad)
        assert error.value.code == RpcErrorCode.INVALID_PARAMS


async def test_a_contact_turned_on_by_the_node_version_keeps_auto_send_on(env: Env) -> None:
    # The Node version sets only the contacts table's column.
    env.daemon.store.update_contact(alice.id, auto_send=True)
    assert env.daemon.store.auto_send_for(alice.id) == (True, False)
