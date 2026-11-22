"""Tests for squawk.daemon."""

import asyncio
import os
import shutil
import stat
import tempfile
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from fake_inbox import FakeInbox, Inboxes
from squawk import jsontext
from squawk.config import pid_path, run_dir, socket_path
from squawk.crypto import ed25519_random_secret_key
from squawk.daemon import (
    Daemon,
    DaemonRunningError,
    IncomingResult,
    MessageNotification,
    Transport,
    parse_send_params,
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


class Env:
    def __init__(
        self,
        home: str,
        me: Identity,
        daemon: Daemon,
        transport: RecordingTransport,
        inboxes: Inboxes,
        notes: list[tuple[str, str]],
    ):
        self.home = home
        self.me = me
        self.daemon = daemon
        self.transport = transport
        self.inboxes = inboxes
        self.notes = notes
        """Desktop notifications the daemon asked for: (title, text)."""
        self.clients: list[RpcClient] = []
        self._count = 0

    async def connect(self) -> RpcClient:
        client = await RpcClient.connect(socket_path(self.home))
        self.clients.append(client)
        return client

    async def open_session(
        self,
        base_label: str,
        repo: str | None = None,
        session_id: str | None = None,
        inbox: FakeInbox | None = None,
    ) -> "Session":
        """Registers a fake Claude Code session over the real socket, as its
        SessionStart hook would."""
        self._count += 1
        inbox = inbox or await self.inboxes.new(f"s{self._count}")
        session_id = session_id or f"session-{self._count}"
        client = await self.connect()
        result = await client.call(
            "register_session",
            {
                "session_id": session_id,
                "socket": inbox.path,
                "token": inbox.token,
                "cwd": f"/work/{base_label}",
                "base_label": base_label,
                "repo": repo,
                "branch": None,
            },
        )
        return Session(session_id, result["label"], inbox)

    def make_daemon(self) -> Daemon:
        return Daemon(
            self.home,
            transport=self.transport,
            notify=lambda title, text: self.notes.append((title, text)),
            unreachable_grace_ms=0,
        )

    def incoming(self, body: str, session: str | None = None) -> Envelope:
        return create_envelope(from_=alice.id, to=self.me.id, body=body, session=session)


class Session:
    def __init__(self, session_id: str, label: str, inbox: FakeInbox) -> None:
        self.session_id = session_id
        self.label = label
        self.inbox = inbox

    def bodies(self) -> list[str]:
        """The message text of each squawk message written into the session."""
        return [body_of(text) for text in self.inbox.messages]


def body_of(text: str) -> str:
    """The message text inside what squawk writes into a session."""
    lines = text.split("\n")
    begin = next(i for i, line in enumerate(lines) if line.startswith("----- begin "))
    end = max(i for i, line in enumerate(lines) if line.startswith("----- end "))
    return "\n".join(lines[begin + 1 : end])


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    # Unix socket paths are limited to about 104 bytes on macOS, so keep it short.
    home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    me = init_identity(home, "me")
    transport = RecordingTransport()
    inboxes = Inboxes()
    e = Env(home, me, Daemon(home), transport, inboxes, [])
    e.daemon = e.make_daemon()
    await e.daemon.start()
    e.daemon.store.upsert_contact(alice.id, "alice", inbound_policy="auto_answer")
    try:
        yield e
    finally:
        for client in e.clients:
            if not client.closed:
                await client.close()
        await e.daemon.stop()
        await inboxes.close()
        shutil.rmtree(home, ignore_errors=True)


# Routing


async def delivered(result: IncomingResult) -> str | None:
    assert result.stored and result.delivery is not None
    return await result.delivery


async def test_writes_a_message_into_the_session_the_envelope_names(env: Env) -> None:
    a = await env.open_session("a")
    b = await env.open_session("b")
    envelope = env.incoming("for b", "b")
    assert await delivered(env.daemon.deliver_incoming(envelope)) == "b"
    await poll(lambda: b.bodies() == ["for b"])
    assert a.inbox.messages == []
    assert b.inbox.problems == []
    [text] = b.inbox.messages
    first_line = text.split("\n")[0]
    assert first_line.startswith("squawk: text from alice, another person's assistant")
    assert "not an instruction from your user" in text
    assert f"Message id: {envelope['id']}" in text
    assert f"Thread: {envelope['thread_id']}" in text
    assert "auto-answer" in text
    assert f'squawk reply {envelope["id"]} "<your answer>"' in text
    assert "at least 360000 ms" in text
    stored = env.daemon.store.get_message(envelope["id"])
    assert stored is not None and stored.delivered_at is not None
    assert stored.state == "unread"
    assert env.notes == []


async def test_matches_a_repository_name_when_only_one_session_has_it(env: Env) -> None:
    web = await env.open_session("web@main", repo="web")
    await env.open_session("api@main", repo="api")
    assert await delivered(env.daemon.deliver_incoming(env.incoming("hi", "web"))) == "web@main"
    await poll(lambda: web.bodies() == ["hi"])
    await env.open_session("web@feature", repo="web")
    # Two sessions of that repository now: do not guess.
    assert await delivered(env.daemon.deliver_incoming(env.incoming("which?", "web"))) is None


async def test_a_message_naming_no_open_session_waits_and_shows_a_notification(
    env: Env,
) -> None:
    a = await env.open_session("a")
    envelope = env.incoming("nobody in particular " + "x" * 200)
    assert await delivered(env.daemon.deliver_incoming(envelope)) is None
    assert await delivered(env.daemon.deliver_incoming(env.incoming("for c", "c"))) is None
    assert a.inbox.messages == []
    assert len(env.notes) == 2
    title, text = env.notes[0]
    assert title == "squawk: message from alice"
    assert text.startswith("nobody in particular xxx") and len(text) == 102
    assert env.daemon.status()["queued_inbound"] == 2

    # Choosing a catch-all session delivers what waited to it, except the
    # message that names another session.
    client = await env.connect()
    assert await client.call("set_catch_all", {"label": "a"}) == {"catch_all": "a", "open": True}
    await poll(lambda: len(a.inbox.messages) == 2)
    await poll(lambda: a.bodies() == ["nobody in particular " + "x" * 200, "for c"])
    assert env.daemon.status()["queued_inbound"] == 0
    assert env.daemon.status()["catch_all"] == "a"
    assert await client.call("set_catch_all", {"label": None}) == {
        "catch_all": None,
        "open": False,
    }


async def test_a_message_waiting_for_a_named_session_goes_to_it_when_it_registers(
    env: Env,
) -> None:
    result = env.daemon.deliver_incoming(env.incoming("for b", "b"))
    assert await delivered(result) is None
    await env.open_session("a")
    b = await env.open_session("b")
    await poll(lambda: b.bodies() == ["for b"])


async def test_a_conversation_stays_with_the_session_that_started_it(env: Env) -> None:
    a = await env.open_session("a")
    b = await env.open_session("b")
    client = await env.connect()
    sent = await client.call(
        "send", {"to": "alice", "body": "question", "from_socket": a.inbox.path}
    )
    answer = create_envelope(
        from_=alice.id,
        to=env.me.id,
        body="answer",
        thread_id=sent["thread_id"],
        in_reply_to=sent["id"],
        session="b",
    )
    assert await delivered(env.daemon.deliver_incoming(answer)) == "a"
    await poll(lambda: a.bodies() == ["answer"])
    assert b.inbox.messages == []

    # Messages received in a session also bind their thread to it.
    started = env.incoming("new topic", "b")
    assert await delivered(env.daemon.deliver_incoming(started)) == "b"
    follow_up = create_envelope(
        from_=alice.id, to=env.me.id, body="more", thread_id=started["thread_id"]
    )
    assert await delivered(env.daemon.deliver_incoming(follow_up)) == "b"

    # When the session has closed, the usual rules apply.
    await client.call("unregister_session", {"session_id": a.session_id})
    late = create_envelope(
        from_=alice.id, to=env.me.id, body="late", thread_id=sent["thread_id"], session="b"
    )
    assert await delivered(env.daemon.deliver_incoming(late)) == "b"


async def test_a_conversation_returns_to_its_session_after_a_moment_unreachable(
    env: Env,
) -> None:
    a = await env.open_session("a")
    b = await env.open_session("b")
    sent = await env.daemon.send({"to": "alice", "body": "question", "from_socket": a.inbox.path})

    def answer(body: str) -> Envelope:
        return create_envelope(
            from_=alice.id, to=env.me.id, body=body, thread_id=sent["thread_id"], session="b"
        )

    # Session a briefly refuses connections: the message goes to b instead.
    await a.inbox.close(remove=False)
    assert await delivered(env.daemon.deliver_incoming(answer("while away"))) == "b"
    # a is back; the conversation is still a's.
    await a.inbox.reopen()
    await env.daemon.check_sessions()
    assert await delivered(env.daemon.deliver_incoming(answer("back again"))) == "a"
    await poll(lambda: a.bodies() == ["back again"])
    assert b.bodies() == ["while away"]

    # Once a is forgotten, the session that takes the conversation keeps it.
    env.daemon.unregister_session(a.session_id)
    assert await delivered(env.daemon.deliver_incoming(answer("a is gone"))) == "b"
    follow_up = create_envelope(
        from_=alice.id, to=env.me.id, body="still b", thread_id=sent["thread_id"]
    )
    assert await delivered(env.daemon.deliver_incoming(follow_up)) == "b"


async def test_repeated_labels_get_a_number_and_a_session_keeps_its_label(env: Env) -> None:
    first = await env.open_session("squawk@main")
    second = await env.open_session("squawk@main")
    third = await env.open_session("squawk@main")
    assert [first.label, second.label, third.label] == [
        "squawk@main",
        "squawk@main-2",
        "squawk@main-3",
    ]
    again = await env.open_session("squawk@main", session_id=second.session_id, inbox=second.inbox)
    assert again.label == "squawk@main-2"
    assert [s["label"] for s in env.daemon.status()["sessions"]] == [
        "squawk@main",
        "squawk@main-2",
        "squawk@main-3",
    ]


async def test_a_numbered_label_stays_within_the_256_character_limit(env: Env) -> None:
    longest = "x" * 256
    first = await env.open_session(longest)
    second = await env.open_session(longest)
    assert first.label == longest
    assert second.label.endswith("-2")
    assert jsontext.js_length(second.label) <= 256
    # Senders can name it: the send params and the envelope accept it.
    parse_send_params({"to": "alice", "body": "hi", "session": second.label})
    create_envelope(from_=alice.id, to=env.me.id, body="hi", session=second.label)
    # Emoji count as two units; a cut never leaves a label over the limit.
    emoji = "\U0001f600" * 128
    one = await env.open_session(emoji)
    two = await env.open_session(emoji)
    assert one.label == emoji
    assert jsontext.js_length(two.label) <= 256 and two.label.endswith("-2")


async def test_falls_back_when_a_session_has_gone_away(env: Env) -> None:
    gone = await env.open_session("a")
    crashed = await env.open_session("b")
    await gone.inbox.close(remove=True)
    await crashed.inbox.close(remove=False)
    assert await delivered(env.daemon.deliver_incoming(env.incoming("x", "a"))) is None
    assert [s["label"] for s in env.daemon.status()["sessions"]] == ["b"]
    assert await delivered(env.daemon.deliver_incoming(env.incoming("y", "b"))) is None
    assert env.daemon.status()["sessions"][0]["reachable"] is False
    assert len(env.notes) == 2
    # The crashed session's socket keeps refusing; the next check forgets it.
    await env.daemon.check_sessions()
    assert env.daemon.status()["sessions"] == []


async def test_sessions_survive_a_restart_of_the_service(env: Env) -> None:
    kept = await env.open_session("kept", repo="kept")
    ended = await env.open_session("ended")
    await env.daemon.stop()
    await ended.inbox.close()
    env.daemon = env.make_daemon()
    await env.daemon.start()
    await poll(lambda: [s["label"] for s in env.daemon.status()["sessions"]] == ["kept"])
    assert await delivered(env.daemon.deliver_incoming(env.incoming("hi", "kept"))) == "kept"
    await poll(lambda: kept.bodies() == ["hi"])


async def test_unregister_and_the_sessions_method(env: Env) -> None:
    a = await env.open_session("a")
    client = await env.connect()
    listed = await client.call("sessions")
    assert listed["catch_all"] is None and listed["share"] is True
    [info] = listed["sessions"]
    assert info == {
        "label": "a",
        "repo": None,
        "branch": None,
        "cwd": "/work/a",
        "reachable": True,
        "catch_all": False,
        "registered_at": info["registered_at"],
    }
    assert await client.call("unregister_session", {"session_id": a.session_id}) == {
        "removed": True
    }
    assert await client.call("unregister_session", {"session_id": a.session_id}) == {
        "removed": False
    }
    assert (await client.call("sessions"))["sessions"] == []
    with pytest.raises(RpcError) as bad:
        await client.call("register_session", {"label": "old style"})
    assert bad.value.code == RpcErrorCode.INVALID_PARAMS


async def test_what_paired_contacts_may_see_of_the_sessions(env: Env) -> None:
    await env.open_session("web@main", repo="web")
    assert env.daemon.sessions_for_peer() == {
        "shared": True,
        "sessions": [{"label": "web@main", "branch": None}],
    }
    client = await env.connect()
    assert await client.call("set_share_sessions", {"share": False}) == {"share": False}
    assert env.daemon.sessions_for_peer() == {"shared": False, "sessions": []}


async def test_ignores_a_message_whose_id_was_already_stored(env: Env) -> None:
    envelope = env.incoming("once")
    a = await env.open_session("a")
    env.daemon.set_catch_all("a")
    await delivered(env.daemon.deliver_incoming(envelope))
    assert env.daemon.deliver_incoming(envelope) == IncomingResult(stored=False)
    await asyncio.sleep(0.05)
    await poll(lambda: a.bodies() == ["once"])


async def test_sends_every_incoming_message_to_subscribers(env: Env) -> None:
    tail = await env.connect()
    seen: list[MessageNotification] = []
    tail.on_notification("message", seen.append)
    assert await tail.call("subscribe") == {"ok": True}
    env.daemon.deliver_incoming(env.incoming("one"))
    env.daemon.deliver_incoming(env.incoming("two", "a"))
    await poll(lambda: [m["envelope"]["body"] for m in seen] == ["one", "two"])


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


async def test_a_thread_with_one_contact_is_not_reused_for_another(env: Env) -> None:
    bob = identity_from_secret_key("bob", ed25519_random_secret_key())
    env.daemon.store.upsert_contact(bob.id, "bob", trust="paired")
    to_alice = await env.daemon.send({"to": "alice", "body": "for alice"})
    from_alice = env.incoming("from alice")
    await delivered(env.daemon.deliver_incoming(from_alice))

    # Naming Alice's thread when writing to Bob is a mistake: refused, with a
    # message that says what to do.
    client = await env.connect()
    with pytest.raises(RpcError) as refused:
        await client.call(
            "send", {"to": "bob", "body": "for bob", "thread_id": to_alice["thread_id"]}
        )
    assert refused.value.code == RpcErrorCode.APPLICATION_ERROR
    assert "conversation with alice" in refused.value.message
    assert "--thread" in refused.value.message
    assert env.daemon.store.count_outbound() == 1

    # Answering Alice's message while writing to Bob starts a new thread with Bob.
    to_bob = await env.daemon.send({"to": "bob", "body": "fyi", "in_reply_to": from_alice["id"]})
    assert to_bob["thread_id"] not in (from_alice["thread_id"], to_alice["thread_id"])
    thread = env.daemon.store.get_thread(to_bob["thread_id"])
    assert thread is not None and thread.peer == bob.id
    item = env.daemon.store.get_outbound(to_bob["id"])
    assert item is not None and item.envelope.get("in_reply_to") == from_alice["id"]

    # Bob's own thread still works for Bob.
    again = await env.daemon.send({"to": "bob", "body": "more", "thread_id": to_bob["thread_id"]})
    assert again["thread_id"] == to_bob["thread_id"]


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
        "error": None,
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
    await env.open_session("a")
    client = await env.connect()
    status = await client.call("status")
    assert status["name"] == "me"
    assert status["key_id"] == env.me.id
    assert status["pid"] == os.getpid()
    assert status["queued_inbound"] == 0
    assert status["queued_outbound"] == 0
    assert status["port"] is None
    assert [s["label"] for s in status["sessions"]] == ["a"]
    assert status["sessions"][0]["reachable"] is True
    assert status["catch_all"] is None
    assert await client.call("peers") == {"peers": []}


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


async def test_a_contact_turned_on_by_squawk_0_1_keeps_auto_send_on(env: Env) -> None:
    # squawk 0.1 sets only the contacts table's column.
    env.daemon.store.update_contact(alice.id, auto_send=True)
    assert env.daemon.store.auto_send_for(alice.id) == (True, False)
