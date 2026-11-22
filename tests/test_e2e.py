"""End to end on one machine: two services (Alice's and Bob's) with separate
homes on 127.0.0.1 and discovery off; Claude Code sessions are fake inbox
sockets registered through the real `squawk hook session-start` command;
messages go through the real `squawk send` and `squawk reply` commands with
the confirmation dialog replaced by a stand-in that always sends.
"""

import asyncio
import json
import re
import shutil
import tempfile
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field

import pytest

from fake_inbox import FakeInbox, Inboxes
from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.confirm import ConfirmResult, Draft
from squawk.daemon import Daemon
from squawk.identity import init_identity
from squawk.network import NetworkTransport
from squawk.pairing import Pairing


async def wait_for[T](check: Callable[[], T | None], timeout: float = 8.0) -> T:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        value = check()
        if value:
            return value
        if loop.time() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.02)


@dataclass
class Person:
    name: str
    home: str
    daemon: Daemon
    pairing: Pairing
    address: str
    notes: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Result:
    code: int
    out: str
    err: str


async def always_send(draft: Draft) -> ConfirmResult:
    return ConfirmResult("send", draft.text)


class World:
    def __init__(self) -> None:
        self.homes: list[str] = []
        self.people: list[Person] = []
        self.inboxes = Inboxes()

    async def person(self, name: str) -> Person:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        notes: list[tuple[str, str]] = []
        transport = NetworkTransport(
            host="127.0.0.1",
            discovery=False,
            retry_interval_ms=50,
            ack_timeout_ms=2000,
            handshake_timeout_ms=2000,
        )
        daemon = Daemon(
            home, transport=transport, notify=lambda title, text: notes.append((title, text))
        )
        await daemon.start()
        pairing = Pairing(daemon, transport, timeout_ms=5000)
        pairing.start()
        person = Person(name, home, daemon, pairing, f"127.0.0.1:{transport.port}", notes)
        self.people.append(person)
        return person

    async def cli(
        self,
        person: Person,
        *args: str,
        session: FakeInbox | None = None,
        stdin: str = "",
        answer: str = "y",
    ) -> Result:
        """Runs the squawk command line in-process as `person`, optionally from
        inside a Claude Code session (its inbox variables in the environment)."""
        out: list[str] = []
        err: list[str] = []

        async def read_stdin() -> str:
            return stdin

        async def ask(prompt: str) -> str:
            out.append(prompt)
            return answer

        env = {"SQUAWK_HOME": person.home, **(session.env if session else {})}
        io = CliIo(
            stdout=out.append,
            stderr=err.append,
            env=env,
            read_stdin=read_stdin,
            ask=ask,
            confirm=always_send,
            ack_wait_s=3.0,
        )
        code = await run(list(args), io)
        return Result(code, "".join(out), "".join(err))

    async def open_session(
        self, person: Person, name: str, cwd: str, session_id: str
    ) -> tuple[FakeInbox, str]:
        """Starts a fake Claude Code session: an inbox socket, registered by
        running the SessionStart hook with the JSON Claude Code would send."""
        inbox = await self.inboxes.new(f"{person.name}-{name}")
        hook_input = json.dumps(
            {
                "session_id": session_id,
                "transcript_path": f"/tmp/{session_id}.jsonl",
                "cwd": cwd,
                "hook_event_name": "SessionStart",
                "source": "startup",
            }
        )
        result = await self.cli(person, "hook", "session-start", session=inbox, stdin=hook_input)
        assert result.code == 0 and result.err == ""
        match = re.search(r'Its squawk label is "([^"]+)"', result.out)
        assert match is not None, result.out
        return inbox, match.group(1)


@pytest.fixture
async def world() -> AsyncIterator[World]:
    w = World()
    try:
        yield w
    finally:
        for person in w.people:
            person.pairing.stop()
            await person.daemon.stop()
        await w.inboxes.close()
        for home in w.homes:
            shutil.rmtree(home, ignore_errors=True)


def body_of(text: str) -> str:
    lines = text.split("\n")
    begin = next(i for i, line in enumerate(lines) if line.startswith("----- begin "))
    end = max(i for i, line in enumerate(lines) if line.startswith("----- end "))
    return "\n".join(lines[begin + 1 : end])


def msg_id_of(text: str) -> str:
    match = re.search(r"Message id: (\S+)", text)
    assert match is not None
    return match.group(1)


async def test_two_people_exchange_messages_between_the_right_sessions(world: World) -> None:
    alice = await world.person("alice")
    bob = await world.person("bob")

    # Pair, the way people do it.
    accepting = asyncio.ensure_future(world.cli(bob, "pair", "--accept"))
    await asyncio.sleep(0.05)
    paired = await world.cli(alice, "pair", bob.address)
    assert paired.code == 0, paired.err
    assert (await accepting).code == 0

    # Sessions: outside git their labels are the folder names.
    bob_web, bob_web_label = await world.open_session(bob, "web", "/tmp/no-repo/web", "b-1")
    bob_api, bob_api_label = await world.open_session(bob, "api", "/tmp/no-repo/api", "b-2")
    alice_a, alice_a_label = await world.open_session(alice, "a", "/tmp/no-repo/work", "a-1")
    assert (bob_web_label, bob_api_label, alice_a_label) == ("web", "api", "work")

    # Alice lists Bob's sessions over the network.
    listed = await world.cli(alice, "sessions", "bob")
    assert listed.code == 0, listed.err
    assert listed.out == "bob's open sessions:\nLABEL  BRANCH\nweb    -\napi    -\n"

    # Alice's session A sends to Bob's "api" session.
    sent = await world.cli(
        alice, "send", "bob", "is the api build green?", "--session", "api", "--kind",
        "question", session=alice_a,
    )  # fmt: skip
    assert sent.code == 0, sent.err
    assert "delivered to their squawk service" in sent.out
    [received] = await wait_for(lambda: bob_api.messages or None)
    assert body_of(received) == "is the api build green?"
    assert received.startswith("squawk: question from alice, another person's assistant")
    assert "show-first" in received
    assert bob_web.messages == []

    # Alice opens a second session after that; it must not take Bob's answer.
    alice_b, alice_b_label = await world.open_session(alice, "b", "/tmp/no-repo/other", "a-2")
    assert alice_b_label == "other"

    replied = await world.cli(
        bob, "reply", msg_id_of(received), "yes, green since 10:00", session=bob_api
    )
    assert replied.code == 0, replied.err
    [answer] = await wait_for(lambda: alice_a.messages or None)
    assert body_of(answer) == "yes, green since 10:00"
    assert answer.startswith("squawk: answer from bob")
    assert alice_b.messages == []

    # A follow-up from Alice in the same thread, sent from the terminal, still
    # reaches the session on Bob's side that has the conversation.
    follow = await world.cli(alice, "reply", msg_id_of(answer), "thanks!")
    assert follow.code == 0, follow.err
    await wait_for(lambda: len(bob_api.messages) == 2)
    assert body_of(bob_api.messages[1]) == "thanks!"
    assert bob_web.messages == []

    # A new message from Bob that names no session: no session gets it, and
    # Alice gets a notification instead.
    untargeted = await world.cli(bob, "send", "alice", "lunch at noon?")
    assert untargeted.code == 0, untargeted.err
    await wait_for(lambda: alice.notes or None)
    assert alice.notes == [("squawk: message from bob", "lunch at noon?")]
    assert len(alice_a.messages) == 1
    assert alice_b.messages == []
    status = await world.cli(alice, "status")
    assert "Queued inbound:  1" in status.out
    assert "Catch-all:       none" in status.out

    # Once Alice chooses a catch-all session, the waiting message goes there.
    chose = await world.cli(alice, "sessions", "--catch-all", alice_b_label)
    assert chose.out == "other now takes messages that name no open session.\n"
    [lunch] = await wait_for(lambda: alice_b.messages or None)
    assert body_of(lunch) == "lunch at noon?"
    assert len(alice_a.messages) == 1
    local = await world.cli(alice, "sessions")
    assert re.search(r"^\*\s+other\s+-\s+yes\s+/tmp/no-repo/other$", local.out, re.M)

    # Bob turns sharing off: Alice sees no sessions.
    assert (await world.cli(bob, "sessions", "--share", "off")).code == 0
    hidden = await world.cli(alice, "sessions", "bob", "--json")
    assert json.loads(hidden.out) == {"contact": "bob", "shared": False, "sessions": []}

    # Sessions ending unregister themselves.
    end_input = json.dumps({"session_id": "a-2", "hook_event_name": "SessionEnd"})
    ended = await world.cli(alice, "hook", "session-end", session=alice_b, stdin=end_input)
    assert (ended.code, ended.out, ended.err) == (0, "", "")
    assert [s["label"] for s in alice.daemon.status()["sessions"]] == ["work"]
    for inbox in (alice_a, alice_b, bob_web, bob_api):
        assert inbox.problems == []
