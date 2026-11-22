"""Tests for `squawk send`, `reply`, `tail`, `peers` and `status`,
including the confirmation step and the delivery report."""

import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest

from squawk.cli import run
from squawk.cli_io import NOT_RUNNING_MESSAGE, CliIo
from squawk.cli_messages import MESSAGE_NOTE, tail
from squawk.confirm import ConfirmResult, Draft
from squawk.daemon import Daemon
from squawk.identity import init_identity
from squawk.network import Address, NetworkTransport

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


async def wait_for[T](check: Callable[[], T | None], timeout: float = 8.0) -> T:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        value = check()
        if value:
            return value
        if loop.time() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.025)


@dataclass
class Node:
    home: str
    daemon: Daemon

    @property
    def id(self) -> str:
        return self.daemon.identity.id


class Nodes:
    def __init__(self) -> None:
        self.homes: list[str] = []
        self.daemons: list[Daemon] = []
        self.book: dict[str, Address] = {}
        """key id -> address, shared by the nodes in a test (stands in for mDNS)."""

    def make_home(self, name: str) -> str:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        return home

    async def start(self, name: str) -> Node:
        home = self.make_home(name)
        transport = NetworkTransport(
            host="127.0.0.1",
            discovery=False,
            resolve=self.book.get,
            retry_interval_ms=50,
            ack_timeout_ms=2000,
            handshake_timeout_ms=2000,
        )
        daemon = Daemon(home, transport=transport)
        await daemon.start()
        self.daemons.append(daemon)
        assert transport.port is not None
        self.book[daemon.identity.id] = Address("127.0.0.1", transport.port)
        return Node(home, daemon)

    async def paired(self) -> tuple[Node, Node]:
        alice = await self.start("alice")
        bob = await self.start("bob")
        alice.daemon.store.upsert_contact(bob.id, "bob", trust="paired")
        bob.daemon.store.upsert_contact(alice.id, "alice", trust="paired")
        return alice, bob


@pytest.fixture
async def nodes() -> AsyncIterator[Nodes]:
    n = Nodes()
    try:
        yield n
    finally:
        for daemon in n.daemons:
            await daemon.stop()
        for home in n.homes:
            shutil.rmtree(home, ignore_errors=True)


class Confirmer:
    """Stands in for the confirmation dialog: records each draft and gives a set answer."""

    def __init__(self, action: str = "send", text: str | None = None) -> None:
        self.action = action
        self.text = text
        self.drafts: list[Draft] = []

    async def __call__(self, draft: Draft) -> ConfirmResult:
        self.drafts.append(draft)
        return ConfirmResult(self.action, draft.text if self.text is None else self.text)  # type: ignore[arg-type]


class Captured:
    """A `CliIo` that collects output."""

    def __init__(self, home: str, **extra: Any) -> None:
        self.out: list[str] = []
        self.err: list[str] = []
        extra.setdefault("confirm", Confirmer())
        self.io = CliIo(
            stdout=self.out.append, stderr=self.err.append, env={"SQUAWK_HOME": home}, **extra
        )

    @property
    def stdout(self) -> str:
        return "".join(self.out)

    @property
    def stderr(self) -> str:
        return "".join(self.err)


def stdin_of(text: str) -> Callable[[], Any]:
    async def read() -> str:
        return text

    return read


SENT = re.compile(r"^Sent to (\S+) (.*) msg_id=(\S+) thread=(\S+)\.")


async def cli_send(sender: Node, *args: str) -> str:
    """Sends with the CLI from `sender`'s home (confirming) and returns the new message id."""
    c = Captured(sender.home)
    code = await run(["send", *args], c.io)
    assert c.stderr == ""
    assert code == 0
    match = SENT.match(c.stdout)
    assert match is not None, c.stdout
    return match.group(3)


def parse_lines(chunks: list[str]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in "".join(chunks).split("\n") if line != ""]


def lines_when(chunks: list[str], count: int) -> list[dict[str, Any]] | None:
    """The printed lines once there are `count` of them, otherwise None."""
    lines = parse_lines(chunks)
    return lines if len(lines) == count else None


class Tailing:
    """`tail` running in the background against a home, collecting output."""

    def __init__(self, home: str, **options: Any) -> None:
        self.out: list[str] = []
        self.stop = asyncio.Event()
        self.ready = asyncio.Event()
        self.task = asyncio.ensure_future(
            tail(
                home,
                write=self.out.append,
                stderr=lambda t: self.out.append(f"ERR {t}"),
                stop=self.stop,
                on_ready=self.ready.set,
                **options,
            )
        )

    async def finish(self) -> int:
        self.stop.set()
        return await self.task


async def test_prints_a_sent_message_as_one_json_line_in_the_other_services_tail(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    tailing = Tailing(bob.home)
    await tailing.ready.wait()

    id = await cli_send(
        alice, "bob", "hi bob", "--kind", "question", "--session", "review", "--thread", "t-1"
    )
    [line] = await wait_for(lambda: lines_when(tailing.out, 1))
    assert await tailing.finish() == 0

    assert len(tailing.out) == 1
    assert tailing.out[0].endswith("\n")
    assert isinstance(line.pop("created_at"), str)
    assert line == {
        "type": "squawk_message",
        "note": MESSAGE_NOTE,
        "msg_id": id,
        "from": alice.id,
        "from_name": "alice",
        "thread_id": "t-1",
        "in_reply_to": None,
        "kind": "question",
        "policy": "show_first",
        "session": "review",
        "body": "hi bob",
    }
    # The keys come in a fixed order.
    assert list(json.loads(tailing.out[0])) == [
        "type",
        "note",
        "msg_id",
        "from",
        "from_name",
        "thread_id",
        "in_reply_to",
        "kind",
        "policy",
        "session",
        "created_at",
        "body",
    ]


async def test_prints_only_new_messages_by_default_and_leaves_messages_unread(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    old = await cli_send(alice, "bob", "old news")
    await wait_for(lambda: bob.daemon.store.get_message(old))

    tailing = Tailing(bob.home)
    await tailing.ready.wait()
    fresh = await cli_send(alice, "bob", "new news", "--reply-to", old)
    lines = await wait_for(lambda: lines_when(tailing.out, 1))
    assert await tailing.finish() == 0
    assert [line["msg_id"] for line in lines] == [fresh]
    assert lines[0]["in_reply_to"] == old
    assert [m.id for m in bob.daemon.store.inbox()] == [old, fresh]


async def test_unread_prints_unread_messages_first_without_marking_them_read(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    first = await cli_send(alice, "bob", "one")
    second = await cli_send(alice, "bob", "two")
    await wait_for(lambda: len(bob.daemon.store.inbox()) == 2)

    stop = asyncio.Event()
    c = Captured(bob.home, stop=stop)
    tailing = asyncio.ensure_future(run(["tail", "--unread"], c.io))
    lines = await wait_for(lambda: lines_when(c.out, 2))
    stop.set()
    assert await tailing == 0
    assert [(line["msg_id"], line["body"]) for line in lines] == [
        (first, "one"),
        (second, "two"),
    ]
    assert len(bob.daemon.store.inbox()) == 2


async def test_reply_to_joins_the_thread_of_the_message_being_answered(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    question = await cli_send(alice, "bob", "staging green?")
    await wait_for(lambda: bob.daemon.store.get_message(question))
    reply = await cli_send(bob, "alice", "yes", "--reply-to", question)
    stored = bob.daemon.store.get_message(reply)
    asked = bob.daemon.store.get_message(question)
    assert stored is not None and asked is not None
    assert stored.thread_id == asked.thread_id
    assert stored.in_reply_to == question


async def test_pretty_on_its_own_also_shows_messages_that_were_already_waiting(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    id = await cli_send(alice, "bob", "sent before tail started")
    await wait_for(lambda: bob.daemon.store.get_message(id))
    stop = asyncio.Event()
    c = Captured(bob.home, stop=stop)
    tailing = asyncio.ensure_future(run(["tail", "--pretty"], c.io))
    await wait_for(lambda: c.out)
    stop.set()
    assert await tailing == 0
    assert "\nsent before tail started\n" in c.stdout


async def test_pretty_prints_a_block_for_people(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    id = await cli_send(alice, "bob", "pretty please")
    await wait_for(lambda: bob.daemon.store.get_message(id))
    stop = asyncio.Event()
    c = Captured(bob.home, stop=stop)
    tailing = asyncio.ensure_future(run(["tail", "--unread", "--pretty"], c.io))
    await wait_for(lambda: c.out)
    stop.set()
    assert await tailing == 0
    text = c.stdout
    assert text.startswith("-" * 60 + "\n")
    assert f"From:     alice ({alice.id})" in text
    assert f"Message:  {id}" in text
    assert "\npretty please\n" in text


async def test_tail_exits_with_code_1_when_the_service_connection_closes(nodes: Nodes) -> None:
    _, bob = await nodes.paired()
    err: list[str] = []
    ready = asyncio.Event()
    tailing = asyncio.ensure_future(
        tail(bob.home, write=lambda _t: None, stderr=err.append, on_ready=ready.set)
    )
    await ready.wait()
    await bob.daemon.stop()
    assert await tailing == 1
    assert "connection to the squawk service closed" in "".join(err)


def squawk_process(home: str, *args: str, **kwargs: Any) -> "subprocess.Popen[str]":
    return subprocess.Popen(
        [sys.executable, "-m", "squawk.cli", *args],
        env={**os.environ, "SQUAWK_HOME": home, "PYTHONPATH": SRC},
        text=True,
        **kwargs,
    )


async def test_tail_runs_as_a_real_process_and_stops_cleanly_on_sigterm(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    before = await cli_send(alice, "bob", "waiting for you")
    await wait_for(lambda: bob.daemon.store.get_message(before))

    child = squawk_process(
        bob.home, "tail", "--unread", stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        assert child.stdout is not None and child.stderr is not None
        first = await asyncio.to_thread(child.stdout.readline)
        # The unread message is printed only after the subscription is active,
        # so a message sent now arrives as a live notification.
        live = await cli_send(alice, "bob", "are you there?")
        second = await asyncio.to_thread(child.stdout.readline)
        lines = [json.loads(first), json.loads(second)]
        assert [(line["msg_id"], line["body"]) for line in lines] == [
            (before, "waiting for you"),
            (live, "are you there?"),
        ]
        child.send_signal(signal.SIGTERM)
        assert await asyncio.to_thread(child.wait, 10) == 0
        assert child.stderr.read() == ""
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                stream.close()


async def test_tail_exits_quietly_with_code_0_when_its_reader_goes_away(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    before = await cli_send(alice, "bob", "first")
    await wait_for(lambda: bob.daemon.store.get_message(before))
    read_end, write_end = os.pipe()
    child = squawk_process(bob.home, "tail", "--unread", stdout=write_end, stderr=subprocess.PIPE)
    os.close(write_end)
    try:
        with os.fdopen(read_end) as reader:
            assert json.loads(await asyncio.to_thread(reader.readline))["msg_id"] == before
        # Like `squawk tail | head -1`: the reader has gone; the next message
        # cannot be written.
        await cli_send(alice, "bob", "second")
        assert await asyncio.to_thread(child.wait, 10) == 0
        assert child.stderr is not None
        assert child.stderr.read() == ""
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        if child.stderr is not None:
            child.stderr.close()


def test_a_command_writing_to_a_closed_pipe_exits_quietly_with_code_0() -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "squawk.cli", "help"],
            stdout=write_end,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONPATH": SRC},
            text=True,
            timeout=30,
        )
    finally:
        os.close(write_end)
    assert result.returncode == 0
    assert result.stderr == ""


async def test_send_reads_the_message_from_stdin_when_no_text_is_given_or_it_is_a_dash(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    c = Captured(alice.home, read_stdin=stdin_of("line one\nline two\n"))
    assert await run(["send", "bob"], c.io) == 0
    match = SENT.match(c.stdout)
    assert match is not None
    id = match.group(3)

    dash = Captured(alice.home, read_stdin=stdin_of("from a dash\r\n"))
    assert await run(["send", "bob", "-"], dash.io) == 0
    match = SENT.match(dash.stdout)
    assert match is not None
    dash_id = match.group(3)

    received = await wait_for(lambda: bob.daemon.store.get_message(id))
    assert received.body == "line one\nline two"
    received = await wait_for(lambda: bob.daemon.store.get_message(dash_id))
    assert received.body == "from a dash"


async def test_send_rejects_an_empty_message_a_bad_kind_and_an_unknown_contact(
    nodes: Nodes,
) -> None:
    alice, _ = await nodes.paired()
    empty = Captured(alice.home, read_stdin=stdin_of("\n"))
    assert await run(["send", "bob"], empty.io) == 2
    assert "empty" in empty.stderr

    kind = Captured(alice.home)
    assert await run(["send", "bob", "x", "--kind", "shout"], kind.io) == 2
    assert kind.stderr == 'squawk send: --kind must be text, question or answer (got "shout")\n'

    unknown = Captured(alice.home)
    assert await run(["send", "carol", "hello"], unknown.io) == 1
    assert 'unknown contact "carol"' in unknown.stderr
    assert isinstance(unknown.io.confirm, Confirmer) and unknown.io.confirm.drafts == []

    usage = Captured(alice.home)
    assert await run(["send"], usage.io) == 2
    assert usage.stderr.startswith('Usage: squawk send <peer> "<text>"')


async def test_send_refuses_a_blocked_contact_before_asking(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    alice.daemon.store.update_contact(bob.id, trust="blocked")
    c = Captured(alice.home)
    assert await run(["send", "bob", "hi"], c.io) == 1
    assert c.stderr == (
        'squawk send: "bob" is blocked; run `squawk unblock bob` before sending to them\n'
    )
    assert isinstance(c.io.confirm, Confirmer) and c.io.confirm.drafts == []


async def test_peers_and_status_print_as_text_and_json(nodes: Nodes) -> None:
    _, bob = await nodes.paired()
    as_json = Captured(bob.home)
    assert await run(["status", "--json"], as_json.io) == 0
    status = json.loads(as_json.stdout)
    assert status["name"] == "bob"
    assert status["port"] == nodes.book[bob.id].port
    assert as_json.stdout.startswith('{\n  "name": "bob",')

    text = Captured(bob.home)
    assert await run(["status"], text.io) == 0
    assert f"Port:            {status['port']}" in text.stdout
    assert text.stdout.startswith(f"squawkd is running (pid {os.getpid()})\n")

    peers = Captured(bob.home)
    assert await run(["peers", "--json"], peers.io) == 0
    assert json.loads(peers.stdout) == []
    peers_text = Captured(bob.home)
    assert await run(["peers"], peers_text.io) == 0
    assert "No squawk services found" in peers_text.stdout


async def test_says_the_service_is_not_running_with_exit_code_1(nodes: Nodes) -> None:
    home = nodes.make_home("idle")
    for args in (
        ["send", "bob", "hi"],
        ["reply", "some-id", "hi"],
        ["tail"],
        ["peers"],
        ["status", "--json"],
    ):
        c = Captured(home)
        assert await run(args, c.io) == 1
        assert c.stderr == f"squawk: {NOT_RUNNING_MESSAGE}\n"


# reply


async def test_reply_answers_a_question_in_its_thread_and_goes_to_the_sender(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    question = await cli_send(alice, "bob", "staging green?", "--kind", "question")
    await wait_for(lambda: bob.daemon.store.get_message(question))

    c = Captured(bob.home)
    assert await run(["reply", question, "yes, all green"], c.io) == 0
    match = SENT.match(c.stdout)
    assert match is not None, c.stdout
    assert match.group(1) == "alice"
    reply_id = match.group(3)
    confirmer = c.io.confirm
    assert isinstance(confirmer, Confirmer)
    [draft] = confirmer.drafts
    assert (draft.to, draft.to_name, draft.kind, draft.in_reply_to) == (
        alice.id,
        "alice",
        "answer",
        question,
    )

    received = await wait_for(lambda: alice.daemon.store.get_message(reply_id))
    asked = alice.daemon.store.get_message(question)
    assert asked is not None
    assert received.direction == "in"
    assert received.kind == "answer"
    assert received.body == "yes, all green"
    assert received.in_reply_to == question
    assert received.thread_id == asked.thread_id


async def test_reply_to_a_plain_message_is_text_and_can_come_from_stdin(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    note = await cli_send(alice, "bob", "fyi: deploy at 5")
    await wait_for(lambda: bob.daemon.store.get_message(note))
    c = Captured(bob.home, read_stdin=stdin_of("thanks\n"))
    assert await run(["reply", note], c.io) == 0
    match = SENT.match(c.stdout)
    assert match is not None
    stored = bob.daemon.store.get_message(match.group(3))
    assert stored is not None
    assert (stored.kind, stored.body, stored.in_reply_to) == ("text", "thanks", note)


async def test_reply_explains_an_unknown_message_and_usage(nodes: Nodes) -> None:
    _, bob = await nodes.paired()
    c = Captured(bob.home)
    assert await run(["reply", "no-such-id", "hi"], c.io) == 1
    assert c.stderr == 'squawk reply: no message with id "no-such-id"\n'
    usage = Captured(bob.home)
    assert await run(["reply"], usage.io) == 2
    assert usage.stderr.startswith('Usage: squawk reply <msg id> "<text>"')


# The confirmation step and the delivery report


async def test_send_shows_the_draft_and_reports_delivery(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    c = Captured(alice.home)
    assert await run(["send", "bob", "hello", "--session", "review"], c.io) == 0
    confirmer = c.io.confirm
    assert isinstance(confirmer, Confirmer)
    [draft] = confirmer.drafts
    assert (draft.to, draft.to_name, draft.text, draft.kind, draft.session) == (
        bob.id,
        "bob",
        "hello",
        "text",
        "review",
    )
    match = SENT.match(c.stdout)
    assert match is not None
    assert c.stdout == (
        "Sent to bob and delivered to their squawk service (they have not necessarily read "
        f"it yet). msg_id={match.group(3)} thread={match.group(4)}.\n"
    )


async def test_cancel_sends_nothing(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    c = Captured(alice.home, confirm=Confirmer("cancel"))
    assert await run(["send", "bob", "secret stuff"], c.io) == 1
    assert c.stdout == "Not sent: cancelled.\n"
    assert alice.daemon.store.count_outbound() == 0
    assert alice.daemon.store.list_threads() == []
    await asyncio.sleep(0.1)
    assert bob.daemon.store.inbox() == []


async def test_edited_text_is_what_gets_sent(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()
    c = Captured(alice.home, confirm=Confirmer("send", "the edited\ntext"))
    assert await run(["send", "bob", "the original"], c.io) == 0
    match = SENT.match(c.stdout)
    assert match is not None
    assert c.stdout.endswith(
        ". Your user edited the text before sending; what was sent is:\nthe edited\ntext\n"
    )
    received = await wait_for(lambda: bob.daemon.store.get_message(match.group(3)))
    assert received.body == "the edited\ntext"


async def test_timeout_sends_nothing(nodes: Nodes) -> None:
    alice, _ = await nodes.paired()
    c = Captured(alice.home, confirm=Confirmer("timeout"))
    assert await run(["send", "bob", "hello"], c.io) == 1
    assert c.stdout == "Not sent: nobody answered the confirmation dialog in time.\n"
    assert alice.daemon.store.count_outbound() == 0


async def test_auto_send_skips_the_question_per_contact_and_by_default(nodes: Nodes) -> None:
    alice, bob = await nodes.paired()

    async def send_asks() -> bool:
        confirmer = Confirmer()
        c = Captured(alice.home, confirm=confirmer)
        assert await run(["send", "bob", "hi"], c.io) == 0, c.stderr
        return len(confirmer.drafts) == 1

    assert await send_asks()
    # Contact on.
    assert await run(["auto-send", "bob", "on"], Captured(alice.home).io) == 0
    assert not await send_asks()
    # Default on, contact back to following it.
    assert await run(["auto-send", "--default", "on"], Captured(alice.home).io) == 0
    assert await run(["auto-send", "bob", "default"], Captured(alice.home).io) == 0
    assert not await send_asks()
    # The contact's own "off" wins over the default "on".
    assert await run(["auto-send", "bob", "off"], Captured(alice.home).io) == 0
    assert await send_asks()
    await wait_for(lambda: len(bob.daemon.store.inbox()) == 4)


def fake_osascript(directory: str, body: str) -> str:
    """Writes a stand-in for osascript that saves its arguments as JSON in
    args.json and then runs `body` (Python, with `args` bound)."""
    path = os.path.join(directory, "osascript")
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            "args = sys.argv[1:]\n"
            f"json.dump(args, open({os.path.join(directory, 'args.json')!r}, 'w'))\n"
            f"{body}\n"
        )
    os.chmod(path, 0o755)
    return path


async def test_no_dialog_means_nothing_is_sent_and_says_how_to_turn_on_auto_send(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    # osascript fails as it does without a logged-in screen session.
    failing = fake_osascript(
        alice.home,
        "sys.stderr.write('execution error: No user interaction allowed. (-1713)\\n')\nsys.exit(1)",
    )
    for osascript in (failing, os.path.join(alice.home, "missing-osascript")):
        c = Captured(alice.home, confirm=None, osascript=osascript)
        assert await run(["send", "bob", "hello"], c.io) == 1
        assert c.stdout == ""
        assert c.stderr.startswith("squawk send: not sent: ")
        assert "`squawk auto-send bob on`" in c.stderr
        assert "`squawk auto-send --default on`" in c.stderr
        if osascript == failing:
            assert "No user interaction allowed" in c.stderr
    assert alice.daemon.store.count_outbound() == 0
    assert bob.daemon.store.inbox() == []


async def test_the_dialog_gets_the_text_as_an_argument_and_its_answer_is_sent(
    nodes: Nodes,
) -> None:
    alice, bob = await nodes.paired()
    text = '-e "quoted" & {braces}\nsecond line'
    osascript = fake_osascript(alice.home, "print('SEND\\nedited ' + args[5])")
    c = Captured(alice.home, confirm=None, osascript=osascript)
    assert await run(["send", "bob", "--", text], c.io) == 0, c.stderr
    with open(os.path.join(alice.home, "args.json"), encoding="utf-8") as f:
        args = json.load(f)
    # -e <script> -- <title> <prompt> <text> <timeout>
    assert args[0] == "-e"
    assert "on run argv" in args[1]
    assert text not in args[1]
    assert args[2:4] == ["--", "squawk"]
    assert "to bob" in args[4]
    assert args[5] == text
    match = SENT.match(c.stdout)
    assert match is not None
    received = await wait_for(lambda: bob.daemon.store.get_message(match.group(3)))
    assert received.body == "edited " + text


async def test_the_dialog_cancel_answer_sends_nothing(nodes: Nodes) -> None:
    alice, _ = await nodes.paired()
    osascript = fake_osascript(alice.home, "print('CANCEL')")
    c = Captured(alice.home, confirm=None, osascript=osascript)
    assert await run(["send", "bob", "hello"], c.io) == 1
    assert c.stdout == "Not sent: cancelled.\n"
    assert alice.daemon.store.count_outbound() == 0


async def test_reports_a_message_that_is_still_queued(nodes: Nodes) -> None:
    alice, _ = await nodes.paired()
    # Carol's address is unknown, so the message stays queued.
    carol = "C" * 42 + "A"
    alice.daemon.store.upsert_contact(carol, "carol", trust="paired")
    c = Captured(alice.home, ack_wait_s=0.2)
    assert await run(["send", "carol", "are you there?"], c.io) == 0
    assert c.stdout.startswith(
        "Sent to carol: queued, not yet delivered (their service has not answered). "
        "Squawk keeps retrying for up to 7 days; you do not need to resend it. msg_id="
    )
