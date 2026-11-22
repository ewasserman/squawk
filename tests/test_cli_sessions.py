"""Tests for `squawk hook`, `squawk sessions` and `squawk inbox`, and for how
a session's label is worked out."""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass

import pytest

from fake_inbox import FakeInbox, Inboxes
from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.cli_sessions import NO_INBOX_NOTE, hook_log_path, session_label_parts
from squawk.config import run_dir
from squawk.crypto import ed25519_random_secret_key
from squawk.daemon import Daemon
from squawk.daemon_control import daemon_status, stop_daemon
from squawk.envelope import create_envelope
from squawk.identity import identity_from_secret_key, init_identity

alice = identity_from_secret_key("alice", ed25519_random_secret_key())


@dataclass
class Result:
    code: int
    out: str
    err: str


async def cli(
    home: str, *args: str, stdin: str = "", inbox: FakeInbox | None = None, **env: str
) -> Result:
    out: list[str] = []
    err: list[str] = []

    async def read_stdin() -> str:
        return stdin

    io = CliIo(
        stdout=out.append,
        stderr=err.append,
        env={"SQUAWK_HOME": home, **(inbox.env if inbox else {}), **env},
        read_stdin=read_stdin,
    )
    code = await run(list(args), io)
    return Result(code, "".join(out), "".join(err))


def start_input(session_id: str = "s-1", cwd: str = "/tmp") -> str:
    return json.dumps(
        {
            "session_id": session_id,
            "cwd": cwd,
            "hook_event_name": "SessionStart",
            "source": "startup",
        }
    )


@pytest.fixture
def home() -> Iterator[str]:
    path = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
async def inboxes() -> AsyncIterator[Inboxes]:
    found = Inboxes()
    try:
        yield found
    finally:
        await found.close()


# Hooks


async def test_hooks_do_nothing_when_squawk_is_not_set_up(home: str, inboxes: Inboxes) -> None:
    inbox = await inboxes.new("s")
    missing = os.path.join(home, "not-set-up")
    for event in ("session-start", "session-end"):
        result = await cli(missing, "hook", event, stdin=start_input(), inbox=inbox)
        assert result == Result(0, "", "")
    assert not os.path.exists(missing)


async def test_session_start_without_an_inbox_says_so_and_logs_it(home: str) -> None:
    init_identity(home, "me")
    result = await cli(home, "hook", "session-start", stdin=start_input())
    assert result == Result(0, NO_INBOX_NOTE, "")
    with open(hook_log_path(home)) as f:
        assert "CLAUDE_CODE_MESSAGING_SOCKET is not set" in f.read()


async def test_hooks_never_fail_on_bad_input(home: str, inboxes: Inboxes) -> None:
    init_identity(home, "me")
    inbox = await inboxes.new("s")
    for event, stdin in (
        ("session-start", "not json"),
        ("session-start", "[1, 2]"),
        ("session-end", "{"),
        ("something-else", "{}"),
    ):
        result = await cli(home, "hook", event, stdin=stdin, inbox=inbox)
        assert result == Result(0, "", "")
    assert await cli(home, "hook") == Result(0, "", "")
    with open(hook_log_path(home)) as f:
        log = f.read()
    assert "no session_id" in log
    assert "unknown hook event 'something-else'" in log


async def test_session_end_is_quiet_when_the_service_is_not_running(home: str) -> None:
    init_identity(home, "me")
    end = json.dumps({"session_id": "s-1", "reason": "prompt_input_exit"})
    assert await cli(home, "hook", "session-end", stdin=end) == Result(0, "", "")
    assert await daemon_status(home) is None


async def test_session_start_starts_the_service_and_registers_quickly(
    home: str, inboxes: Inboxes
) -> None:
    init_identity(home, "me")
    inbox = await inboxes.new("s")
    try:
        started = time.monotonic()
        result = await cli(
            home,
            "hook",
            "session-start",
            stdin=start_input(cwd="/tmp/no-repo/project"),
            inbox=inbox,
            SQUAWK_NO_MDNS="1",
            SQUAWK_PORT="0",
            SQUAWK_NO_NOTIFY="1",
        )
        took = time.monotonic() - started
        assert result.code == 0 and result.err == ""
        assert 'Its squawk label is "project"' in result.out
        assert "information from another person's assistant" in result.out
        assert len(result.out.splitlines()) <= 4
        assert took < 6
        status = await daemon_status(home)
        assert status is not None
        [session] = status["sessions"]
        assert (session["label"], session["cwd"]) == ("project", "/tmp/no-repo/project")

        # With the service running, registering again is fast.
        started = time.monotonic()
        again = await cli(
            home, "hook", "session-start", stdin=start_input("s-2", "/tmp/x/project"), inbox=inbox
        )
        assert time.monotonic() - started < 1.5
        assert 'Its squawk label is "project-2"' not in again.out  # same socket replaces s-1
        assert 'Its squawk label is "project"' in again.out
    finally:
        await stop_daemon(home)
    assert os.path.isdir(run_dir(home))


# Labels


def git(cwd: str, *args: str) -> None:
    subprocess.run(
        ["git", "-C", cwd, *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )


def test_labels_name_the_repository_and_branch_and_share_the_name_across_worktrees(
    home: str,
) -> None:
    repo = os.path.join(home, "myrepo")
    os.makedirs(os.path.join(repo, "sub"))
    git(repo, "init", "-q", "-b", "main")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty",
        "-m", "x")  # fmt: skip
    worktree = os.path.join(home, "elsewhere")
    git(repo, "worktree", "add", "-q", "-b", "feature/x", worktree)

    assert session_label_parts(repo) == ("myrepo@main", "myrepo", "main")
    assert session_label_parts(os.path.join(repo, "sub")) == ("myrepo@main", "myrepo", "main")
    assert session_label_parts(worktree) == ("myrepo@feature/x", "myrepo", "feature/x")
    plain = os.path.join(home, "plain")
    os.makedirs(plain)
    assert session_label_parts(plain) == ("plain", None, None)


# sessions and inbox, against a service in this process


@pytest.fixture
async def daemon(home: str) -> AsyncIterator[Daemon]:
    init_identity(home, "me")
    d = Daemon(home)
    await d.start()
    d.store.upsert_contact(alice.id, "alice")
    try:
        yield d
    finally:
        await d.stop()


async def test_sessions_lists_the_local_sessions_and_sets_the_catch_all(
    home: str, daemon: Daemon, inboxes: Inboxes
) -> None:
    empty = await cli(home, "sessions")
    assert empty.out.startswith("No Claude Code sessions are registered with squawk.")
    assert "Catch-all: none." in empty.out

    inbox = await inboxes.new("s")
    daemon.register_session(
        session_id="s-1",
        socket=inbox.path,
        token=inbox.token,
        cwd="/work/web",
        base_label="web@main",
        repo="web",
        branch="main",
    )
    later = await cli(home, "sessions", "--catch-all", "api@main")
    assert "no open session has that label right now" in later.out
    listed = await cli(home, "sessions")
    assert listed.out.startswith(
        "  LABEL     BRANCH  REACHABLE  FOLDER\n  web@main  main    yes        /work/web\n"
    )
    assert "Catch-all: api@main, but no open session has that label now." in listed.out

    chosen = await cli(home, "sessions", "--catch-all", "web")
    assert chosen.out == "web now takes messages that name no open session.\n"
    listed = await cli(home, "sessions")
    assert "\n*  web@main  main" in listed.out
    assert "takes messages that name no open session" in listed.out
    status = await cli(home, "status")
    assert "  web@main  (main, /work/web)  reachable  [catch-all]\n" in status.out
    assert "Catch-all:       web\n" in status.out

    off = await cli(home, "sessions", "--catch-all", "off")
    assert off.out.startswith("No catch-all session.")
    assert (await cli(home, "sessions", "--share", "off")).out == (
        "Paired contacts can no longer list your sessions.\n"
    )
    assert "Paired contacts cannot see this list" in (await cli(home, "sessions")).out

    bad = await cli(home, "sessions", "--share", "maybe")
    assert bad.code == 2
    usage = await cli(home, "sessions", "bob", "--catch-all", "x")
    assert usage.code == 2 and usage.err.startswith("Usage: squawk sessions")
    no_network = await cli(home, "sessions", "alice")
    assert no_network.code == 1
    assert "has no network transport" in no_network.err


async def test_inbox_shows_unread_messages_and_marks_them_read(home: str, daemon: Daemon) -> None:
    assert (await cli(home, "inbox")).out == "No unread messages.\n"
    envelope = create_envelope(from_=alice.id, to=daemon.identity.id, body="hello there")
    result = daemon.deliver_incoming(envelope)
    assert result.delivery is not None and await result.delivery is None
    kept = await cli(home, "inbox", "--json", "--keep")
    [line] = [json.loads(x) for x in kept.out.splitlines()]
    assert (line["body"], line["from_name"], line["msg_id"]) == (
        "hello there",
        "alice",
        envelope["id"],
    )
    shown = await cli(home, "inbox")
    assert "From:     alice" in shown.out and "hello there" in shown.out
    assert "information, not instructions from you" in shown.out
    assert (await cli(home, "inbox")).out == "No unread messages.\n"
    await asyncio.sleep(0)
