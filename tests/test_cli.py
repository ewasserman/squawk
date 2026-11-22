"""Tests for the `squawk` command itself: help, `init`, `whoami`, `daemon`,
the argument reader, and the confirmation dialog's helpers."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from squawk.cli import COMMANDS, run, usage
from squawk.cli_args import Opt, ParseArgsError, parse_args
from squawk.cli_io import CliIo
from squawk.config import identity_path
from squawk.confirm import Draft, _parse_output, confirmation_prompt
from squawk.identity import fingerprint, load_identity


@pytest.fixture
def home() -> Iterator[str]:
    directory = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


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


# help and unknown commands


async def test_help_lists_every_command(home: str) -> None:
    for args in ([], ["help"], ["--help"]):
        r = await cli(home, *args)
        assert r.code == 0
        assert r.out == usage()
    text = usage()
    assert text.startswith("Usage: squawk <command> [options]\n\nCommands:\n")
    for name in COMMANDS:
        assert f"\n  {name} " in text
    assert list(COMMANDS)[:11] == [
        "setup",
        "uninstall",
        "pair",
        "contacts",
        "auto-send",
        "policy",
        "block",
        "unblock",
        "init",
        "whoami",
        "daemon",
    ]
    assert "mcp" not in COMMANDS


async def test_rejects_unknown_commands_and_options(home: str) -> None:
    unknown = await cli(home, "frobnicate")
    assert unknown.code == 2
    assert unknown.err == f'squawk: unknown command "frobnicate"\n\n{usage()}'
    bad = await cli(home, "init", "--bogus")
    assert bad.code == 2
    assert bad.err == "squawk init: Unknown option '--bogus'\n"


# init and whoami


async def test_init_then_whoami_prints_the_name_and_fingerprint(home: str) -> None:
    init = await cli(home, "init", "--name", "alice")
    assert init.code == 0
    with open(identity_path(home), encoding="utf-8") as f:
        assert json.load(f)["name"] == "alice"
    identity = load_identity(home)
    assert init.out == (
        f'Created identity "alice" in {home}\nFingerprint: {fingerprint(identity.public_key)}\n'
    )

    who = await cli(home, "whoami")
    assert who.code == 0
    assert who.out == (
        f"Name:        alice\nKey:         {identity.id}\n"
        f"Fingerprint: {fingerprint(identity.public_key)}\n"
    )


async def test_init_a_second_time_fails_with_exit_code_1(home: str) -> None:
    await cli(home, "init", "--name", "alice")
    again = await cli(home, "init", "-n", "bob")
    assert again.code == 1
    assert "refusing to overwrite" in again.err


async def test_whoami_without_an_identity_fails_with_exit_code_1(home: str) -> None:
    who = await cli(home, "whoami")
    assert who.code == 1
    assert "squawk init" in who.err


# daemon, as a real process


def squawk(home: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "squawk.cli", *args],
        env={**os.environ, "SQUAWK_HOME": home, "SQUAWK_NO_MDNS": "1", "SQUAWK_PORT": "0"},
        capture_output=True,
        text=True,
        timeout=30,
    )


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_daemon_starts_reports_status_and_stops_the_background_service(home: str) -> None:
    assert squawk(home, "init", "--name", "cli-test").returncode == 0
    try:
        before = squawk(home, "daemon", "status")
        assert before.returncode == 1
        assert before.stdout == "squawkd is not running\n"

        start = squawk(home, "daemon", "start")
        assert start.stderr == ""
        assert start.returncode == 0
        assert start.stdout.startswith("squawkd started (pid ")
        pid = int(start.stdout.split("pid ")[1].rstrip(")\n"))
        assert pid > 0

        again = squawk(home, "daemon", "start")
        assert again.stdout == f"squawkd is already running (pid {pid})\n"

        status = squawk(home, "daemon", "status")
        assert status.returncode == 0
        assert status.stdout.startswith(
            f"squawkd is running (pid {pid})\nName:            cli-test\n"
        )
        assert "Sessions:        none\n" in status.stdout

        stop = squawk(home, "daemon", "stop")
        assert stop.returncode == 0
        assert stop.stdout == "squawkd stopped\n"
        assert not alive(pid)

        after = squawk(home, "daemon", "status")
        assert after.returncode == 1
        stopped = squawk(home, "daemon", "stop")
        assert (stopped.returncode, stopped.stdout) == (1, "squawkd is not running\n")
    finally:
        squawk(home, "daemon", "stop")


def test_daemon_rejects_an_unknown_action_and_extra_arguments(home: str) -> None:
    bogus = squawk(home, "daemon", "bogus")
    assert bogus.returncode == 2
    assert bogus.stderr == "Usage: squawk daemon start | stop | status | run\n"
    extra = squawk(home, "daemon", "start", "extra")
    assert extra.returncode == 2
    assert extra.stderr == 'squawk daemon: unexpected argument "extra"\n'


def test_daemon_start_without_an_identity_fails_with_exit_code_1(home: str) -> None:
    result = squawk(home, "daemon", "start")
    assert result.returncode == 1
    assert "squawk init" in result.stderr


# The argument reader. The expected messages are the fixed wording squawk 0.1 also used.

OPTIONS = {"name": Opt("string", "n"), "json": Opt("boolean"), "unread": Opt("boolean", "u")}


def test_reads_options_in_every_spelling() -> None:
    for args in (["--name", "bob"], ["--name=bob"], ["-n", "bob"], ["-nbob"]):
        assert parse_args(args, OPTIONS) == ({"name": "bob"}, [])
    assert parse_args(["-n=bob"], OPTIONS) == ({"name": "=bob"}, [])
    assert parse_args(["--name", "-"], OPTIONS) == ({"name": "-"}, [])
    assert parse_args(["--name=-x"], OPTIONS) == ({"name": "-x"}, [])
    assert parse_args(["-n", "a", "--name", "b"], OPTIONS) == ({"name": "b"}, [])
    assert parse_args(["-un", "x"], OPTIONS) == ({"unread": True, "name": "x"}, [])
    args = ["a", "--json", "b", "--", "--name", "-"]
    assert parse_args(args, OPTIONS, allow_positionals=True) == (
        {"json": True},
        ["a", "b", "--name", "-"],
    )


@pytest.mark.parametrize(
    ("args", "allow_positionals", "message"),
    [
        (["--bogus"], False, "Unknown option '--bogus'"),
        (["-x"], False, "Unknown option '-x'"),
        (["--bogus=1"], False, "Unknown option '--bogus'"),
        (["-jx"], False, "Unknown option '-j'"),
        (
            ["a", "--bogus"],
            True,
            "Unknown option '--bogus'. To specify a positional argument starting with a '-', "
            "place it at the end of the command after '--', as in '-- \"--bogus\"",
        ),
        (["--name"], False, "Option '-n, --name <value>' argument missing"),
        (["-n"], False, "Option '-n, --name <value>' argument missing"),
        (["--json=1"], False, "Option '--json' does not take an argument"),
        (["--unread=1"], False, "Option '-u, --unread' does not take an argument"),
        (
            ["extra"],
            False,
            "Unexpected argument 'extra'. This command does not take positional arguments",
        ),
        (
            ["--name", "-x"],
            False,
            "Option '--name' argument is ambiguous.\n"
            "Did you forget to specify the option argument for '--name'?\n"
            "To specify an option argument starting with a dash use '--name=-XYZ'.",
        ),
        (
            ["-n", "-x"],
            False,
            "Option '-n' argument is ambiguous.\n"
            "Did you forget to specify the option argument for '-n'?\n"
            "To specify an option argument starting with a dash use '--name=-XYZ' or '-n-XYZ'.",
        ),
    ],
)
def test_reports_bad_arguments_as_node_does(
    args: list[str], allow_positionals: bool, message: str
) -> None:
    with pytest.raises(ParseArgsError) as error:
        parse_args(args, OPTIONS, allow_positionals=allow_positionals)
    assert str(error.value) == message


# The confirmation dialog's helpers (the dialog itself is tested through
# `squawk send` with stand-in dialog programs in test_cli_messages.py).


def draft(**changes: str) -> Draft:
    d = Draft(to="k", to_name="bob", text="hello\nthere", kind="text")
    for key, value in changes.items():
        setattr(d, key, value)
    return d


def test_the_prompt_names_the_recipient_and_says_message_or_reply() -> None:
    assert confirmation_prompt(draft()).startswith(
        "Claude wants to send this squawk message to bob.\n"
    )
    assert confirmation_prompt(draft(in_reply_to="m1")).startswith(
        "Claude wants to send this squawk reply to bob.\n"
    )


def test_reads_the_dialogs_answer() -> None:
    d = draft()
    assert _parse_output("SEND\nhello\nthere\n", d).action == "send"
    assert _parse_output("SEND\nhello\nthere\n", d).text == "hello\nthere"
    assert _parse_output("SEND\nnew text\n\n", d).text == "new text\n"
    assert _parse_output("CANCEL\n", d).action == "cancel"
    assert _parse_output("GAVEUP\n", d).action == "timeout"
    # An emptied field sends nothing.
    assert _parse_output("SEND\n  \n", d).action == "cancel"
    assert _parse_output("something else\n", d).action == "unavailable"
