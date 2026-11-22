"""What every `squawk` subcommand receives: where to write, which environment
to read, and inputs that tests replace (standard input, answers to prompts,
the confirmation dialog, a way to stop `tail`).

To add a subcommand, write an async function `run(args, io) -> exit code`
and add a `Command` for it to one of the command tables (`CONTACT_COMMANDS`
in cli_contacts.py, `MESSAGE_COMMANDS` in cli_messages.py, or the table in
cli.py). `squawk help` lists it with its summary.
"""

import asyncio
import os
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from squawk.confirm import ConfirmFn

NOT_RUNNING_MESSAGE = "squawk service is not running; start it with `squawk daemon start`"
"""Printed when no background service answers on the socket."""


def quiet_stdout() -> None:
    """Points standard output at /dev/null, so nothing more is written to a
    closed pipe (Python would otherwise complain while exiting)."""
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, sys.stdout.fileno())
    os.close(devnull)


def _write_stdout(text: str) -> None:
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        # Output goes to a program that stopped reading (such as
        # `squawk tail | head`): exit at once and quietly.
        # Raising would not work everywhere, because some
        # output is written from inside the socket client's callbacks.
        quiet_stdout()
        os._exit(0)


def _write_stderr(text: str) -> None:
    sys.stderr.write(text)
    sys.stderr.flush()


async def _read_stdin() -> str:
    text: str = await asyncio.to_thread(sys.stdin.read)
    return text


async def _ask_on_stdin(prompt: str) -> str:
    _write_stdout(prompt)
    line: str = await asyncio.to_thread(sys.stdin.readline)
    return line.rstrip("\r\n")


@dataclass
class CliIo:
    """Where a command writes its output and which environment it reads.

    The defaults are the real process's; tests pass their own.
    """

    stdout: Callable[[str], None] = _write_stdout
    stderr: Callable[[str], None] = _write_stderr
    env: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    read_stdin: Callable[[], Awaitable[str]] = _read_stdin
    """Reads all of standard input (`send` and `reply` with no text)."""
    ask: Callable[[str], Awaitable[str]] = _ask_on_stdin
    """Shows a prompt and returns the line the person typed (`pair`)."""
    stop: asyncio.Event | None = None
    """Setting it stops `tail`, which then exits with code 0. When None,
    `tail` stops on SIGINT or SIGTERM."""
    confirm: "ConfirmFn | None" = None
    """Test hook: asks whether to send a message instead of the macOS dialog.
    Only tests set it; there is deliberately no environment variable for this,
    so a command line cannot skip the dialog."""
    osascript: str = "/usr/bin/osascript"
    """The program that shows the confirmation dialog. Tests point it at a
    stand-in script."""
    ack_wait_s: float = 3.0
    """How long `send` and `reply` wait for the recipient's service to
    acknowledge a message before reporting it as still queued."""


@dataclass(frozen=True)
class Command:
    """A subcommand. `run` gets the arguments after the command's name and returns an exit code."""

    summary: str
    run: Callable[[list[str], CliIo], Awaitable[int]]
