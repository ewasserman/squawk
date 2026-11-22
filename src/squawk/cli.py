"""The `squawk` command.

The subcommands live in tables: setup and uninstall (cli_setup.py), the
contact commands (cli_contacts.py), the identity and service commands
(here), the message commands (cli_messages.py), the session commands
(cli_sessions.py) and the relay commands (cli_relay.py). `main` finds a
command by name and `squawk help` lists them all in that order. cli_io.py explains how to add one.
"""

import asyncio
import sys
from collections.abc import Sequence

from squawk.cli_args import Opt, ParseArgsError, parse_args, string_value
from squawk.cli_contacts import CONTACT_COMMANDS
from squawk.cli_io import CliIo, Command, quiet_stdout
from squawk.cli_messages import MESSAGE_COMMANDS, format_service_status
from squawk.cli_relay import RELAY_COMMANDS
from squawk.cli_sessions import SESSION_COMMANDS
from squawk.cli_setup import SETUP_COMMANDS, SetupError
from squawk.config import squawk_home
from squawk.daemon import DaemonRunningError
from squawk.daemon_control import (
    DaemonControlError,
    daemon_status,
    run_daemon_foreground,
    start_daemon,
    stop_daemon,
)
from squawk.identity import (
    IdentityExistsError,
    NoIdentityError,
    fingerprint,
    init_identity,
    load_identity,
)
from squawk.version import VERSION


async def _init(args: list[str], io: CliIo) -> int:
    values, _ = parse_args(args, {"name": Opt("string", "n")})
    home = squawk_home(io.env)
    identity = init_identity(home, string_value(values, "name"))
    io.stdout(f'Created identity "{identity.name}" in {home}\n')
    io.stdout(f"Fingerprint: {fingerprint(identity.public_key)}\n")
    return 0


async def _whoami(args: list[str], io: CliIo) -> int:
    parse_args(args)
    identity = load_identity(squawk_home(io.env))
    io.stdout(f"Name:        {identity.name}\n")
    io.stdout(f"Key:         {identity.id}\n")
    io.stdout(f"Fingerprint: {fingerprint(identity.public_key)}\n")
    return 0


async def _daemon(args: list[str], io: CliIo) -> int:
    _, positionals = parse_args(args, allow_positionals=True)
    action = positionals[0] if positionals else None
    home = squawk_home(io.env)
    if len(positionals) > 1:
        io.stderr(f'squawk daemon: unexpected argument "{positionals[1]}"\n')
        return 2
    if action == "start":
        load_identity(home)
        result = await start_daemon(home, io.env)
        io.stdout(
            f"squawkd is already running (pid {result.pid})\n"
            if result.already_running
            else f"squawkd started (pid {result.pid})\n"
        )
        return 0
    if action == "stop":
        stopped = await stop_daemon(home)
        io.stdout("squawkd stopped\n" if stopped else "squawkd is not running\n")
        return 0 if stopped else 1
    if action == "status":
        status = await daemon_status(home)
        if status is None:
            io.stdout("squawkd is not running\n")
            return 1
        io.stdout(format_service_status(status))
        return 0
    if action == "run":
        load_identity(home)
        await run_daemon_foreground(home)
        return 0
    io.stderr("Usage: squawk daemon start | stop | status | run\n")
    return 2


COMMANDS: dict[str, Command] = {
    **SETUP_COMMANDS,
    **CONTACT_COMMANDS,
    "init": Command("create this machine's key pair (--name <display name>)", _init),
    "whoami": Command("print this machine's display name, key and fingerprint", _whoami),
    "daemon": Command("control the background service (start | stop | status | run)", _daemon),
    **MESSAGE_COMMANDS,
    **SESSION_COMMANDS,
    **RELAY_COMMANDS,
}
"""Every subcommand, in the order `squawk help` lists them."""


def usage() -> str:
    width = max(len(name) for name in COMMANDS)
    lines = [f"  {name.ljust(width)}  {cmd.summary}" for name, cmd in COMMANDS.items()]
    return "Usage: squawk <command> [options]\n\nCommands:\n" + "\n".join(lines) + "\n"


async def run(argv: Sequence[str], io: CliIo | None = None) -> int:
    """Runs the command line `argv` (without the program name) and returns the exit code."""
    io = CliIo() if io is None else io
    if not argv or argv[0] in ("help", "--help"):
        io.stdout(usage())
        return 0
    name, rest = argv[0], list(argv[1:])
    if name == "--version":
        io.stdout(f"{VERSION}\n")
        return 0
    command = COMMANDS.get(name)
    if command is None:
        io.stderr(f'squawk: unknown command "{name}"\n\n{usage()}')
        return 2
    try:
        return await command.run(rest, io)
    except (
        IdentityExistsError,
        NoIdentityError,
        DaemonRunningError,
        DaemonControlError,
        SetupError,
    ) as err:
        io.stderr(f"squawk: {err}\n")
        return 1
    except ParseArgsError as err:
        io.stderr(f"squawk {name}: {err}\n")
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    """The `squawk` program: runs `argv` (default: the process arguments) and returns an exit code.

    When output goes to a program that stops reading early (such as
    `squawk tail | head`), it exits quietly with code 0.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        return asyncio.run(run(args))
    except BrokenPipeError:
        quiet_stdout()
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
