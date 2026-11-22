"""The `squawk relay` command and its subcommands.

`squawk relay serve` runs the relay server in the foreground. Later
subcommands (setting which relay this service uses, and its status) are
added to `RELAY_SUBCOMMANDS`.
"""

import asyncio
import contextlib
import os
import signal
from collections.abc import Mapping

from squawk.cli_args import Opt, ParseArgsError, parse_args, string_value
from squawk.cli_io import CliIo, Command
from squawk.config import squawk_home
from squawk.relay import RelayServer

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def relay_data_dir(env: Mapping[str, str]) -> str:
    """Where `squawk relay serve` keeps its database by default: the
    SQUAWK_RELAY_DATA environment variable if set, otherwise the `relay`
    directory in the squawk home directory."""
    from_env = env.get("SQUAWK_RELAY_DATA")
    if from_env:
        return from_env
    return os.path.join(squawk_home(env), "relay")


async def _serve(args: list[str], io: CliIo) -> int:
    values, _ = parse_args(
        args, {"host": Opt("string"), "port": Opt("string", "p"), "data": Opt("string")}
    )
    port_text = string_value(values, "port")
    port = DEFAULT_PORT
    if port_text is not None:
        if not port_text.isdigit() or int(port_text) > 65535:
            raise ParseArgsError(f'"{port_text}" is not a port number (0-65535)')
        port = int(port_text)
    host = string_value(values, "host") or DEFAULT_HOST
    data_dir = string_value(values, "data") or relay_data_dir(io.env)
    relay = RelayServer(data_dir, host=host, port=port)
    await relay.start()
    stop = io.stop if io.stop is not None else asyncio.Event()
    loop = asyncio.get_running_loop()
    handled: list[signal.Signals] = []
    if io.stop is None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(sig, stop.set)
                handled.append(sig)
    try:
        io.stdout(f"squawk relay listening on ws://{host}:{relay.port}\n")
        io.stdout(f"Relay key: {relay.key_id}\n")
        io.stdout(f"Data:      {data_dir}\n")
        await stop.wait()
    finally:
        for sig in handled:
            loop.remove_signal_handler(sig)
        await relay.stop()
    io.stdout("squawk relay stopped\n")
    return 0


RELAY_SUBCOMMANDS: dict[str, Command] = {
    "serve": Command("run the relay server (--host, --port, --data)", _serve),
}


async def _relay(args: list[str], io: CliIo) -> int:
    sub = RELAY_SUBCOMMANDS.get(args[0]) if args else None
    if sub is None:
        width = max(len(name) for name in RELAY_SUBCOMMANDS)
        lines = "".join(
            f"  {name.ljust(width)}  {cmd.summary}\n" for name, cmd in RELAY_SUBCOMMANDS.items()
        )
        io.stderr(f"Usage: squawk relay <subcommand>\n\nSubcommands:\n{lines}")
        return 2
    return await sub.run(args[1:], io)


RELAY_COMMANDS: dict[str, Command] = {
    "relay": Command("run the relay server (serve)", _relay),
}
