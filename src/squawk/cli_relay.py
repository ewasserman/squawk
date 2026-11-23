"""The `squawk relay` command and its subcommands.

`squawk relay serve` runs the relay server in the foreground.
`squawk relay set <url>` chooses the relay this machine's service uses to
reach contacts on other networks (`--off` removes it), and
`squawk relay status` shows whether the service is connected to it.
"""

import asyncio
import contextlib
import os
import signal
from collections.abc import Mapping
from typing import cast

from squawk.cli_args import Opt, ParseArgsError, parse_args, string_value
from squawk.cli_io import CliIo, Command
from squawk.config import db_path, squawk_home
from squawk.daemon import RelayStatus, StatusResult, store_relay_settings
from squawk.daemon_control import connect_to_daemon
from squawk.relay import RelayServer
from squawk.relay.access import (
    ACCESS_MODES,
    OPEN_WARNING,
    AccessMode,
    AccessPolicy,
    AllowedKeysError,
    KeysAccess,
    OpenAccess,
    default_access_mode,
)
from squawk.relay_client import RELAY_URL_KEY
from squawk.relay_url import RelayUrlError, check_relay_url
from squawk.rpc import RpcError
from squawk.store import Store

CONNECT_WAIT_S = 5.0
"""How long `squawk relay set` and `squawk setup --relay` wait to see
whether the service connects to the new relay."""

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
        args,
        {
            "host": Opt("string"),
            "port": Opt("string", "p"),
            "data": Opt("string"),
            "trust-forwarded-for": Opt("boolean"),
            "access": Opt("string"),
            "allowed-keys": Opt("string"),
        },
    )
    port_text = string_value(values, "port")
    port = DEFAULT_PORT
    if port_text is not None:
        if not (port_text.isascii() and port_text.isdigit()) or int(port_text) > 65535:
            raise ParseArgsError(f'"{port_text}" is not a port number (0-65535)')
        port = int(port_text)
    host = string_value(values, "host") or DEFAULT_HOST
    trust_forwarded_for = values.get("trust-forwarded-for") is True
    try:
        access = _access_policy(
            string_value(values, "access"),
            host,
            trust_forwarded_for,
            allowed_keys=string_value(values, "allowed-keys"),
        )
    except AllowedKeysError as err:
        io.stderr(f"squawk relay serve: {err}\n")
        return 1
    data_dir = string_value(values, "data") or relay_data_dir(io.env)
    relay = RelayServer(
        data_dir,
        host=host,
        port=port,
        trust_forwarded_for=trust_forwarded_for,
        access=access,
    )
    await relay.start()
    stop = io.stop if io.stop is not None else asyncio.Event()
    loop = asyncio.get_running_loop()
    handled: list[signal.Signals] = []
    if io.stop is None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(sig, stop.set)
                handled.append(sig)
    # SIGHUP rereads the allowed keys or allowed users file.
    with contextlib.suppress(NotImplementedError, RuntimeError, AttributeError):
        loop.add_signal_handler(signal.SIGHUP, relay.reload_access)
        handled.append(signal.SIGHUP)
    try:
        io.stdout(f"squawk relay listening on ws://{host}:{relay.port}\n")
        io.stdout(f"Relay key: {relay.key_id}\n")
        io.stdout(f"Data:      {data_dir}\n")
        if access.mode == "open":
            io.stdout(f"{OPEN_WARNING}\n")
        elif isinstance(access, KeysAccess):
            io.stdout(f"Access:    keys ({len(access.keys)} allowed in {access.path})\n")
        else:
            io.stdout(f"Access:    {access.mode}\n")
        await stop.wait()
    finally:
        for sig in handled:
            loop.remove_signal_handler(sig)
        await relay.stop()
    io.stdout("squawk relay stopped\n")
    return 0


def _access_policy(
    given: str | None, host: str, trust_forwarded_for: bool, *, allowed_keys: str | None
) -> AccessPolicy:
    """The access policy `--access` asks for. Without `--access`, only a
    relay that nothing but this machine can reach defaults to open; any
    other relay must be told who may use it. Raises `AllowedKeysError` if
    the allowed keys file cannot be used."""
    mode: AccessMode | None
    if given is None:
        mode = default_access_mode(host, trust_forwarded_for)
        if mode is None:
            reason = (
                "it is behind a proxy (--trust-forwarded-for)"
                if trust_forwarded_for
                else f"it listens on {host}, which other machines can reach"
            )
            raise ParseArgsError(
                f"choose who may use this relay with --access open|keys|github: {reason}"
            )
    elif given in ACCESS_MODES:
        mode = given
    else:
        raise ParseArgsError(f'"{given}" is not an access mode (open, keys or github)')
    if allowed_keys is not None and mode != "keys":
        raise ParseArgsError("--allowed-keys is used only with --access keys")
    if mode == "keys":
        if allowed_keys is None:
            raise ParseArgsError("--access keys needs --allowed-keys FILE")
        return KeysAccess(allowed_keys)
    if mode != "open":
        raise ParseArgsError(f"--access {mode} is not available yet")
    return OpenAccess()


async def save_relay(home: str, url: str | None, *, allow_plain: bool = False) -> bool:
    """Stores the relay the service in `home` uses (None: no relay). If the
    service is running, it is told to switch to the new relay at once;
    otherwise the setting is written to its database and used when it
    starts. Returns whether the service is running.

    Raises `RelayUrlError` if `url` cannot be used, or `RpcError` if the
    running service refuses it."""
    if url is not None:
        check_relay_url(url, allow_plain=allow_plain)
    client = await connect_to_daemon(home)
    if client is None:
        os.makedirs(home, mode=0o700, exist_ok=True)
        store = Store.open(db_path(home))
        try:
            store_relay_settings(store, url, allow_plain=allow_plain)
        finally:
            store.close()
        return False
    try:
        await client.call("set_relay", {"url": url, "allow_plain": allow_plain})
    finally:
        await client.close()
    return True


async def wait_for_relay(home: str, timeout_s: float = CONNECT_WAIT_S) -> RelayStatus | None:
    """Asks the running service about its relay until it is connected, an
    attempt has failed, or `timeout_s` seconds have passed, and returns the
    last answer (None if no relay is set or the service is not running)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    client = await connect_to_daemon(home)
    if client is None:
        return None
    try:
        while True:
            status = cast(StatusResult, await client.call("status"))
            relay = status.get("relay")
            if (
                relay is None
                or relay["connected"]
                or relay["last_error"] is not None
                or relay.get("in_use") is False
            ):
                return relay
            if loop.time() >= deadline:
                return relay
            await asyncio.sleep(0.1)
    finally:
        await client.close()


def describe_new_relay(url: str, running: bool, relay: RelayStatus | None) -> str:
    """What `squawk relay set` and `squawk setup --relay` say after storing a relay."""
    lines = [f"Relay set to {url}."]
    if url.startswith("ws://"):
        lines.append(
            "This relay is not encrypted (ws://): use it only for testing on this machine "
            "or your own network."
        )
    if not running:
        lines.append(
            "The squawk service is not running; it connects to the relay when it starts "
            "(`squawk daemon start`)."
        )
    elif relay is not None and relay.get("in_use") is False:
        lines.append(
            "The running service is not using it (it has no network connection, or the URL "
            "no longer passes the checks). Restart it with `squawk daemon stop` and "
            "`squawk daemon start`."
        )
    elif relay is not None and relay["connected"]:
        lines.append(f"Connected. Relay key: {relay['relay_key']}")
    elif relay is not None and relay["last_error"] is not None:
        lines.append(
            f"Not connected yet: {relay['last_error']}. The service keeps trying; "
            "`squawk relay status` shows the connection."
        )
    else:
        lines.append("Still connecting; `squawk relay status` shows the connection.")
    return "\n".join(lines) + "\n"


SET_USAGE = "Usage: squawk relay set <url> [--allow-plain] | squawk relay set --off\n"


async def _set(args: list[str], io: CliIo) -> int:
    values, positionals = parse_args(
        args, {"allow-plain": Opt("boolean"), "off": Opt("boolean")}, allow_positionals=True
    )
    off = values.get("off") is True
    allow_plain = values.get("allow-plain") is True
    if len(positionals) > 1 or off == bool(positionals) or (off and allow_plain):
        io.stderr(SET_USAGE)
        return 2
    home = squawk_home(io.env)
    url = None if off else positionals[0]
    try:
        running = await save_relay(home, url, allow_plain=allow_plain)
    except (RelayUrlError, RpcError) as err:
        io.stderr(f"squawk relay set: {err}\n")
        return 1
    if url is None:
        io.stdout("Relay removed. Messages go only over the local network.\n")
        return 0
    relay = await wait_for_relay(home) if running else None
    io.stdout(describe_new_relay(check_relay_url(url, allow_plain=allow_plain), running, relay))
    return 0


def format_relay_status(
    relay: RelayStatus | None, queued: int, relayed: int, *, running: bool
) -> str:
    """The report `squawk relay status` prints."""
    if relay is None:
        lines = [
            "Relay:           none (messages go only over the local network; "
            "`squawk relay set <url>` sets one)"
        ]
    else:
        if relay["connected"]:
            connected = "yes"
        elif not running:
            connected = "no (the squawk service is not running)"
        else:
            connected = "no"
        lines = [
            f"Relay:           {relay['url']}",
            f"Connected:       {connected}",
            f"Relay key:       {relay['relay_key'] or 'unknown (not connected yet)'}",
        ]
        if not relay["connected"] and running and relay["last_error"] is not None:
            lines.append(f"Last error:      {relay['last_error']}")
    lines.append(f"Queued outbound: {queued}")
    lines.append(f"Held at relay:   {relayed} (waiting for the recipient's receipt)")
    return "\n".join(lines) + "\n"


async def _status(args: list[str], io: CliIo) -> int:
    parse_args(args)
    home = squawk_home(io.env)
    client = await connect_to_daemon(home)
    if client is not None:
        try:
            status = cast(StatusResult, await client.call("status"))
        except RpcError as err:
            io.stderr(f"squawk relay status: {err}\n")
            return 1
        finally:
            await client.close()
        io.stdout(
            format_relay_status(
                status.get("relay"),
                status["queued_outbound"],
                status.get("relayed_outbound", 0),
                running=True,
            )
        )
        return 0
    # The service is not running: report what its database says.
    relay: RelayStatus | None = None
    queued = relayed = 0
    path = db_path(home)
    if os.path.exists(path):
        store = Store.open(path)
        try:
            url = store.get_setting(RELAY_URL_KEY)
            if url:
                relay = {"url": url, "connected": False, "relay_key": None, "last_error": None}
            queued = store.count_outbound()
            relayed = store.count_relayed()
        finally:
            store.close()
    io.stdout(format_relay_status(relay, queued, relayed, running=False))
    return 0


RELAY_SUBCOMMANDS: dict[str, Command] = {
    "set": Command(
        "use a relay to reach contacts on other networks: set <url> (wss://; --allow-plain "
        "also accepts ws:// for testing), or set --off to stop using one",
        _set,
    ),
    "status": Command(
        "show the relay this service uses, whether it is connected, and the messages "
        "waiting for it",
        _status,
    ),
    "serve": Command(
        "run the relay server (--host, --port, --data, --trust-forwarded-for, --access,"
        " --allowed-keys)",
        _serve,
    ),
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
    "relay": Command(
        "choose and check the relay for contacts on other networks, or run one "
        "(set | status | serve)",
        _relay,
    ),
}
