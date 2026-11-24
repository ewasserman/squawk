"""The `squawk relay` command and its subcommands.

`squawk relay serve` runs the relay server in the foreground.
`squawk relay set <url>` chooses the relay this machine's service uses to
reach contacts on other networks (`--off` removes it), and
`squawk relay status` shows whether the service is connected to it.
`squawk relay admin` lists the GitHub users that signed in to a relay run on
this machine and removes keys from it.
"""

import asyncio
import contextlib
import os
import signal
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

from squawk import jsontext
from squawk.cli_args import Opt, ParseArgsError, parse_args, string_value
from squawk.cli_io import NOT_RUNNING_MESSAGE, CliIo, Command
from squawk.config import db_path, squawk_home
from squawk.daemon import RelayStatus, StatusResult, store_relay_settings
from squawk.daemon_control import connect_to_daemon
from squawk.encoding import is_key_id
from squawk.relay import RelayServer
from squawk.relay.access import (
    ACCESS_MODES,
    DEFAULT_MAX_KEYS_PER_USER,
    OPEN_WARNING,
    AccessMode,
    AccessPolicy,
    AllowedKeysError,
    AllowedUsersError,
    GitHubAccess,
    KeysAccess,
    OpenAccess,
    default_access_mode,
)
from squawk.relay.github import UrllibGitHub
from squawk.relay.storage import DB_FILE, RelayStore, SignedInUser
from squawk.relay_client import NEEDS_SIGN_IN_TEXT, NOT_PERMITTED_TEXT, RELAY_URL_KEY
from squawk.relay_url import RelayUrlError, check_relay_url
from squawk.rpc import RpcError
from squawk.store import Store
from squawk.timefmt import iso_from_ms, now_ms, parse_iso_ms

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
            "allowed-users": Opt("string"),
            "github-client-id": Opt("string"),
            "max-keys-per-user": Opt("string"),
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
            allowed_users=string_value(values, "allowed-users"),
            github_client_id=string_value(values, "github-client-id"),
            max_keys_per_user=string_value(values, "max-keys-per-user"),
        )
    except (AllowedKeysError, AllowedUsersError) as err:
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
        loop.add_signal_handler(signal.SIGHUP, relay.reload_access_logged)
        handled.append(signal.SIGHUP)
    try:
        io.stdout(f"squawk relay listening on ws://{host}:{relay.port}\n")
        io.stdout(f"Relay key: {relay.key_id}\n")
        io.stdout(f"Data:      {data_dir}\n")
        if access.mode == "open":
            io.stdout(f"{OPEN_WARNING}\n")
        elif isinstance(access, KeysAccess):
            io.stdout(f"Access:    keys ({len(access.keys)} allowed in {access.path})\n")
        elif isinstance(access, GitHubAccess):
            io.stdout(f"Access:    github ({len(access.users)} users in {access.path})\n")
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
    given: str | None,
    host: str,
    trust_forwarded_for: bool,
    *,
    allowed_keys: str | None,
    allowed_users: str | None = None,
    github_client_id: str | None = None,
    max_keys_per_user: str | None = None,
) -> AccessPolicy:
    """The access policy `--access` asks for. Without `--access`, only a
    relay that nothing but this machine can reach defaults to open; any
    other relay must be told who may use it. Raises `AllowedKeysError` or
    `AllowedUsersError` if the allowed keys or allowed users file cannot be
    used."""
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
    if mode != "github":
        for option, value in (
            ("--allowed-users", allowed_users),
            ("--github-client-id", github_client_id),
            ("--max-keys-per-user", max_keys_per_user),
        ):
            if value is not None:
                raise ParseArgsError(f"{option} is used only with --access github")
    if mode == "keys":
        if allowed_keys is None:
            raise ParseArgsError("--access keys needs --allowed-keys FILE")
        return KeysAccess(allowed_keys)
    if mode == "github":
        if github_client_id is None or not github_client_id.strip():
            raise ParseArgsError("--access github needs --github-client-id ID")
        if allowed_users is None:
            raise ParseArgsError("--access github needs --allowed-users FILE")
        max_keys = DEFAULT_MAX_KEYS_PER_USER
        if max_keys_per_user is not None:
            if not (max_keys_per_user.isascii() and max_keys_per_user.isdigit()) or (
                int(max_keys_per_user) < 1
            ):
                raise ParseArgsError(f'"{max_keys_per_user}" is not a number of keys (1 or more)')
            max_keys = int(max_keys_per_user)
        return GitHubAccess(
            allowed_users, UrllibGitHub(github_client_id.strip()), max_keys_per_user=max_keys
        )
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
                or relay.get("access_problem") is not None
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
    elif relay is not None and relay.get("access_problem") == "needs-sign-in":
        lines.append("This relay needs you to sign in: run `squawk relay login`.")
    elif relay is not None and relay.get("access_problem") == "not-permitted":
        lines.append(
            "This relay does not permit this computer's key; ask the person who runs it. "
            "The service tries again every 6 hours."
        )
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
        problem = relay.get("access_problem") if running else None
        note = {"not-permitted": NOT_PERMITTED_TEXT, "needs-sign-in": NEEDS_SIGN_IN_TEXT}.get(
            problem or ""
        )
        lines = [
            f"Relay:           {relay['url']}" + ("" if note is None else f" ({note})"),
            f"Connected:       {connected}",
            f"Relay key:       {relay['relay_key'] or 'unknown (not connected yet)'}",
        ]
        if not relay["connected"] and running and note is None and relay["last_error"] is not None:
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


LOGIN_WARNING = (
    "GitHub should ask only to read your public profile. If it asks for\n"
    "anything more, deny it: the relay should never need more.\n"
)


async def _login(args: list[str], io: CliIo) -> int:
    parse_args(args)
    client = await connect_to_daemon(squawk_home(io.env))
    if client is None:
        io.stderr(NOT_RUNNING_MESSAGE + "\n")
        return 1
    try:
        started = await client.call("relay_login_start")
        if not started.get("needed"):
            io.stdout("This service is already let in by the relay; no sign-in is needed.\n")
            return 0
        minutes = _minutes_until(str(started.get("expires_at")))
        valid = "" if minutes is None else f" (valid for {minutes} minutes)"
        io.stdout(
            f"Open {started['verification_uri']} and enter {started['user_code']}{valid}.\n"
            + LOGIN_WARNING
        )
        result = await client.call("relay_login_wait")
    except RpcError as err:
        io.stderr(f"squawk relay login: {err}\n")
        return 1
    except ConnectionError:
        io.stderr("squawk relay login: the squawk service stopped during the sign-in\n")
        return 1
    finally:
        await client.close()
    user = result.get("user")
    io.stdout(f"Signed in to the relay as {user}\n" if user else "Signed in to the relay\n")
    return 0


def _minutes_until(iso: str) -> int | None:
    """Whole minutes from now until `iso` (rounded to the nearest), or None."""
    at = parse_iso_ms(iso)
    if at is None:
        return None
    return max(0, round((at - now_ms()) / 60_000))


# `squawk relay admin`: works directly on the database of a relay run on this
# machine, which may be running in another process at the same time (SQLite
# lets both use the database; each waits briefly for the other's writes).


def _open_relay_data(command: str, data_option: str | None, io: CliIo) -> RelayStore | None:
    """Opens the relay database in `--data DIR` (default: where `squawk
    relay serve` keeps it). Reports an error and returns None if there is no
    relay data there; it never creates a data directory."""
    data_dir = data_option or relay_data_dir(io.env)
    if not os.path.isfile(os.path.join(data_dir, DB_FILE)):
        io.stderr(
            f"squawk relay admin {command}: there is no relay data in {data_dir}"
            " (give the relay's data directory with --data DIR)\n"
        )
        return None
    return RelayStore.open(data_dir)


def _readable_time(ms: int) -> str:
    """`ms` as a date and time in UTC to the minute, e.g. "2026-11-21 12:00 UTC"."""
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%d %H:%M UTC")


NO_USERS_TEXT = (
    "No GitHub user has signed in to this relay.\n"
    "(A relay run with --access keys has no users: the keys that may use it are the ones "
    "in its allowed keys file.)\n"
)


def format_relay_users(users: list[SignedInUser]) -> str:
    """The report `squawk relay admin users` prints."""
    if not users:
        return NO_USERS_TEXT
    blocks = []
    for user in users:
        lines = [
            f"{user.login} (GitHub id {user.github_id})",
            f"  first signed in {_readable_time(user.first_signed_in_at_ms)},"
            f" last signed in {_readable_time(user.last_signed_in_at_ms)}",
        ]
        if not user.keys:
            lines.append("  no keys")
        else:
            lines.append(f"  keys ({len(user.keys)}):")
            for key in user.keys:
                connected = (
                    "no mailbox"
                    if key.last_connected_at_ms is None
                    else f"last connected {_readable_time(key.last_connected_at_ms)}"
                )
                lines.append(
                    f"    {key.key_id}  added {_readable_time(key.added_at_ms)}, {connected}"
                )
        blocks.append("\n".join(lines) + "\n")
    return "\n".join(blocks)


def relay_users_json(users: list[SignedInUser]) -> dict[str, object]:
    """What `squawk relay admin users --json` prints, before it is turned into text."""
    return {
        "users": [
            {
                "login": user.login,
                "github_id": user.github_id,
                "first_signed_in_at": iso_from_ms(user.first_signed_in_at_ms),
                "last_signed_in_at": iso_from_ms(user.last_signed_in_at_ms),
                "keys": [
                    {
                        "key": key.key_id,
                        "added_at": iso_from_ms(key.added_at_ms),
                        "last_connected_at": None
                        if key.last_connected_at_ms is None
                        else iso_from_ms(key.last_connected_at_ms),
                    }
                    for key in user.keys
                ],
            }
            for user in users
        ]
    }


async def _admin_users(args: list[str], io: CliIo) -> int:
    values, _ = parse_args(args, {"data": Opt("string"), "json": Opt("boolean")})
    store = _open_relay_data("users", string_value(values, "data"), io)
    if store is None:
        return 1
    try:
        users = store.signed_in_users()
    finally:
        store.close()
    if values.get("json") is True:
        io.stdout(jsontext.stringify(relay_users_json(users), "  ") + "\n")
    else:
        io.stdout(format_relay_users(users))
    return 0


REMOVE_KEY_USAGE = "Usage: squawk relay admin remove-key <key> [--data DIR]\n"


async def _admin_remove_key(args: list[str], io: CliIo) -> int:
    values, positionals = parse_args(args, {"data": Opt("string")}, allow_positionals=True)
    if len(positionals) != 1:
        io.stderr(REMOVE_KEY_USAGE)
        return 2
    key = positionals[0]
    if not is_key_id(key):
        io.stderr(f'squawk relay admin remove-key: "{key}" is not a key id\n')
        return 2
    store = _open_relay_data("remove-key", string_value(values, "data"), io)
    if store is None:
        return 1
    try:
        owner = store.key_owner(key)
        if owner is None and not store.has_mailbox(key):
            io.stderr(f"squawk relay admin remove-key: this relay does not know the key {key}\n")
            return 1
        waiting = store.usage(key, 0).messages
        store.delete_mailbox(key)
    finally:
        store.close()
    owned = "" if owner is None else f" (GitHub user {owner.login}, id {owner.github_id})"
    plural = "" if waiting == 1 else "s"
    io.stdout(
        f"Removed the key {key}{owned}: deleted its mailbox, its allow list, "
        f"{waiting} waiting message{plural} and any open invite.\n"
        "If the relay is running, it closes the key's connection within a minute.\n"
        "In GitHub mode the key must sign in again to use the relay; in keys mode, take it "
        "out of the allowed keys file too, or it can connect again.\n"
    )
    return 0


ADMIN_SUBCOMMANDS: dict[str, Command] = {
    "users": Command(
        "list the GitHub users that signed in, with their keys (--data DIR, --json)",
        _admin_users,
    ),
    "remove-key": Command(
        "forget a key and delete its mailbox, allow list, waiting messages and invite: "
        "remove-key <key> (--data DIR)",
        _admin_remove_key,
    ),
}


async def _dispatch(
    usage: str, subcommands: Mapping[str, Command], args: list[str], io: CliIo
) -> int:
    """Runs the subcommand named by `args[0]`, or prints `usage` and the
    list of subcommands."""
    sub = subcommands.get(args[0]) if args else None
    if sub is None:
        width = max(len(name) for name in subcommands)
        lines = "".join(
            f"  {name.ljust(width)}  {cmd.summary}\n" for name, cmd in subcommands.items()
        )
        io.stderr(f"{usage}\n\nSubcommands:\n{lines}")
        return 2
    return await sub.run(args[1:], io)


async def _admin(args: list[str], io: CliIo) -> int:
    return await _dispatch(
        "Usage: squawk relay admin <subcommand> [--data DIR]\n\n"
        "Works on the database of a relay run on this machine (by default where "
        "`squawk relay serve` keeps it), also while the relay is running.",
        ADMIN_SUBCOMMANDS,
        args,
        io,
    )


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
    "login": Command("sign in to a relay that admits people by their GitHub account", _login),
    "serve": Command(
        "run the relay server (--host, --port, --data, --trust-forwarded-for, --access,"
        " --allowed-keys, --allowed-users, --github-client-id, --max-keys-per-user)",
        _serve,
    ),
    "admin": Command(
        "look after a relay run on this machine: admin users lists the GitHub users that "
        "signed in and their keys; admin remove-key <key> removes a key (--data DIR)",
        _admin,
    ),
}


async def _relay(args: list[str], io: CliIo) -> int:
    return await _dispatch("Usage: squawk relay <subcommand>", RELAY_SUBCOMMANDS, args, io)


RELAY_COMMANDS: dict[str, Command] = {
    "relay": Command(
        "choose and check the relay for contacts on other networks, or run one "
        "(set | status | login | serve | admin)",
        _relay,
    ),
}
