"""Commands for pairing and managing contacts: `squawk pair`, `contacts`,
`auto-send`, `policy`, `block` and `unblock`. They talk to the running
service over its local socket.
"""

import contextlib
import re
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from squawk import jsontext
from squawk.cli_args import Opt, parse_args, string_value
from squawk.cli_io import NOT_RUNNING_MESSAGE, CliIo, Command
from squawk.config import squawk_home
from squawk.daemon_control import connect_to_daemon
from squawk.rpc import RpcClient, RpcError


async def _with_service(io: CliIo, work: Callable[[RpcClient], Awaitable[int]]) -> int:
    """Connects, runs `work` and closes the connection. Any error is printed
    as `squawk: <message>` and gives exit code 1."""
    rpc = await connect_to_daemon(squawk_home(io.env))
    if rpc is None:
        io.stderr(NOT_RUNNING_MESSAGE + "\n")
        return 1
    try:
        return await work(rpc)
    except Exception as err:
        io.stderr(f"squawk: {err}\n")
        return 1
    finally:
        await rpc.close()


def format_code(code: str) -> str:
    """ "123456" -> "123 456", easier to read aloud."""
    return f"{code[:3]} {code[3:]}"


PAIR_USAGE = "Usage: squawk pair <peer> | squawk pair --accept | squawk pair --code <code>\n"


async def _pair(args: list[str], io: CliIo) -> int:
    values, positionals = parse_args(
        args, {"accept": Opt("boolean"), "code": Opt("string")}, allow_positionals=True
    )
    accept = values.get("accept") is True
    code = string_value(values, "code")
    peer = positionals[0] if positionals else None
    if sum(1 for chosen in (accept, code is not None, peer is not None) if chosen) != 1:
        io.stderr(PAIR_USAGE)
        return 2

    async def work(rpc: RpcClient) -> int:
        if accept:
            io.stdout(
                "Waiting for someone to pair with you (up to 2 minutes). "
                "Ask them to run `squawk pair <your name>`.\n"
            )
            offer = await rpc.call("pair_accept")
        elif code is not None:
            io.stdout("Joining the invite through the relay...\n")
            offer = await rpc.call("pair_join", {"code": code})
        else:
            io.stdout(f"Contacting {peer}...\n")
            offer = await rpc.call("pair_start", {"peer": peer})
        return await _compare_and_confirm(rpc, offer, io, through_relay=code is not None)

    return await _with_service(io, work)


async def _invite(args: list[str], io: CliIo) -> int:
    parse_args(args)

    async def work(rpc: RpcClient) -> int:
        invite = await rpc.call("invite_create")
        io.stdout(
            "\n".join(
                [
                    "",
                    f"    Invite code: {invite['code']}",
                    "",
                    "Read this code to the person you want to pair with, on a phone or",
                    "video call. They run:",
                    "",
                    f"    squawk pair --code {invite['code']}",
                    "",
                    "The code works once, for 10 minutes. Waiting for them to join...",
                    "",
                ]
            )
        )
        offer = await rpc.call("invite_wait")
        return await _compare_and_confirm(rpc, offer, io, through_relay=True)

    return await _with_service(io, work)


async def _compare_and_confirm(
    rpc: RpcClient, offer: dict[str, Any], io: CliIo, *, through_relay: bool
) -> int:
    """Shows the code to compare, asks whether it matches, and confirms."""
    if through_relay:
        how = [
            "Compare this code with the one on the other person's screen,",
            "on a phone or video call, where you can hear or see them. Do not",
            "send it as a message: the relay passed this pairing along and",
            "could be interfering. If the codes differ, answer no.",
        ]
    else:
        how = [
            "Compare this code with the one on the other person's screen,",
            "in person or on a call. If they differ, someone may be",
            "interfering: answer no.",
        ]
    io.stdout(
        "\n".join(
            [
                "",
                f'Pairing with "{offer["peer_name"]}"',
                f"Their key fingerprint: {offer['peer_fingerprint']}",
                "",
                f"    Code: {format_code(offer['code'])}",
                "",
                *how,
                "",
            ]
        )
    )
    answer = await io.ask("Do the codes match? [y/N] ")
    if not re.fullmatch(r"\s*y(es)?\s*", answer, re.IGNORECASE):
        with contextlib.suppress(RpcError, ConnectionError):
            await rpc.call("pair_confirm", {"pairing_id": offer["pairing_id"], "match": False})
        io.stdout("Pairing cancelled. Nothing was saved.\n")
        return 1
    io.stdout("Waiting for the other person to confirm...\n")
    result = await rpc.call("pair_confirm", {"pairing_id": offer["pairing_id"], "match": True})
    io.stdout(f'Paired with "{result["contact"]["name"]}".\n')
    return 0


async def _contacts(args: list[str], io: CliIo) -> int:
    values, _ = parse_args(args, {"json": Opt("boolean")})

    async def work(rpc: RpcClient) -> int:
        contacts: list[dict[str, Any]] = (await rpc.call("contacts"))["contacts"]
        if values.get("json"):
            io.stdout(jsontext.stringify(contacts) + "\n")
            return 0
        if not contacts:
            io.stdout("No contacts yet. Pair with someone using `squawk pair`.\n")
            return 0
        for c in contacts:
            policy_default = " (default)" if c["policy_is_default"] else ""
            auto_default = " (default)" if c.get("auto_send_is_default") else ""
            io.stdout(
                f"{c['name']}  {c['trust']}  {c['fingerprint']}  "
                f"policy={c['inbound_policy']}{policy_default}  "
                f"auto_send={'on' if c['auto_send'] else 'off'}{auto_default}\n"
            )
        return 0

    return await _with_service(io, work)


AUTO_SEND_USAGE = (
    "Usage: squawk auto-send <contact> on|off|default | squawk auto-send --default on|off\n"
)


async def _auto_send(args: list[str], io: CliIo) -> int:
    values, positionals = parse_args(args, {"default": Opt("string")}, allow_positionals=True)
    default = string_value(values, "default")
    if default is not None:
        if default not in ("on", "off") or positionals:
            io.stderr(AUTO_SEND_USAGE)
            return 2

        async def set_default(rpc: RpcClient) -> int:
            await rpc.call("set_default_auto_send", {"auto_send": default == "on"})
            io.stdout(
                "Claude will now send messages to contacts without their own setting "
                "without asking you first.\n"
                if default == "on"
                else "Claude will ask you before sending each message to contacts without "
                "their own setting.\n"
            )
            return 0

        return await _with_service(io, set_default)

    if len(positionals) != 2 or positionals[1] not in ("on", "off", "default"):
        io.stderr(AUTO_SEND_USAGE)
        return 2
    contact, setting = positionals
    value = None if setting == "default" else setting == "on"

    async def work(rpc: RpcClient) -> int:
        c = (await rpc.call("update_contact", {"contact": contact, "auto_send": value}))["contact"]
        if c["auto_send"]:
            text = f'Claude will now send messages to "{c["name"]}" without asking you first.'
        else:
            text = f'Claude will ask you before sending each message to "{c["name"]}".'
        if value is None:
            text += " (This is the default; `squawk auto-send --default on|off` changes it.)"
        io.stdout(text + "\n")
        return 0

    return await _with_service(io, work)


def _to_policy(value: str | None) -> str | None:
    return {"show-first": "show_first", "auto-answer": "auto_answer"}.get(value or "")


def _explain(policy: str) -> str:
    if policy == "auto_answer":
        return (
            "Claude may answer their messages directly (replies are still confirmed with "
            "you unless auto-send is on)."
        )
    return "Claude will show you their messages and take no action without your approval."


async def _policy(args: list[str], io: CliIo) -> int:
    values, positionals = parse_args(args, {"default": Opt("string")}, allow_positionals=True)
    default = string_value(values, "default")
    if default is not None:
        default_policy = _to_policy(default)
        if default_policy is None or positionals:
            io.stderr("Usage: squawk policy --default show-first|auto-answer\n")
            return 2

        async def set_default(rpc: RpcClient) -> int:
            await rpc.call("set_default_policy", {"policy": default_policy})
            io.stdout(
                f"Default for contacts without their own setting: {default}. "
                f"{_explain(default_policy)}\n"
            )
            return 0

        return await _with_service(io, set_default)

    contact = positionals[0] if positionals else None
    setting = positionals[1] if len(positionals) > 1 else None
    policy = None if setting == "default" else _to_policy(setting)
    if not contact or (policy is None and setting != "default") or len(positionals) > 2:
        io.stderr("Usage: squawk policy <contact> show-first|auto-answer|default\n")
        return 2

    async def work(rpc: RpcClient) -> int:
        c = (await rpc.call("update_contact", {"contact": contact, "inbound_policy": policy}))[
            "contact"
        ]
        shown = c["inbound_policy"].replace("_", "-", 1)
        note = " (the default)" if policy is None else ""
        io.stdout(f'"{c["name"]}": {shown}{note}. {_explain(c["inbound_policy"])}\n')
        return 0

    return await _with_service(io, work)


async def _set_trust(method: Literal["block", "unblock"], args: list[str], io: CliIo) -> int:
    _, positionals = parse_args(args, {}, allow_positionals=True)
    if len(positionals) != 1 or not positionals[0]:
        io.stderr(f"Usage: squawk {method} <contact>\n")
        return 2
    contact = positionals[0]

    async def work(rpc: RpcClient) -> int:
        result = await rpc.call(method, {"contact": contact})
        verb = "Blocked" if method == "block" else "Unblocked"
        io.stdout(f'{verb} "{result["name"]}".\n')
        return 0

    return await _with_service(io, work)


async def _block(args: list[str], io: CliIo) -> int:
    return await _set_trust("block", args, io)


async def _unblock(args: list[str], io: CliIo) -> int:
    return await _set_trust("unblock", args, io)


CONTACT_COMMANDS: dict[str, Command] = {
    "pair": Command(
        "pair with someone: `pair <peer>` (name from `squawk peers`, or host:port), "
        "`pair --accept` to wait, or `pair --code <code>` to join an invite through the relay",
        _pair,
    ),
    "invite": Command(
        "create a one-time code for pairing through the relay with someone on another network",
        _invite,
    ),
    "contacts": Command("list paired and blocked contacts (--json)", _contacts),
    "auto-send": Command(
        "let Claude send to a contact without asking you first: "
        "`auto-send <contact> on|off|default`, or `auto-send --default on|off` "
        "(off by default)",
        _auto_send,
    ),
    "policy": Command(
        "decide what your Claude does with a contact's messages: "
        "`policy <contact> show-first|auto-answer|default`, or "
        "`policy --default show-first|auto-answer`",
        _policy,
    ),
    "block": Command("refuse all connections and messages from a contact", _block),
    "unblock": Command("accept a blocked contact again", _unblock),
}
