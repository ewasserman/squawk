"""Tests for `squawk pair`, `contacts`, `auto-send`, `block` and `unblock`."""

import asyncio
import json
import re
import shutil
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest

from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.daemon import Daemon
from squawk.identity import init_identity
from squawk.network import NetworkTransport
from squawk.pairing import Pairing

BOB_KEY = "A" * 43


@dataclass
class Node:
    home: str
    daemon: Daemon
    pairing: Pairing
    address: str


class Nodes:
    def __init__(self) -> None:
        self.homes: list[str] = []
        self.nodes: list[Node] = []

    def make_home(self) -> str:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        return home

    async def start(self, name: str) -> Node:
        home = self.make_home()
        init_identity(home, name)
        transport = NetworkTransport(host="127.0.0.1", discovery=False)
        daemon = Daemon(home, transport=transport)
        await daemon.start()
        pairing = Pairing(daemon, transport, timeout_ms=5000)
        pairing.start()
        node = Node(home, daemon, pairing, f"127.0.0.1:{transport.port}")
        self.nodes.append(node)
        return node


@pytest.fixture
async def nodes() -> AsyncIterator[Nodes]:
    n = Nodes()
    try:
        yield n
    finally:
        for node in n.nodes:
            node.pairing.stop()
            await node.daemon.stop()
        for home in n.homes:
            shutil.rmtree(home, ignore_errors=True)


@dataclass
class Result:
    code: int
    out: str
    err: str


async def cli(home: str, *args: str, answer: str = "y") -> Result:
    """Runs the CLI in-process against `home`, answering any question with `answer`."""
    out: list[str] = []
    err: list[str] = []

    async def ask(prompt: str) -> str:
        out.append(prompt)
        return answer

    io = CliIo(stdout=out.append, stderr=err.append, env={"SQUAWK_HOME": home}, ask=ask)
    code = await run(list(args), io)
    return Result(code, "".join(out), "".join(err))


def code_of(out: str) -> str | None:
    match = re.search(r"Code: (\d{3} \d{3})", out)
    return None if match is None else match.group(1)


async def test_pairs_two_people_who_both_answer_yes_then_lists_blocks_and_unblocks(
    nodes: Nodes,
) -> None:
    alice = await nodes.start("alice")
    bob = await nodes.start("bob")

    bob_run = asyncio.ensure_future(cli(bob.home, "pair", "--accept"))
    await asyncio.sleep(0.05)
    a = await cli(alice.home, "pair", bob.address)
    b = await bob_run

    assert a.code == 0, a.err
    assert b.code == 0, b.err
    assert code_of(a.out) is not None
    assert code_of(a.out) == code_of(b.out)
    assert 'Paired with "bob"' in a.out
    assert 'Paired with "alice"' in b.out
    assert "Do the codes match? [y/N] " in a.out

    listed = await cli(alice.home, "contacts", "--json")
    [contact] = json.loads(listed.out)
    assert (contact["name"], contact["trust"]) == ("bob", "paired")

    assert 'Blocked "bob"' in (await cli(alice.home, "block", "bob")).out
    stored = alice.daemon.store.get_contact(bob.daemon.identity.id)
    assert stored is not None and stored.trust == "blocked"
    assert (await cli(alice.home, "unblock", "bob")).code == 0
    stored = alice.daemon.store.get_contact(bob.daemon.identity.id)
    assert stored is not None and stored.trust == "paired"


async def test_saves_nothing_when_a_person_answers_no(nodes: Nodes) -> None:
    alice = await nodes.start("alice")
    bob = await nodes.start("bob")

    bob_run = asyncio.ensure_future(cli(bob.home, "pair", "--accept", answer="n"))
    await asyncio.sleep(0.05)
    a = await cli(alice.home, "pair", bob.address, answer="y")
    b = await bob_run

    assert b.code == 1
    assert "Nothing was saved" in b.out
    assert a.code == 1
    assert "cancelled" in a.err
    assert alice.daemon.store.list_contacts() == []
    assert bob.daemon.store.list_contacts() == []


async def test_explains_usage_and_a_missing_service(nodes: Nodes) -> None:
    home = nodes.make_home()
    usage = await cli(home, "pair")
    assert usage.code == 2
    assert usage.err == "Usage: squawk pair <peer> | squawk pair --accept\n"
    r = await cli(home, "contacts")
    assert r.code == 1
    assert r.err == "squawk service is not running; start it with `squawk daemon start`\n"
    for args in (["block"], ["unblock", "a", "b"], ["auto-send", "bob"], ["auto-send"]):
        assert (await cli(home, *args)).code == 2


async def test_auto_send_turns_on_and_off_for_a_contact(nodes: Nodes) -> None:
    alice = await nodes.start("alice")
    alice.daemon.store.upsert_contact(BOB_KEY, "bob", trust="paired")
    on = await cli(alice.home, "auto-send", "bob", "on")
    assert on.code == 0
    assert on.out == 'Claude will now send messages to "bob" without asking you first.\n'
    assert alice.daemon.store.auto_send_for(BOB_KEY) == (True, False)
    off = await cli(alice.home, "auto-send", "bob", "off")
    assert off.out == 'Claude will ask you before sending each message to "bob".\n'
    assert alice.daemon.store.auto_send_for(BOB_KEY) == (False, False)
    contact = alice.daemon.store.get_contact(BOB_KEY)
    assert contact is not None and contact.auto_send is False
    assert (await cli(alice.home, "auto-send", "bob")).code == 2
    assert (await cli(alice.home, "auto-send", "bob", "maybe")).code == 2


async def test_auto_send_default_applies_to_contacts_without_their_own_setting(
    nodes: Nodes,
) -> None:
    alice = await nodes.start("alice")
    alice.daemon.store.upsert_contact(BOB_KEY, "bob", trust="paired")
    alice.daemon.store.upsert_contact("Q" * 43, "carol", trust="paired")

    def lines(out: str) -> list[str]:
        return [re.sub(r"  \S+-\S+  ", "  FP  ", line) for line in out.splitlines()]

    listed = await cli(alice.home, "contacts")
    assert lines(listed.out) == [
        "bob  paired  FP  policy=show_first (default)  auto_send=off (default)",
        "carol  paired  FP  policy=show_first (default)  auto_send=off (default)",
    ]

    on = await cli(alice.home, "auto-send", "--default", "on")
    assert on.code == 0
    assert on.out == (
        "Claude will now send messages to contacts without their own setting without "
        "asking you first.\n"
    )
    assert (await cli(alice.home, "auto-send", "carol", "off")).code == 0
    listed = await cli(alice.home, "contacts")
    assert lines(listed.out) == [
        "bob  paired  FP  policy=show_first (default)  auto_send=on (default)",
        "carol  paired  FP  policy=show_first (default)  auto_send=off",
    ]
    contacts: list[dict[str, Any]] = json.loads((await cli(alice.home, "contacts", "--json")).out)
    assert [(c["name"], c["auto_send"], c["auto_send_is_default"]) for c in contacts] == [
        ("bob", True, True),
        ("carol", False, False),
    ]

    back = await cli(alice.home, "auto-send", "carol", "default")
    assert back.out == (
        'Claude will now send messages to "carol" without asking you first. '
        "(This is the default; `squawk auto-send --default on|off` changes it.)\n"
    )
    off = await cli(alice.home, "auto-send", "--default", "off")
    assert off.out == (
        "Claude will ask you before sending each message to contacts without their own setting.\n"
    )
    assert alice.daemon.store.auto_send_for(BOB_KEY) == (False, True)
    for args in (["--default", "maybe"], ["--default", "on", "bob"], ["--default"]):
        assert (await cli(alice.home, "auto-send", *args)).code == 2


async def test_contacts_says_when_there_are_none(nodes: Nodes) -> None:
    alice = await nodes.start("alice")
    r = await cli(alice.home, "contacts")
    assert r.out == "No contacts yet. Pair with someone using `squawk pair`.\n"
    assert (await cli(alice.home, "contacts", "--json")).out == "[]\n"
