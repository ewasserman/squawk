"""Pairing through a relay with an invite code, mDNS off and no direct route."""

import asyncio
import os
import re
import shutil
import tempfile
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from websockets.asyncio.client import ClientConnection, connect

from squawk import jsontext
from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.crypto import ed25519_random_secret_key, ed25519_sign
from squawk.daemon import Daemon
from squawk.encoding import to_base64url
from squawk.identity import Identity, identity_from_secret_key, init_identity
from squawk.network import NetworkTransport, auth_message
from squawk.pairing import Pairing, PairingError
from squawk.relay import RelayServer
from squawk.relay.limits import MINUTE_MS
from squawk.relay_client import RelayClient


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


class Clock:
    def __init__(self) -> None:
        self.ms = 1_800_000_000_000

    def __call__(self) -> int:
        return self.ms


@dataclass
class Node:
    daemon: Daemon
    transport: NetworkTransport
    pairing: Pairing

    @property
    def id(self) -> str:
        return self.daemon.identity.id


class Setup:
    def __init__(self, relay: RelayServer) -> None:
        self.relay = relay
        self.url = f"ws://127.0.0.1:{relay.port}"
        self.homes: list[str] = []
        self.nodes: list[Node] = []

    async def node(self, name: str) -> Node:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        relay = RelayClient(
            self.url, allow_plain=True, backoff_min_ms=50, allow_check_interval_ms=50
        )
        transport = NetworkTransport(
            host="127.0.0.1", discovery=False, retry_interval_ms=50, relay=relay
        )
        daemon = Daemon(home, transport=transport)
        await daemon.start()
        pairing = Pairing(daemon, transport, timeout_ms=5_000)
        pairing.start()
        node = Node(daemon, transport, pairing)
        self.nodes.append(node)
        await wait_for(lambda: relay.connected)
        return node


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
async def setup(tmp_path: object, clock: Clock) -> AsyncIterator[Setup]:
    relay = RelayServer(os.path.join(str(tmp_path), "relay"), port=0, now=clock)
    await relay.start()
    s = Setup(relay)
    try:
        yield s
    finally:
        for node in s.nodes:
            node.pairing.stop()
        await asyncio.gather(*(n.daemon.stop() for n in s.nodes), return_exceptions=True)
        await relay.stop()
        for home in s.homes:
            shutil.rmtree(home, ignore_errors=True)


async def test_pairs_with_an_invite_code_and_then_messages_flow(setup: Setup) -> None:
    alice = await setup.node("alice")
    bob = await setup.node("bob")
    invite = await alice.pairing.invite()
    alice_offer = asyncio.ensure_future(alice.pairing.invite_joined())
    bob_offer = await bob.pairing.join(invite["code"].lower())
    a_offer = await alice_offer
    assert a_offer["code"] == bob_offer["code"]
    assert a_offer["peer_key"] == bob.id
    assert bob_offer["peer_key"] == alice.id
    assert (a_offer["peer_name"], bob_offer["peer_name"]) == ("bob", "alice")

    a, b = await asyncio.gather(
        alice.pairing.confirm(a_offer["pairing_id"], True),
        bob.pairing.confirm(bob_offer["pairing_id"], True),
    )
    assert a.public_key == bob.id and a.relay_url == setup.url
    assert b.public_key == alice.id and b.relay_url == setup.url

    sent = await alice.daemon.send({"to": "bob", "body": "paired through the relay"})
    await wait_for(lambda: bob.daemon.store.get_message(sent["id"]))
    await wait_for(lambda: alice.daemon.store.acked_at(sent["id"]))


async def test_an_invite_code_works_only_once(setup: Setup) -> None:
    alice = await setup.node("alice")
    bob = await setup.node("bob")
    carol = await setup.node("carol")
    invite = await alice.pairing.invite()
    await bob.pairing.join(invite["code"])
    with pytest.raises(PairingError, match="unknown, expired or already used"):
        await carol.pairing.join(invite["code"])


async def test_an_expired_invite_code_is_refused(setup: Setup, clock: Clock) -> None:
    alice = await setup.node("alice")
    bob = await setup.node("bob")
    invite = await alice.pairing.invite()
    clock.ms += 10 * MINUTE_MS + 1
    with pytest.raises(PairingError, match="unknown, expired or already used"):
        await bob.pairing.join(invite["code"])


async def test_pair_without_a_relay_says_how_to_set_one(tmp_path: object) -> None:
    home = os.path.join(str(tmp_path), "home")
    init_identity(home, "alice")
    transport = NetworkTransport(host="127.0.0.1", discovery=False)
    daemon = Daemon(home, transport=transport)
    await daemon.start()
    pairing = Pairing(daemon, transport)
    try:
        with pytest.raises(PairingError, match="squawk relay set"):
            await pairing.invite()
    finally:
        await daemon.stop()


class RawClient:
    """A relay client speaking the protocol by hand, for the attacker."""

    def __init__(self, ws: ClientConnection) -> None:
        self.ws = ws

    @classmethod
    async def login(cls, url: str, identity: Identity) -> "RawClient":
        ws = await connect(url)
        hello = jsontext.parse(str(await ws.recv()))
        sig = ed25519_sign(
            auth_message(hello["challenge"], identity.id, hello["key"]), identity.secret_key
        )
        await ws.send(
            jsontext.stringify({"t": "auth", "v": 1, "key": identity.id, "sig": to_base64url(sig)})
        )
        ok = jsontext.parse(str(await ws.recv()))
        assert ok["t"] == "ok"
        return cls(ws)

    async def send(self, frame: dict[str, Any]) -> None:
        await self.ws.send(jsontext.stringify(frame))

    async def recv(self) -> dict[str, Any]:
        frame: dict[str, Any] = jsontext.parse(str(await asyncio.wait_for(self.ws.recv(), 5)))
        return frame


async def test_an_attacker_in_the_middle_cannot_produce_matching_codes(setup: Setup) -> None:
    # Mallory sits between Alice and Bob: one of Mallory's keys joins Alice's
    # invite, another invites Bob, and every pairing frame is passed across
    # unchanged. Each side sees one of Mallory's keys, not the other person's.
    alice = await setup.node("alice")
    bob = await setup.node("bob")
    m1 = await RawClient.login(
        setup.url, identity_from_secret_key("m1", ed25519_random_secret_key())
    )
    m2 = await RawClient.login(
        setup.url, identity_from_secret_key("m2", ed25519_random_secret_key())
    )

    alice_invite = await alice.pairing.invite()
    alice_offer = asyncio.ensure_future(alice.pairing.invite_joined())
    await m1.send({"t": "invite-join", "req": "j", "code": alice_invite["code"]})
    room_with_alice = (await m1.recv())["room"]
    await m2.send({"t": "invite-create", "req": "c"})
    code_for_bob = (await m2.recv())["code"]
    bob_offer = asyncio.ensure_future(bob.pairing.join(code_for_bob))
    room_with_bob = (await m2.recv())["room"]

    async def pass_across(src: RawClient, dst: RawClient, room: str) -> None:
        while True:
            frame = await src.recv()
            if frame.get("t") == "pair":
                await dst.send({"t": "pair", "room": room, "frame": frame["frame"]})

    forwarding = [
        asyncio.ensure_future(pass_across(m2, m1, room_with_alice)),
        asyncio.ensure_future(pass_across(m1, m2, room_with_bob)),
    ]
    try:
        results = await asyncio.gather(alice_offer, bob_offer, return_exceptions=True)
    finally:
        for task in forwarding:
            task.cancel()
    a_result, b_result = results
    # Either a side noticed (Bob's commitment does not match the key Alice was
    # told about) or the codes differ; never two matching codes.
    if isinstance(a_result, dict) and isinstance(b_result, dict):
        assert a_result["code"] != b_result["code"]
    else:
        assert isinstance(a_result, PairingError) or isinstance(b_result, PairingError)
    assert alice.daemon.store.get_contact(bob.id) is None
    assert bob.daemon.store.get_contact(alice.id) is None


class CliRun:
    """Runs the CLI in-process against a home, answering questions with "y"."""

    def __init__(self, home: str, *args: str) -> None:
        self.out: list[str] = []
        self.err: list[str] = []

        async def ask(prompt: str) -> str:
            self.out.append(prompt)
            return "y"

        io = CliIo(
            stdout=self.out.append, stderr=self.err.append, env={"SQUAWK_HOME": home}, ask=ask
        )
        self.task = asyncio.ensure_future(run(list(args), io))

    @property
    def text(self) -> str:
        return "".join(self.out)


async def test_the_invite_and_pair_code_commands(setup: Setup) -> None:
    alice = await setup.node("alice")
    bob = await setup.node("bob")
    inviting = CliRun(alice.daemon.home, "invite")
    found = await wait_for(lambda: re.search(r"Invite code: (\S+)", inviting.text))
    joining = CliRun(bob.daemon.home, "pair", "--code", found.group(1))
    assert (await inviting.task, await joining.task) == (0, 0), (inviting.err, joining.err)
    assert "on a phone or\nvideo call" in inviting.text
    assert "Do not\nsend it as a message" in joining.text
    assert 'Paired with "alice"' in joining.text
    assert 'Paired with "bob"' in inviting.text
