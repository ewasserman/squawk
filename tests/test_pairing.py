"""Tests for squawk.pairing."""

import asyncio
import re
import shutil
import tempfile
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from websockets.asyncio.client import connect

from squawk.config import socket_path
from squawk.crypto import ed25519_random_secret_key, random_bytes
from squawk.daemon import Daemon
from squawk.encoding import to_base64url
from squawk.identity import identity_from_secret_key, init_identity
from squawk.network import NetworkTransport, PeerLink
from squawk.pairing import Pairing, PairingError, pair_code, pair_commitment
from squawk.rpc import RpcClient, RpcError


async def wait_for[T](check: Callable[[], T | None], timeout: float = 5.0) -> T:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        value = check()
        if value:
            return value
        if loop.time() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.025)


@dataclass
class Node:
    home: str
    daemon: Daemon
    transport: NetworkTransport
    pairing: Pairing
    rpc: RpcClient
    address: str

    @property
    def id(self) -> str:
        return self.daemon.identity.id


class Nodes:
    def __init__(self) -> None:
        self.homes: list[str] = []
        self.nodes: list[Node] = []

    async def start(self, name: str, timeout_ms: int = 10_000) -> Node:
        """Starts a service on loopback with no mDNS and no address book, so
        only saved addresses work."""
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        transport = NetworkTransport(
            host="127.0.0.1",
            discovery=False,
            retry_interval_ms=50,
            handshake_timeout_ms=2000,
        )
        daemon = Daemon(home, transport=transport)
        await daemon.start()
        pairing = Pairing(daemon, transport, timeout_ms=timeout_ms)
        pairing.start()
        rpc = await RpcClient.connect(socket_path(home))
        node = Node(home, daemon, transport, pairing, rpc, f"127.0.0.1:{transport.port}")
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
            await node.rpc.close()
            await node.daemon.stop()
        for home in n.homes:
            shutil.rmtree(home, ignore_errors=True)


def new_key() -> str:
    return identity_from_secret_key("x", ed25519_random_secret_key()).id


def test_pair_code_is_six_digits_and_the_same_for_the_same_inputs() -> None:
    k1, k2 = new_key(), new_key()
    n1, n2 = random_bytes(32), random_bytes(32)
    code = pair_code(k1, k2, n1, n2)
    assert re.fullmatch(r"\d{6}", code)
    assert pair_code(k1, k2, n1, n2) == code


def test_pair_code_changes_when_a_key_is_replaced() -> None:
    k1, k2, k3 = new_key(), new_key(), new_key()
    n1, n2 = random_bytes(32), random_bytes(32)
    assert pair_code(k1, k3, n1, n2) != pair_code(k1, k2, n1, n2)
    assert pair_code(k3, k2, n1, n2) != pair_code(k1, k2, n1, n2)


async def test_pairs_when_both_confirm_matching_codes_and_messages_then_flow_both_ways(
    nodes: Nodes,
) -> None:
    alice = await nodes.start("alice")
    bob = await nodes.start("bob")

    bob_waits = asyncio.ensure_future(bob.rpc.call("pair_accept"))
    await asyncio.sleep(0.02)
    alice_offer = await alice.rpc.call("pair_start", {"peer": bob.address})
    bob_offer = await bob_waits

    assert re.fullmatch(r"\d{6}", alice_offer["code"])
    assert alice_offer["code"] == bob_offer["code"]
    assert alice_offer["peer_name"] == "bob"
    assert bob_offer["peer_name"] == "alice"
    assert alice_offer["peer_key"] == bob.id
    assert bob_offer["peer_key"] == alice.id

    a, b = await asyncio.gather(
        alice.rpc.call("pair_confirm", {"pairing_id": alice_offer["pairing_id"], "match": True}),
        bob.rpc.call("pair_confirm", {"pairing_id": bob_offer["pairing_id"], "match": True}),
    )
    assert a["status"] == "paired"
    assert b["status"] == "paired"
    assert a["contact"]["key_id"] == bob.id
    contact = alice.daemon.store.get_contact(bob.id)
    assert contact is not None and contact.trust == "paired"
    contact = bob.daemon.store.get_contact(alice.id)
    assert contact is not None and contact.name == "alice"

    # Each side saved the other's address during pairing.
    to_bob = await alice.daemon.send({"to": "bob", "body": "hi bob"})
    await wait_for(lambda: bob.daemon.store.get_message(to_bob["id"]))
    to_alice = await bob.daemon.send({"to": "alice", "body": "hi alice"})
    await wait_for(lambda: alice.daemon.store.get_message(to_alice["id"]))


async def test_saves_nothing_when_one_person_says_the_codes_do_not_match(nodes: Nodes) -> None:
    alice = await nodes.start("alice")
    bob = await nodes.start("bob")

    bob_waits = asyncio.ensure_future(bob.pairing.accept())
    await asyncio.sleep(0.02)
    alice_offer = await alice.pairing.initiate(bob.address)
    bob_offer = await bob_waits

    alice_done = asyncio.ensure_future(alice.pairing.confirm(alice_offer["pairing_id"], True))
    with pytest.raises(PairingError, match="did not match"):
        await bob.pairing.confirm(bob_offer["pairing_id"], False)
    with pytest.raises(PairingError, match="cancelled"):
        await alice_done
    assert alice.daemon.store.get_contact(bob.id) is None
    assert bob.daemon.store.get_contact(alice.id) is None


async def test_does_not_save_the_contact_if_only_one_side_confirms(nodes: Nodes) -> None:
    alice = await nodes.start("alice", 500)
    bob = await nodes.start("bob", 500)

    bob_waits = asyncio.ensure_future(bob.pairing.accept())
    await asyncio.sleep(0.02)
    alice_offer = await alice.pairing.initiate(bob.address)
    await bob_waits

    with pytest.raises(PairingError, match=r"timed out|disconnected"):
        await alice.pairing.confirm(alice_offer["pairing_id"], True)
    assert alice.daemon.store.get_contact(bob.id) is None
    assert bob.daemon.store.get_contact(alice.id) is None


async def test_leaves_a_paired_contacts_message_connection_alone_while_waiting_to_pair(
    nodes: Nodes,
) -> None:
    alice = await nodes.start("alice")
    bob = await nodes.start("bob")
    for a, b in ((alice, bob), (bob, alice)):
        a.daemon.store.upsert_contact(b.id, b.daemon.identity.name, trust="paired")
        a.daemon.store.set_setting(f"address:{b.id}", b.address)
    waiting = asyncio.ensure_future(bob.pairing.accept())
    sent = await alice.daemon.send({"to": "bob", "body": "just a message"})
    await wait_for(lambda: bob.daemon.store.get_message(sent["id"]))
    # Alice's service restarts, closing its connection to Bob.
    await alice.daemon.stop()
    await asyncio.sleep(0.1)
    assert not waiting.done()
    bob.pairing.stop()
    with pytest.raises(PairingError):
        await waiting


async def test_refuses_an_unpaired_key_when_nobody_is_waiting_to_pair(nodes: Nodes) -> None:
    alice = await nodes.start("alice")
    bob = await nodes.start("bob")
    with pytest.raises(PairingError) as refused:
        await alice.pairing.initiate(bob.address)
    assert re.search(
        r"is not waiting to pair\. Ask them to run `squawk pair --accept`", str(refused.value)
    )


async def test_refuses_an_initiator_whose_reveal_does_not_match_its_commitment(
    nodes: Nodes,
) -> None:
    bob = await nodes.start("bob")
    bob_waits = asyncio.ensure_future(bob.pairing.accept())
    await asyncio.sleep(0.02)

    # Mallory commits to one nonce and then reveals a different one.
    mallory = identity_from_secret_key("mallory", ed25519_random_secret_key())
    ws = await connect(f"ws://{bob.address}/", proxy=None)
    link = PeerLink(ws, mallory, lambda _k, _l: "pairing", outgoing=True, timeout_ms=2000)
    await link.ready
    frames: list[dict[str, Any]] = []

    def on_frame(frame: dict[str, Any]) -> None:
        frames.append(frame)
        if frame["t"] == "pair-nonce":
            link.send({"t": "pair-reveal", "nonce": to_base64url(random_bytes(32))})

    link.on_frame(on_frame)
    link.send(
        {
            "t": "pair-commit",
            "commit": to_base64url(pair_commitment(mallory.id, random_bytes(32))),
            "name": "alice",
            "port": 1,
        }
    )

    with pytest.raises(PairingError, match="commitment did not match"):
        await bob_waits
    await wait_for(lambda: any(f["t"] == "pair-abort" for f in frames))
    assert bob.daemon.store.get_contact(mallory.id) is None
    link.terminate()
    await link.wait_closed()


async def test_refuses_to_pair_with_a_discovered_name_that_is_not_on_the_network(
    nodes: Nodes,
) -> None:
    alice = await nodes.start("alice")
    with pytest.raises(RpcError, match='no squawk service called "nobody"'):
        await alice.rpc.call("pair_start", {"peer": "nobody"})


async def test_block_and_unblock_change_trust_over_the_socket(nodes: Nodes) -> None:
    alice = await nodes.start("alice")
    carol = new_key()
    alice.daemon.store.upsert_contact(carol, "carol", trust="paired")
    assert await alice.rpc.call("block", {"contact": "carol"}) == {
        "name": "carol",
        "key_id": carol,
        "trust": "blocked",
    }
    contact = alice.daemon.store.get_contact(carol)
    assert contact is not None and contact.trust == "blocked"
    assert (await alice.rpc.call("unblock", {"contact": "carol"}))["trust"] == "paired"
