"""Tests for squawk.network."""

import asyncio
import dataclasses
import shutil
import tempfile
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from websockets.asyncio.client import connect

from squawk.crypto import ed25519_random_secret_key
from squawk.daemon import Daemon
from squawk.discovery import Advertisement, Discovery, RawService
from squawk.envelope import create_envelope
from squawk.identity import Identity, fingerprint, identity_from_secret_key, init_identity
from squawk.network import Address, LinkError, NetworkTransport, PeerLink, dialable


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


@dataclasses.dataclass
class Node:
    """One service with its own home directory, on loopback, without mDNS."""

    home: str
    daemon: Daemon
    transport: NetworkTransport

    @property
    def port(self) -> int:
        return self.transport.port

    @property
    def id(self) -> str:
        return self.daemon.identity.id


class Net:
    def __init__(self) -> None:
        self.homes: list[str] = []
        self.running: list[Daemon] = []
        self.book: dict[str, Address] = {}
        """key id -> address, shared by all nodes in a test (stands in for mDNS)."""

    def make_home(self, name: str) -> str:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        return home

    async def start_node(self, home: str, port: int = 0) -> Node:
        transport = NetworkTransport(
            port=port,
            host="127.0.0.1",
            discovery=False,
            resolve=self.book.get,
            retry_interval_ms=50,
            ack_timeout_ms=2000,
            handshake_timeout_ms=2000,
        )
        daemon = Daemon(home, transport=transport)
        await daemon.start()
        self.running.append(daemon)
        self.book[daemon.identity.id] = Address("127.0.0.1", transport.port)
        return Node(home, daemon, transport)

    async def node(self, name: str) -> Node:
        return await self.start_node(self.make_home(name))

    async def stop_node(self, node: Node) -> None:
        await node.daemon.stop()
        self.running.remove(node.daemon)


def pair(a: Node, b: Node) -> None:
    a.daemon.store.upsert_contact(b.id, b.daemon.identity.name, trust="paired")
    b.daemon.store.upsert_contact(a.id, a.daemon.identity.name, trust="paired")


def attempts(node: Node, message_id: str) -> int:
    item = node.daemon.store.get_outbound(message_id)
    return 0 if item is None else item.attempts


@pytest.fixture
async def net() -> AsyncIterator[Net]:
    n = Net()
    try:
        yield n
    finally:
        await asyncio.gather(*(d.stop() for d in n.running), return_exceptions=True)
        for home in n.homes:
            shutil.rmtree(home, ignore_errors=True)


async def test_delivers_a_sealed_message_and_records_the_acknowledgement(net: Net) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    pair(alice, bob)

    sent = await alice.daemon.send({"to": "bob", "body": "hello bob"})

    received = await wait_for(lambda: bob.daemon.store.get_message(sent["id"]))
    assert received.body == "hello bob"
    assert received.direction == "in"
    await wait_for(lambda: alice.daemon.store.acked_at(sent["id"]))
    assert alice.daemon.store.get_outbound(sent["id"]) is None


async def test_delivers_a_message_that_waited_longer_than_the_freshness_window(
    net: Net,
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    pair(alice, bob)
    # Written an hour ago while Bob was away; still queued.
    old = create_envelope(
        from_=alice.id,
        to=bob.id,
        body="written an hour ago",
        created_at=int(time.time() * 1000) - 60 * 60_000,
    )
    alice.daemon.store.queue_outgoing(old)
    alice.transport.kick()

    received = await wait_for(lambda: bob.daemon.store.get_message(old["id"]))
    assert received.body == "written an hour ago"
    assert received.created_at == old["created_at"]
    await wait_for(lambda: alice.daemon.store.acked_at(old["id"]))


async def test_refuses_an_incoming_id_that_belongs_to_a_message_from_someone_else(
    net: Net,
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    carol = await net.node("carol")
    pair(alice, bob)
    pair(carol, bob)

    from_alice = await alice.daemon.send({"to": "bob", "body": "from alice"})
    await wait_for(lambda: alice.daemon.store.acked_at(from_alice["id"]))
    # Carol reuses the id of Alice's message.
    reused: Any = create_envelope(from_=carol.id, to=bob.id, body="from carol")
    clash: Any = {**reused, "id": from_alice["id"], "thread_id": from_alice["id"]}
    carol.daemon.store.queue_outgoing(clash)
    carol.transport.kick()

    # A refusal that cannot clear up: Carol's message fails at once, with the reason.
    def refused() -> bool:
        mine = carol.daemon.store.get_message(from_alice["id"])
        return mine is not None and mine.state == "failed"

    await wait_for(refused)
    mine = carol.daemon.store.get_message(from_alice["id"])
    assert mine is not None and mine.error == "refused: message id already in use"
    assert carol.daemon.store.get_outbound(from_alice["id"]) is None
    stored = bob.daemon.store.get_message(from_alice["id"])
    assert stored is not None and stored.body == "from alice"
    assert carol.daemon.store.acked_at(from_alice["id"]) is None


async def test_marks_a_message_failed_when_the_receiver_refuses_its_thread_for_good(
    net: Net,
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    carol = await net.node("carol")
    pair(alice, bob)
    pair(carol, bob)

    from_alice = await alice.daemon.send({"to": "bob", "body": "from alice"})
    await wait_for(lambda: alice.daemon.store.acked_at(from_alice["id"]))
    # Carol writes into the thread Bob has with Alice.
    clash = create_envelope(
        from_=carol.id, to=bob.id, body="from carol", thread_id=from_alice["thread_id"]
    )
    carol.daemon.store.queue_outgoing(clash)
    carol.transport.kick()

    def failed() -> bool:
        mine = carol.daemon.store.get_message(clash["id"])
        return mine is not None and mine.state == "failed"

    await wait_for(failed)
    # It is out of the queue, so it is not retried, and the reason is kept.
    assert carol.daemon.store.get_outbound(clash["id"]) is None
    assert carol.daemon.status()["queued_outbound"] == 0
    stored = carol.daemon.store.get_message(clash["id"])
    assert stored is not None
    info = carol.daemon._message_info(stored)
    assert info["state"] == "failed"
    assert info["error"] == "refused: thread id already in use"
    assert bob.daemon.store.get_message(clash["id"]) is None


async def test_keeps_retrying_a_refusal_that_can_clear_up(
    net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    pair(alice, bob)
    # Alice's clock is an hour ahead of Bob's: Bob refuses the message as
    # "stale", which clears up once the clock is set right.
    ahead = int(time.time() * 1000) + 60 * 60_000
    monkeypatch.setattr("squawk.network.now_ms", lambda: ahead)
    sent = await alice.daemon.send({"to": "bob", "body": "from the future"})
    await wait_for(lambda: attempts(alice, sent["id"]) >= 1)
    item = alice.daemon.store.get_outbound(sent["id"])
    assert item is not None and item.last_error == "refused: stale"
    mine = alice.daemon.store.get_message(sent["id"])
    assert mine is not None and mine.state == "queued" and mine.error is None


async def test_falls_back_to_the_saved_address_when_the_advertised_one_is_someone_else(
    net: Net,
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    mallory = await net.node("mallory")
    pair(alice, bob)
    alice.daemon.store.set_setting(f"address:{bob.id}", f"127.0.0.1:{bob.port}")
    # Mallory advertises Bob's key with her own address.
    net.book[bob.id] = Address("127.0.0.1", mallory.port)
    sent = await alice.daemon.send({"to": "bob", "body": "for bob"})
    await wait_for(lambda: bob.daemon.store.get_message(sent["id"]))


async def test_does_not_hold_up_other_recipients_while_one_is_slow_to_answer(
    net: Net,
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    carol = await net.node("carol")
    pair(alice, bob)
    pair(alice, carol)
    # Carol's address accepts connections but never answers.
    held: list[asyncio.StreamWriter] = []

    async def silent_handler(_r: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)

    silent = await asyncio.start_server(silent_handler, "127.0.0.1", 0)
    silent_port = silent.sockets[0].getsockname()[1]
    net.book[carol.id] = Address("127.0.0.1", silent_port)
    try:
        await alice.daemon.send({"to": "carol", "body": "for carol"})
        await asyncio.sleep(0.1)
        start = time.monotonic()
        sent = await alice.daemon.send({"to": "bob", "body": "for bob"})
        await wait_for(lambda: bob.daemon.store.get_message(sent["id"]))
        # Well under the 2 s handshake timeout Carol's dial is stuck in.
        assert time.monotonic() - start < 1.5
    finally:
        for writer in held:
            writer.close()
        silent.close()


async def test_a_recipient_with_many_due_messages_does_not_hold_up_the_others(
    net: Net,
) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    carol = await net.node("carol")
    pair(alice, bob)
    pair(alice, carol)
    # Carol's address accepts connections but never answers, and more than
    # 100 messages for her are due.
    held: list[asyncio.StreamWriter] = []

    async def silent_handler(_r: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)

    silent = await asyncio.start_server(silent_handler, "127.0.0.1", 0)
    net.book[carol.id] = Address("127.0.0.1", silent.sockets[0].getsockname()[1])
    try:
        for n in range(150):
            alice.daemon.store.queue_outgoing(
                create_envelope(from_=alice.id, to=carol.id, body=f"for carol {n}")
            )
        alice.transport.kick()
        await asyncio.sleep(0.1)
        start = time.monotonic()
        sent = await alice.daemon.send({"to": "bob", "body": "for bob"})
        await wait_for(lambda: bob.daemon.store.get_message(sent["id"]))
        # Well under the 2 s handshake timeout Carol's dial is stuck in.
        assert time.monotonic() - start < 1.5
    finally:
        for writer in held:
            writer.close()
        silent.close()


async def test_retries_after_the_receiver_restarts(net: Net) -> None:
    alice = await net.node("alice")
    bob_home = net.make_home("bob")
    bob = await net.start_node(bob_home)
    pair(alice, bob)
    bob_port = bob.port
    await net.stop_node(bob)

    sent = await alice.daemon.send({"to": "bob", "body": "are you there?"})
    await wait_for(lambda: attempts(alice, sent["id"]) >= 1)
    item = alice.daemon.store.get_outbound(sent["id"])
    assert item is not None and item.last_error

    bob = await net.start_node(bob_home, bob_port)
    received = await wait_for(lambda: bob.daemon.store.get_message(sent["id"]), 10)
    assert received.body == "are you there?"
    await wait_for(lambda: alice.daemon.store.acked_at(sent["id"]))


async def test_refuses_a_connection_from_a_key_that_is_not_a_paired_contact(net: Net) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    # Only alice thinks they are paired; bob has never heard of alice.
    alice.daemon.store.upsert_contact(bob.id, "bob", trust="paired")

    sent = await alice.daemon.send({"to": "bob", "body": "let me in"})
    await wait_for(lambda: attempts(alice, sent["id"]) >= 1)
    assert bob.daemon.store.get_message(sent["id"]) is None
    assert alice.daemon.store.acked_at(sent["id"]) is None
    item = alice.daemon.store.get_outbound(sent["id"])
    assert item is not None
    assert item.last_error == "the other side refused the connection: not a paired contact"


async def test_refuses_a_blocked_contact(net: Net) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    pair(alice, bob)
    bob.daemon.store.update_contact(alice.id, trust="blocked")

    sent = await alice.daemon.send({"to": "bob", "body": "blocked?"})
    await wait_for(lambda: attempts(alice, sent["id"]) >= 1)
    assert bob.daemon.store.get_message(sent["id"]) is None


async def test_drops_a_stranger_who_signs_the_handshake_with_a_key_it_does_not_hold(
    net: Net,
) -> None:
    bob = await net.node("bob")
    alice = identity_from_secret_key("alice", ed25519_random_secret_key())
    bob.daemon.store.upsert_contact(alice.id, "alice", trust="paired")
    # Mallory claims alice's key but signs with her own.
    mallory = identity_from_secret_key("mallory", ed25519_random_secret_key())
    impostor = dataclasses.replace(mallory, id=alice.id)
    ws = await connect(f"ws://127.0.0.1:{bob.port}/", proxy=None)
    link = PeerLink(ws, impostor, lambda _k, _l: "paired", outgoing=True, timeout_ms=2000)
    with pytest.raises(LinkError):
        await link.ready
    await asyncio.wait_for(link.wait_closed(), 5)
    assert ws.close_code in (4001, 1005, 1006)


async def test_does_not_deliver_to_a_host_that_answers_with_a_different_key(net: Net) -> None:
    alice = await net.node("alice")
    bob = await net.node("bob")
    carol = await net.node("carol")
    pair(alice, bob)
    pair(alice, carol)
    # The address book wrongly points bob's key at carol's port.
    net.book[bob.id] = Address("127.0.0.1", carol.port)

    sent = await alice.daemon.send({"to": "bob", "body": "for bob only"})
    await wait_for(lambda: attempts(alice, sent["id"]) >= 1)
    assert carol.daemon.store.get_message(sent["id"]) is None
    item = alice.daemon.store.get_outbound(sent["id"])
    assert item is not None
    assert "different key" in (item.last_error or "") or "closed" in (item.last_error or "")


async def test_answers_a_plain_http_request_with_426(net: Net) -> None:
    bob = await net.node("bob")
    reader, writer = await asyncio.open_connection("127.0.0.1", bob.port)
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    status = await reader.readline()
    writer.close()
    assert b" 426 " in status


# Peers


class FixedBackend:
    def __init__(self, services: list[RawService]) -> None:
        self.services = services

    async def publish(self, instance_name: str, port: int, txt: dict[str, str]) -> None:
        pass

    async def browse(
        self, on_up: Callable[[RawService], None], on_down: Callable[[RawService], None]
    ) -> None:
        for service in self.services:
            on_up(service)

    def query(self) -> None:
        pass

    async def destroy(self) -> None:
        pass


async def test_reports_peers_seen_by_discovery_and_whether_each_is_paired(net: Net) -> None:
    home = net.make_home("alice")
    carol = identity_from_secret_key("carol", ed25519_random_secret_key())
    dave = identity_from_secret_key("dave", ed25519_random_secret_key())

    def advert(who: Identity, port: int) -> RawService:
        return RawService(
            name=f"{who.name} (x)",
            host=f"{who.name}.local",
            port=port,
            addresses=["192.168.1.9"],
            txt={
                "name": who.name,
                "id": who.id,
                "fp": fingerprint(who.public_key),
                "port": str(port),
            },
        )

    transport = NetworkTransport(
        host="127.0.0.1",
        discovery=Discovery(
            Advertisement(name="alice", key_id="unused", fingerprint="00", port=0),
            backend=FixedBackend([advert(carol, 4001), advert(dave, 4002)]),
        ),
    )
    daemon = Daemon(home, transport=transport)
    await daemon.start()
    net.running.append(daemon)
    daemon.store.upsert_contact(carol.id, "carol", trust="paired")

    peers = sorted(daemon.peers(), key=lambda p: p["name"])
    assert [(p["name"], p["port"], p["paired"]) for p in peers] == [
        ("carol", 4001, True),
        ("dave", 4002, False),
    ]
    assert transport.resolve(dave.id) == Address("192.168.1.9", 4002)
    assert daemon.status()["port"] == transport.port


async def test_candidates_come_from_the_resolver_then_mdns_then_the_saved_address(
    net: Net,
) -> None:
    home = net.make_home("alice")
    carol = identity_from_secret_key("carol", ed25519_random_secret_key())
    service = RawService(
        name="carol (x)",
        host="carol.local",
        port=4001,
        addresses=["fe80::1", "10.0.0.7"],
        txt={"name": "carol", "id": carol.id, "fp": "ab", "port": "4001"},
    )
    transport = NetworkTransport(
        host="127.0.0.1",
        resolve=lambda key: Address("127.0.0.1", 9) if key == carol.id else None,
        discovery=Discovery(
            Advertisement(name="alice", key_id="unused", fingerprint="00", port=0),
            backend=FixedBackend([service]),
        ),
    )
    daemon = Daemon(home, transport=transport)
    await daemon.start()
    net.running.append(daemon)
    daemon.store.set_setting(f"address:{carol.id}", "192.168.1.20:4005")
    assert transport.candidates(carol.id) == [
        Address("127.0.0.1", 9),
        Address("10.0.0.7", 4001),
        Address("carol.local", 4001),
        Address("192.168.1.20", 4005),
    ]


def test_dialable_refuses_ipv6_link_local_addresses() -> None:
    assert dialable("192.168.1.9")
    assert dialable("hal.local")
    assert dialable("2001:db8::1")
    assert not dialable("fe80::1c2b:3d4e")
    assert not dialable("FE80::1%en0")
