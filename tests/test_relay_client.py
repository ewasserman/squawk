"""Two services and a relay on one machine, with mDNS off: messages go
through the relay when there is no direct route, and directly when there is."""

import asyncio
import os
import shutil
import sqlite3
import tempfile
from collections.abc import AsyncIterator, Callable

import pytest

from squawk.daemon import SHARE_SESSIONS_KEY, Daemon
from squawk.identity import init_identity
from squawk.network import Address, LinkError, NetworkTransport
from squawk.relay import RelayServer
from squawk.relay.storage import DB_FILE
from squawk.relay_client import (
    RELAY_ALLOW_PLAIN_KEY,
    RELAY_URL_KEY,
    RelayClient,
    relay_client_from_settings,
)
from squawk.store import OutboundItem, StoredMessage


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


class Setup:
    def __init__(self, relay: RelayServer) -> None:
        self.relay = relay
        self.url = f"ws://127.0.0.1:{relay.port}"
        self.homes: list[str] = []
        self.running: list[Daemon] = []
        self.book: dict[str, Address] = {}
        """Direct addresses; empty means no direct route between services."""

    def make_home(self, name: str) -> str:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        return home

    async def start(self, home: str, *, lan: bool = False) -> Daemon:
        relay = RelayClient(
            self.url, allow_plain=True, backoff_min_ms=50, allow_check_interval_ms=50
        )
        transport = NetworkTransport(
            host="127.0.0.1",
            discovery=False,
            resolve=self.book.get,
            retry_interval_ms=50,
            ack_timeout_ms=2000,
            handshake_timeout_ms=2000,
            relay=relay,
        )
        daemon = Daemon(home, transport=transport)
        await daemon.start()
        self.running.append(daemon)
        if lan:
            self.book[daemon.identity.id] = Address("127.0.0.1", transport.port)
        await wait_for(lambda: relay.connected)
        return daemon

    async def stop(self, daemon: Daemon) -> None:
        await daemon.stop()
        self.running.remove(daemon)

    def waiting_at_relay(self) -> int:
        with sqlite3.connect(os.path.join(self.relay._data_dir, DB_FILE)) as db:
            row = db.execute("SELECT COUNT(*) FROM messages").fetchone()
        return int(row[0])

    def allow_list_of(self, key: str) -> list[str]:
        with sqlite3.connect(os.path.join(self.relay._data_dir, DB_FILE)) as db:
            rows = db.execute("SELECT sender FROM allowed WHERE owner = ?", (key,)).fetchall()
        return sorted(row[0] for row in rows)


def pair(a: Daemon, b: Daemon) -> None:
    a.store.upsert_contact(b.identity.id, b.identity.name, trust="paired")
    b.store.upsert_contact(a.identity.id, a.identity.name, trust="paired")


def in_state(daemon: Daemon, message_id: str, state: str) -> StoredMessage | None:
    message = daemon.store.get_message(message_id)
    return message if message is not None and message.state == state else None


def after_an_attempt(daemon: Daemon, message_id: str) -> OutboundItem | None:
    item = daemon.store.get_outbound(message_id)
    return item if item is not None and item.attempts > 0 else None


def transport_of(daemon: Daemon) -> NetworkTransport:
    assert isinstance(daemon.transport, NetworkTransport)
    return daemon.transport


@pytest.fixture
async def setup(tmp_path: object) -> AsyncIterator[Setup]:
    relay = RelayServer(os.path.join(str(tmp_path), "relay"), port=0)
    await relay.start()
    s = Setup(relay)
    try:
        yield s
    finally:
        await asyncio.gather(*(d.stop() for d in s.running), return_exceptions=True)
        await relay.stop()
        for home in s.homes:
            shutil.rmtree(home, ignore_errors=True)


async def test_messages_go_both_ways_through_the_relay(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    pair(alice, bob)
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    await wait_for(lambda: setup.allow_list_of(alice.identity.id) == [bob.identity.id])

    sent = await alice.send({"to": "bob", "body": "hello through the relay"})
    received = await wait_for(lambda: bob.store.get_message(sent["id"]))
    assert received.body == "hello through the relay"
    # Bob's signed receipt marks it delivered at Alice's.
    await wait_for(lambda: alice.store.acked_at(sent["id"]))
    assert alice.store.get_outbound(sent["id"]) is None

    reply = await bob.send({"to": "alice", "body": "hello back", "in_reply_to": sent["id"]})
    back = await wait_for(lambda: alice.store.get_message(reply["id"]))
    assert back.body == "hello back"
    await wait_for(lambda: bob.store.acked_at(reply["id"]))
    # Messages and receipts were all deleted at the relay once handled.
    await wait_for(lambda: setup.waiting_at_relay() == 0)


async def test_a_message_waits_at_the_relay_until_the_recipient_comes_back(
    setup: Setup,
) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob_home = setup.make_home("bob")
    bob = await setup.start(bob_home)
    pair(alice, bob)
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    await setup.stop(bob)

    sent = await alice.send({"to": "bob", "body": "are you there?"})
    stored = await wait_for(lambda: in_state(alice, sent["id"], "sent"))
    assert stored.state == "sent"
    assert alice.store.count_relayed() == 1
    assert setup.waiting_at_relay() == 1

    bob = await setup.start(bob_home)
    received = await wait_for(lambda: bob.store.get_message(sent["id"]))
    assert received.body == "are you there?"
    await wait_for(lambda: alice.store.acked_at(sent["id"]))
    assert alice.store.count_relayed() == 0


async def test_on_the_local_network_messages_still_go_directly(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"), lan=True)
    bob = await setup.start(setup.make_home("bob"), lan=True)
    pair(alice, bob)
    sent = await alice.send({"to": "bob", "body": "direct"})
    await wait_for(lambda: alice.store.acked_at(sent["id"]))
    message = alice.store.get_message(sent["id"])
    assert message is not None and message.state == "acked"
    assert setup.waiting_at_relay() == 0
    assert bob.store.get_message(sent["id"]) is not None


async def test_a_blocked_contact_is_taken_off_the_allow_list(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    pair(alice, bob)
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    bob.store.update_contact(alice.identity.id, trust="blocked")
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [])

    sent = await alice.send({"to": "bob", "body": "let me in"})
    item = await wait_for(lambda: after_an_attempt(alice, sent["id"]))
    assert item.last_error is not None and "not-allowed" in item.last_error
    assert bob.store.get_message(sent["id"]) is None
    assert setup.waiting_at_relay() == 0


async def test_a_contact_whose_saved_relay_differs_is_still_tried_through_ours(
    setup: Setup,
) -> None:
    # The saved URL can be out of date (the contact moved relays, or the
    # same relay has a new name); the relay itself says whether they are there.
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    pair(alice, bob)
    alice.store.update_contact(bob.identity.id, relay_url="wss://elsewhere.example")
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    sent = await alice.send({"to": "bob", "body": "hi"})
    await wait_for(lambda: alice.store.acked_at(sent["id"]))


async def test_switching_relays_queues_held_messages_again(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    pair(alice, bob)
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    await setup.stop(bob)
    sent = await alice.send({"to": "bob", "body": "held"})
    await wait_for(lambda: in_state(alice, sent["id"], "sent"))
    await transport_of(alice).use_relay(None)
    message = alice.store.get_message(sent["id"])
    assert message is not None and message.state == "queued"
    assert alice.store.count_relayed() == 0


async def test_connected_only_once_the_allow_list_is_sent(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    relay = transport_of(alice).relay
    assert relay is not None and relay.connected
    assert relay._sent_allow == []


async def test_a_refusal_from_the_recipient_comes_back_as_a_failure(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    carol = await setup.start(setup.make_home("carol"))
    pair(alice, bob)
    pair(carol, bob)
    await wait_for(lambda: len(setup.allow_list_of(bob.identity.id)) == 2)
    await wait_for(lambda: setup.allow_list_of(carol.identity.id) == [bob.identity.id])
    # Carol's message to Bob starts a thread; Alice then tries to add to it.
    first = await carol.send({"to": "bob", "body": "carol's thread"})
    await wait_for(lambda: bob.store.get_message(first["id"]))
    sent = await alice.send({"to": "bob", "body": "sneaking in", "thread_id": first["id"]})
    failed = await wait_for(lambda: in_state(alice, sent["id"], "failed"))
    assert failed.error == "refused: thread id already in use"
    assert transport_of(alice).relay is not None


def test_the_relay_client_comes_from_the_settings() -> None:
    settings: dict[str, str] = {}
    assert relay_client_from_settings(settings.get) is None
    settings[RELAY_URL_KEY] = "ws://localhost:8765"
    # Plain ws:// without the opt-in is not used.
    assert relay_client_from_settings(settings.get) is None
    settings[RELAY_ALLOW_PLAIN_KEY] = "on"
    client = relay_client_from_settings(settings.get)
    assert client is not None and client.url == "ws://localhost:8765"


async def test_lists_a_contacts_sessions_through_the_relay(
    setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    pair(alice, bob)
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    await wait_for(lambda: setup.allow_list_of(alice.identity.id) == [bob.identity.id])
    monkeypatch.setattr(
        bob,
        "sessions_for_peer",
        lambda: {"shared": True, "sessions": [{"label": "squawk@main", "branch": "main"}]},
    )
    result = await transport_of(alice).request_sessions(bob.identity.id)
    assert result == {"shared": True, "sessions": [{"label": "squawk@main", "branch": "main"}]}

    bob.store.set_setting(SHARE_SESSIONS_KEY, "off")
    monkeypatch.undo()
    result = await transport_of(alice).request_sessions(bob.identity.id)
    assert result == {"shared": False, "sessions": []}


async def test_says_when_a_contact_is_offline(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    pair(alice, bob)
    await wait_for(lambda: setup.allow_list_of(bob.identity.id) == [alice.identity.id])
    await setup.stop(bob)
    with pytest.raises(LinkError, match="bob is offline"):
        await transport_of(alice).request_sessions(bob.identity.id)


async def test_says_when_a_contact_has_not_allowed_us_at_the_relay(setup: Setup) -> None:
    alice = await setup.start(setup.make_home("alice"))
    bob = await setup.start(setup.make_home("bob"))
    alice.store.upsert_contact(bob.identity.id, "bob", trust="paired")
    with pytest.raises(LinkError, match="does not list you as a contact"):
        await transport_of(alice).request_sessions(bob.identity.id)
