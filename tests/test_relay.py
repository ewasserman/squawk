"""Tests for the relay server (squawk.relay), against docs/plan/relay.md."""

import asyncio
import itertools
import os
import re
import signal
import sqlite3
import stat
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from squawk import jsontext
from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.crypto import ed25519_random_secret_key, ed25519_sign, random_bytes
from squawk.encoding import to_base64url
from squawk.identity import Identity, identity_from_secret_key
from squawk.network import auth_message
from squawk.relay import Rate, RelayLimits, RelayServer
from squawk.relay.access import (
    AccessMode,
    AllowedKeysError,
    AllowedUsersError,
    Decision,
    GitHubAccess,
    KeysAccess,
    OpenAccess,
    default_access_mode,
    is_loopback_host,
    parse_allowed_keys,
    parse_allowed_users,
)
from squawk.relay.github import (
    Denied,
    DeviceCode,
    Expired,
    GitHubError,
    GitHubUser,
    Pending,
    PollAnswer,
    Token,
)
from squawk.relay.invite_code import ALPHABET, code_hash, new_code, normalize_code
from squawk.relay.limits import DAY_MS, HOUR_MS, MINUTE_MS, RateLimiter
from squawk.relay.storage import DB_FILE, KeyOwner, RelayStore
from squawk.timefmt import iso_from_ms
from squawk.version import VERSION

Frame = dict[str, Any]

START_MS = 1_800_000_000_000


class Clock:
    """A clock the test moves by hand."""

    def __init__(self) -> None:
        self.ms = START_MS

    def __call__(self) -> int:
        return self.ms

    def advance(self, ms: int) -> None:
        self.ms += ms


def make_identity(name: str) -> Identity:
    return identity_from_secret_key(name, ed25519_random_secret_key())


def fake_sealed(sender: Identity, recipient: Identity, ct_bytes: int = 64) -> Frame:
    """Something shaped like a sealed message. The relay never opens one, so
    the contents do not need to be a real encryption."""
    return {
        "v": 1,
        "from": sender.id,
        "to": recipient.id,
        "epk": to_base64url(random_bytes(32)),
        "nonce": to_base64url(random_bytes(24)),
        "ct": to_base64url(random_bytes(ct_bytes)),
    }


_reqs = itertools.count(1)


class Client:
    """A test client speaking the relay protocol."""

    def __init__(self, ws: ClientConnection, identity: Identity, hello: Frame) -> None:
        self.ws = ws
        self.identity = identity
        self.hello = hello
        self.ok: Frame = {}

    async def send(self, frame: Frame) -> None:
        await self.ws.send(jsontext.stringify(frame))

    async def recv(self, timeout: float = 3.0) -> Frame:
        data = await asyncio.wait_for(self.ws.recv(), timeout)
        assert isinstance(data, str)
        frame = jsontext.parse(data)
        assert isinstance(frame, dict)
        return frame

    async def nothing_more(self, wait: float = 0.15) -> None:
        with pytest.raises(TimeoutError):
            await self.recv(wait)

    async def request(self, t: str, **fields: Any) -> Frame:
        req = f"r{next(_reqs)}"
        await self.send({"t": t, "req": req, **fields})
        answer = await self.recv()
        assert answer.get("req") == req, answer
        return answer

    async def allow(self, *senders: Identity) -> None:
        answer = await self.request("allow", senders=[s.id for s in senders])
        assert answer["t"] == "allowed", answer

    async def deposit(self, recipient: Identity, message_id: str = "", **extra: Any) -> Frame:
        sealed = extra.pop("sealed", None) or fake_sealed(self.identity, recipient)
        return await self.request(
            "deposit", id=message_id or f"m{next(_reqs)}", sealed=sealed, **extra
        )

    async def close(self) -> None:
        await self.ws.close()


async def close_code(ws: ClientConnection) -> tuple[int, str]:
    """Waits for the server to close the connection; returns its code and reason."""
    with pytest.raises(ConnectionClosed) as info:
        while True:
            await asyncio.wait_for(ws.recv(), 3)
    rcvd = info.value.rcvd
    assert rcvd is not None
    return rcvd.code, rcvd.reason


async def open_ws(relay: RelayServer) -> tuple[ClientConnection, Frame]:
    ws = await connect(f"ws://127.0.0.1:{relay.port}")
    data = await ws.recv()
    assert isinstance(data, str)
    hello = jsontext.parse(data)
    return ws, hello


async def login(
    relay: RelayServer,
    identity: Identity,
    *,
    relay_key: str | None = None,
    signer: Identity | None = None,
    expect_ok: bool = True,
) -> Client:
    ws, hello = await open_ws(relay)
    message = auth_message(hello["challenge"], identity.id, relay_key or hello["key"])
    sig = ed25519_sign(message, (signer or identity).secret_key)
    client = Client(ws, identity, hello)
    await client.send({"t": "auth", "v": 1, "key": identity.id, "sig": to_base64url(sig)})
    if expect_ok:
        client.ok = await client.recv()
        assert client.ok["t"] == "ok", client.ok
    return client


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def data_dir(tmp_path: Any) -> str:
    return os.path.join(str(tmp_path), "relay-data")


RelayFactory = Callable[..., Any]


@pytest.fixture
async def start_relay(data_dir: str, clock: Clock) -> AsyncIterator[RelayFactory]:
    """Starts relays on free ports with the fake clock; stops them afterwards."""
    running: list[RelayServer] = []

    async def start(
        limits: RelayLimits | None = None,
        directory: str | None = None,
        access: Any = None,
    ) -> RelayServer:
        relay = RelayServer(directory or data_dir, port=0, limits=limits, now=clock, access=access)
        await relay.start()
        running.append(relay)
        return relay

    yield start
    for relay in running:
        await relay.stop()


@pytest.fixture
async def relay(start_relay: RelayFactory) -> RelayServer:
    started: RelayServer = await start_relay()
    return started


alice = make_identity("alice")
bob = make_identity("bob")
carol = make_identity("carol")


# Proving a key.


async def test_hello_carries_the_relay_key_and_a_challenge(relay: RelayServer) -> None:
    ws, hello = await open_ws(relay)
    assert hello["t"] == "hello"
    assert hello["v"] == 1
    assert hello["key"] == relay.key_id
    assert len(hello["challenge"]) >= 43
    assert hello["access"] == "open"
    await ws.close()


class FixedAccess:
    """An access policy with a fixed answer for each key (ADMITTED otherwise)."""

    def __init__(self, mode: AccessMode, answers: dict[str, Decision]) -> None:
        self._mode: AccessMode = mode
        self.answers = answers

    @property
    def mode(self) -> AccessMode:
        return self._mode

    def decide(self, key: str) -> Decision:
        return self.answers.get(key, Decision.ADMITTED)


async def test_hello_names_the_access_mode(start_relay: RelayFactory) -> None:
    relay = await start_relay(access=FixedAccess("keys", {}))
    ws, hello = await open_ws(relay)
    assert hello["access"] == "keys"
    await ws.close()


@pytest.mark.parametrize("decision", [Decision.REFUSED, Decision.UNKNOWN])
async def test_a_key_the_access_mode_does_not_admit_is_closed_with_4003_and_gets_no_mailbox(
    start_relay: RelayFactory, decision: Decision
) -> None:
    relay = await start_relay(access=FixedAccess("keys", {alice.id: decision}))
    client = await login(relay, alice, expect_ok=False)
    assert await close_code(client.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(alice.id)
    admitted = await login(relay, bob)
    assert admitted.ok["t"] == "ok"
    assert relay.store.has_mailbox(bob.id)
    await admitted.close()


async def test_the_access_check_comes_after_the_signature_check(start_relay: RelayFactory) -> None:
    relay = await start_relay(access=FixedAccess("keys", {alice.id: Decision.REFUSED}))
    client = await login(relay, alice, signer=bob, expect_ok=False)
    assert await close_code(client.ws) == (4001, "bad signature")


def test_open_access_admits_every_key() -> None:
    assert OpenAccess().mode == "open"
    assert OpenAccess().decide(alice.id) is Decision.ADMITTED


@pytest.mark.parametrize(
    ("host", "trust_forwarded_for", "expected"),
    [
        ("127.0.0.1", False, "open"),
        ("127.0.0.2", False, "open"),
        ("::1", False, "open"),
        ("localhost", False, "open"),
        ("127.0.0.1", True, None),
        ("0.0.0.0", False, None),
        ("::", False, None),
        ("192.168.1.10", False, None),
        ("relay.example.net", False, None),
    ],
)
def test_open_is_the_default_only_for_a_relay_only_this_machine_can_reach(
    host: str, trust_forwarded_for: bool, expected: str | None
) -> None:
    assert default_access_mode(host, trust_forwarded_for) == expected
    assert is_loopback_host(host) == (expected is not None or trust_forwarded_for)


def test_deleting_a_mailbox_removes_its_allow_list_waiting_messages_and_invite() -> None:
    store = RelayStore.open_memory()
    for key in (alice.id, bob.id):
        store.touch_mailbox(key, START_MS)
    store.set_allowed(alice.id, [bob.id])
    store.set_allowed(bob.id, [alice.id])
    store.add_message(bob.id, alice.id, "m1", "{}", START_MS)
    store.add_message(alice.id, bob.id, "m2", "{}", START_MS)
    store.add_invite("hash", alice.id, START_MS + 1000)

    store.delete_mailbox(alice.id)

    assert not store.has_mailbox(alice.id)
    assert not store.is_allowed(alice.id, bob.id)
    assert store.usage(alice.id, 0).messages == 0
    assert store.invite_creator("hash") is None
    # Bob's mailbox, his allow list and the message waiting for him are his.
    assert store.has_mailbox(bob.id)
    assert store.is_allowed(bob.id, alice.id)
    assert store.usage(bob.id, 0).messages == 1
    store.close()


async def test_auth_answers_ok_with_the_number_waiting(relay: RelayServer) -> None:
    client = await login(relay, alice)
    assert client.ok == {"t": "ok", "waiting": 0}
    await client.close()


async def test_auth_signed_by_a_different_key_is_refused(relay: RelayServer) -> None:
    client = await login(relay, alice, signer=bob, expect_ok=False)
    assert await close_code(client.ws) == (4001, "bad signature")


async def test_auth_with_a_garbage_signature_is_refused(relay: RelayServer) -> None:
    ws, _ = await open_ws(relay)
    sig = to_base64url(random_bytes(64))
    await ws.send(jsontext.stringify({"t": "auth", "v": 1, "key": alice.id, "sig": sig}))
    assert await close_code(ws) == (4001, "bad signature")


async def test_signature_made_for_another_relay_key_is_refused(relay: RelayServer) -> None:
    other_relay = make_identity("other relay")
    client = await login(relay, alice, relay_key=other_relay.id, expect_ok=False)
    assert await close_code(client.ws) == (4001, "bad signature")


async def test_malformed_auth_is_refused(relay: RelayServer) -> None:
    ws, _ = await open_ws(relay)
    await ws.send(jsontext.stringify({"t": "auth", "v": 1, "key": "nope", "sig": "x"}))
    assert await close_code(ws) == (4001, "bad auth")


async def test_a_frame_other_than_auth_before_ok_closes_the_connection(
    relay: RelayServer,
) -> None:
    ws, _ = await open_ws(relay)
    await ws.send(jsontext.stringify({"t": "fetch", "req": "1"}))
    assert (await close_code(ws))[0] == 4001


async def test_a_client_that_does_not_authenticate_in_time_is_disconnected(
    start_relay: RelayFactory,
) -> None:
    relay = await start_relay(RelayLimits(auth_timeout_s=0.2))
    ws, _ = await open_ws(relay)
    assert await close_code(ws) == (4001, "authentication timed out")


async def test_a_second_connection_with_the_same_key_replaces_the_first(
    relay: RelayServer,
) -> None:
    first = await login(relay, alice)
    second = await login(relay, alice)
    assert await close_code(first.ws) == (4002, "replaced")
    # The new connection works.
    await second.allow(bob)
    await second.close()


async def test_the_relay_key_and_mailboxes_are_kept_in_the_data_directory(
    start_relay: RelayFactory, data_dir: str
) -> None:
    relay = await start_relay()
    key = relay.key_id
    client = await login(relay, alice)
    await client.close()
    await relay.stop()
    assert stat.S_IMODE(os.stat(data_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(os.path.join(data_dir, DB_FILE)).st_mode) == 0o600
    again = await start_relay()
    assert again.key_id == key
    with sqlite3.connect(os.path.join(data_dir, DB_FILE)) as db:
        rows = db.execute("SELECT key_id FROM mailboxes").fetchall()
    assert rows == [(alice.id,)]


# Frames after ok.


async def test_a_request_without_req_or_of_unknown_type_is_malformed(relay: RelayServer) -> None:
    client = await login(relay, alice)
    await client.send({"t": "allow", "senders": []})
    assert await client.recv() == {"t": "refused", "req": None, "reason": "malformed"}
    await client.send({"t": "allow", "req": "x" * 65, "senders": []})
    assert await client.recv() == {"t": "refused", "req": None, "reason": "malformed"}
    answer = await client.request("dance")
    assert answer == {"t": "refused", "req": answer["req"], "reason": "malformed"}
    await client.ws.send(b"\x00binary")
    assert await client.recv() == {"t": "refused", "req": None, "reason": "malformed"}
    await client.ws.send("not json")
    assert await client.recv() == {"t": "refused", "req": None, "reason": "malformed"}
    await client.close()


async def test_allow_list_must_be_key_ids(relay: RelayServer) -> None:
    client = await login(relay, alice)
    answer = await client.request("allow", senders=["not a key"])
    assert answer["reason"] == "malformed"
    await client.close()


# Deposit.


async def test_deposit_is_refused_when_the_sender_is_not_on_the_allow_list(
    relay: RelayServer,
) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    await b.allow(carol)
    answer = await a.deposit(bob)
    assert answer["t"] == "refused"
    assert answer["reason"] == "not-allowed"
    await a.close()
    await b.close()


async def test_deposit_to_a_mailbox_that_does_not_exist_is_not_allowed(
    relay: RelayServer,
) -> None:
    a = await login(relay, alice)
    answer = await a.deposit(carol)
    assert answer["reason"] == "not-allowed"
    await a.close()


async def test_deposit_from_a_key_removed_from_the_allow_list_is_refused(
    relay: RelayServer,
) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    await b.allow(alice)
    assert (await a.deposit(bob))["t"] == "deposited"
    await b.allow()
    assert (await a.deposit(bob))["reason"] == "not-allowed"
    await a.close()
    await b.close()


async def test_deposit_whose_sealed_sender_is_not_the_connected_key_is_refused(
    relay: RelayServer,
) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    await b.allow(alice, carol)
    answer = await a.deposit(bob, sealed=fake_sealed(carol, bob))
    assert answer["reason"] == "sender-mismatch"
    await a.close()
    await b.close()


async def test_deposit_with_a_bad_sealed_message_or_id_is_malformed(relay: RelayServer) -> None:
    a = await login(relay, alice)
    bad = fake_sealed(alice, bob)
    bad["extra"] = 1
    assert (await a.deposit(bob, sealed=bad))["reason"] == "malformed"
    assert (await a.deposit(bob, message_id="x" * 129))["reason"] == "malformed"
    await a.send({"t": "deposit", "req": "q", "sealed": fake_sealed(alice, bob)})
    assert (await a.recv())["reason"] == "malformed"
    await a.close()


async def test_shape_is_checked_before_sender_and_sender_before_allow_list(
    relay: RelayServer,
) -> None:
    a = await login(relay, alice)
    # Nobody has allowed alice, so each answer shows which check came first.
    bad = fake_sealed(carol, bob)
    bad["v"] = 2
    assert (await a.deposit(bob, sealed=bad))["reason"] == "malformed"
    assert (await a.deposit(bob, sealed=fake_sealed(carol, bob)))["reason"] == "sender-mismatch"
    assert (await a.deposit(bob))["reason"] == "not-allowed"
    await a.close()


async def test_deposit_and_fetch_and_delete(relay: RelayServer, clock: Clock) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    sealed = fake_sealed(alice, bob)
    answer = await a.deposit(bob, "id-1", sealed=sealed)
    assert answer == {"t": "deposited", "req": answer["req"], "id": "id-1"}
    await b.send({"t": "fetch", "req": "f"})
    deliver = await b.recv()
    assert deliver["t"] == "deliver"
    assert deliver["sealed"] == sealed
    assert deliver["deposited_at"] == "2027-01-15T08:00:00.000Z"
    assert isinstance(deliver["rid"], int)
    await b.send({"t": "delete", "rid": deliver["rid"]})
    await b.nothing_more()
    await b.close()
    # Deleted: not sent again after reconnecting.
    b = await login(relay, bob)
    assert b.ok["waiting"] == 0
    await b.send({"t": "fetch", "req": "f"})
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_a_message_not_deleted_is_sent_again_after_reconnecting(
    relay: RelayServer,
) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    await b.close()
    a = await login(relay, alice)
    await a.deposit(bob, "id-1")
    await a.deposit(bob, "id-2")
    b = await login(relay, bob)
    assert b.ok["waiting"] == 2
    await b.send({"t": "fetch", "req": "f"})
    first = await b.recv()
    second = await b.recv()
    assert first["rid"] < second["rid"]
    await b.send({"t": "delete", "rid": first["rid"]})
    await b.close()
    b = await login(relay, bob)
    assert b.ok["waiting"] == 1
    await b.send({"t": "fetch", "req": "f"})
    again = await b.recv()
    assert again["rid"] == second["rid"]
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_the_same_sender_and_id_is_stored_once(relay: RelayServer) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    sealed = fake_sealed(alice, bob)
    assert (await a.deposit(bob, "same", sealed=sealed))["t"] == "deposited"
    assert (await a.deposit(bob, "same", sealed=sealed))["t"] == "deposited"
    await b.send({"t": "fetch", "req": "f"})
    assert (await b.recv())["t"] == "deliver"
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_a_repeat_of_an_expired_copy_is_stored_again(
    relay: RelayServer, clock: Clock
) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    await b.close()
    a = await login(relay, alice)
    sealed = fake_sealed(alice, bob)
    await a.deposit(bob, "again", sealed=sealed)
    # Past the 7 days, but before the purge has deleted it.
    clock.advance(7 * DAY_MS + 1)
    assert (await a.deposit(bob, "again", sealed=sealed))["t"] == "deposited"
    relay.purge()
    b = await login(relay, bob)
    assert b.ok["waiting"] == 1
    await a.close()
    await b.close()


async def test_new_deposits_are_pushed_to_a_fetching_client(relay: RelayServer) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    await b.send({"t": "fetch", "req": "f"})
    await b.nothing_more()
    a = await login(relay, alice)
    sealed = fake_sealed(alice, bob)
    await a.deposit(bob, sealed=sealed)
    pushed = await b.recv()
    assert pushed["t"] == "deliver"
    assert pushed["sealed"] == sealed
    await a.close()
    await b.close()


async def test_a_client_that_has_not_fetched_gets_no_pushes(relay: RelayServer) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    await a.deposit(bob)
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_at_most_the_limit_of_deliveries_are_outstanding(
    start_relay: RelayFactory,
) -> None:
    relay = await start_relay(RelayLimits(max_outstanding=2))
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    for _ in range(3):
        await a.deposit(bob)
    await b.send({"t": "fetch", "req": "f"})
    first = await b.recv()
    await b.recv()
    await b.nothing_more()
    await b.send({"t": "delete", "rid": first["rid"]})
    third = await b.recv()
    assert third["t"] == "deliver"
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_a_waiting_message_survives_a_relay_restart(
    start_relay: RelayFactory,
) -> None:
    relay = await start_relay()
    b = await login(relay, bob)
    await b.allow(alice)
    await b.close()
    a = await login(relay, alice)
    sealed = fake_sealed(alice, bob)
    await a.deposit(bob, sealed=sealed)
    await a.close()
    await relay.stop()

    restarted = await start_relay()
    b = await login(restarted, bob)
    assert b.ok["waiting"] == 1
    await b.send({"t": "fetch", "req": "f"})
    deliver = await b.recv()
    assert deliver["sealed"] == sealed
    # The allow list survived too.
    a = await login(restarted, alice)
    assert (await a.deposit(bob))["t"] == "deposited"
    await a.close()
    await b.close()


async def test_messages_expire_after_seven_days(relay: RelayServer, clock: Clock) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    await b.close()
    a = await login(relay, alice)
    await a.deposit(bob, "old")
    clock.advance(DAY_MS)
    await a.deposit(bob, "newer")
    clock.advance(6 * DAY_MS)
    relay.purge()
    # Exactly 7 days old: still kept.
    b = await login(relay, bob)
    assert b.ok["waiting"] == 2
    await b.close()
    clock.advance(1)
    relay.purge()
    b = await login(relay, bob)
    assert b.ok["waiting"] == 1
    await b.send({"t": "fetch", "req": "f"})
    deliver = await b.recv()
    assert deliver["deposited_at"] == "2027-01-16T08:00:00.000Z"
    await b.nothing_more()
    with sqlite3.connect(os.path.join(relay._data_dir, DB_FILE)) as db:
        assert db.execute("SELECT COUNT(*) FROM messages").fetchone() == (1,)
    await a.close()
    await b.close()


async def test_expired_messages_are_not_delivered_even_before_the_purge(
    relay: RelayServer, clock: Clock
) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    await a.deposit(bob)
    clock.advance(7 * DAY_MS + 1)
    await b.send({"t": "fetch", "req": "f"})
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_expired_messages_are_purged_at_start(
    start_relay: RelayFactory, clock: Clock, data_dir: str
) -> None:
    relay = await start_relay()
    b = await login(relay, bob)
    await b.allow(alice)
    await b.close()
    a = await login(relay, alice)
    await a.deposit(bob)
    await a.close()
    await relay.stop()
    clock.advance(7 * DAY_MS + 1)
    await start_relay()
    with sqlite3.connect(os.path.join(data_dir, DB_FILE)) as db:
        assert db.execute("SELECT COUNT(*) FROM messages").fetchone() == (0,)


# Limits.


async def test_a_sealed_message_over_the_size_limit_is_refused(
    start_relay: RelayFactory,
) -> None:
    relay = await start_relay(RelayLimits(max_sealed_bytes=1000))
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    assert (await a.deposit(bob, sealed=fake_sealed(alice, bob, 500)))["t"] == "deposited"
    answer = await a.deposit(bob, sealed=fake_sealed(alice, bob, 1000))
    assert answer["reason"] == "too-large"
    answer = await a.request("forward", sealed=fake_sealed(alice, bob, 1000))
    assert answer["reason"] == "too-large"
    await a.close()
    await b.close()


async def test_a_frame_over_the_frame_limit_closes_the_connection(
    start_relay: RelayFactory,
) -> None:
    relay = await start_relay(RelayLimits(max_frame_bytes=2000))
    a = await login(relay, alice)
    await a.send({"t": "deposit", "req": "big", "id": "1", "sealed": fake_sealed(alice, bob, 3000)})
    with pytest.raises(ConnectionClosed) as info:
        await a.recv()
    assert info.value.rcvd is not None
    assert info.value.rcvd.code == 1009


async def test_a_full_mailbox_refuses_deposits(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(max_mailbox_messages=2))
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    await a.deposit(bob, "1")
    await a.deposit(bob, "2")
    assert (await a.deposit(bob, "3"))["reason"] == "mailbox-full"
    # A repeat of a message already stored is still answered deposited.
    assert (await a.deposit(bob, "2"))["t"] == "deposited"
    await a.close()
    await b.close()


async def test_a_mailbox_over_its_size_limit_refuses_deposits(
    start_relay: RelayFactory,
) -> None:
    relay = await start_relay(RelayLimits(max_mailbox_bytes=600))
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    assert (await a.deposit(bob, sealed=fake_sealed(alice, bob, 100)))["t"] == "deposited"
    answer = await a.deposit(bob, sealed=fake_sealed(alice, bob, 300))
    assert answer["reason"] == "mailbox-full"
    await a.close()
    await b.close()


async def test_an_allow_list_over_the_limit_is_refused(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(max_allow_list=1))
    b = await login(relay, bob)
    answer = await b.request("allow", senders=[alice.id, carol.id])
    assert answer["reason"] == "too-large"
    await b.close()


async def test_deposits_are_rate_limited(start_relay: RelayFactory, clock: Clock) -> None:
    relay = await start_relay(RelayLimits(deposit_rate=Rate(60, MINUTE_MS, burst=2)))
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    assert (await a.deposit(bob))["t"] == "deposited"
    assert (await a.deposit(bob))["t"] == "deposited"
    answer = await a.deposit(bob)
    assert answer["reason"] == "rate-limited"
    assert answer["retry_after"] == 1
    clock.advance(1000)
    assert (await a.deposit(bob))["t"] == "deposited"
    await a.close()
    await b.close()


async def test_allow_list_changes_are_rate_limited(start_relay: RelayFactory, clock: Clock) -> None:
    relay = await start_relay(RelayLimits(allow_rate=Rate(1, MINUTE_MS)))
    b = await login(relay, bob)
    await b.allow(alice)
    answer = await b.request("allow", senders=[])
    assert answer["reason"] == "rate-limited"
    assert answer["retry_after"] == 60
    await b.close()


async def test_new_connections_from_one_address_are_rate_limited(
    start_relay: RelayFactory, clock: Clock
) -> None:
    relay = await start_relay(RelayLimits(connect_rate_per_ip=Rate(2, MINUTE_MS)))
    for _ in range(2):
        ws, _hello = await open_ws(relay)
        await ws.close()
    with pytest.raises(InvalidStatus) as info:
        await open_ws(relay)
    assert info.value.response.status_code == 429
    clock.advance(MINUTE_MS)
    ws, _hello = await open_ws(relay)
    await ws.close()


async def test_behind_a_proxy_the_forwarded_address_is_rate_limited(
    data_dir: str, clock: Clock
) -> None:
    relay = RelayServer(
        data_dir,
        port=0,
        limits=RelayLimits(connect_rate_per_ip=Rate(1, MINUTE_MS)),
        now=clock,
        trust_forwarded_for=True,
    )
    await relay.start()
    try:
        url = f"ws://127.0.0.1:{relay.port}"
        for address in ("10.0.0.1", "10.0.0.2"):
            ws = await connect(url, additional_headers={"X-Forwarded-For": f"1.1.1.1, {address}"})
            await ws.close()
        with pytest.raises(InvalidStatus):
            await connect(url, additional_headers={"X-Forwarded-For": "10.0.0.1"})
    finally:
        await relay.stop()


async def test_a_client_that_stops_reading_is_disconnected(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(max_queued_bytes=2_000))
    a = await login(relay, alice)
    # Frames are queued faster than they can be written, as when the client
    # stops reading; past the limit the relay drops the connection instead of
    # queueing more.
    client = relay._clients[alice.id]
    for _ in range(40):
        client.send({"t": "refused", "req": None, "reason": "malformed", "pad": "x" * 100})
    with pytest.raises(ConnectionClosed):
        while True:
            await asyncio.wait_for(a.ws.recv(), 3)


# Forward.


async def test_forward_reaches_a_connected_recipient(relay: RelayServer) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    sealed = fake_sealed(alice, bob)
    answer = await a.request("forward", sealed=sealed)
    assert answer["t"] == "forwarded"
    assert await b.recv() == {"t": "live", "sealed": sealed}
    # Nothing was stored.
    await b.send({"t": "fetch", "req": "f"})
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_forward_to_a_recipient_not_connected_is_refused_as_offline(
    relay: RelayServer,
) -> None:
    b = await login(relay, bob)
    await b.allow(alice)
    await b.close()
    a = await login(relay, alice)
    answer = await a.request("forward", sealed=fake_sealed(alice, bob))
    assert answer["reason"] == "offline"
    await a.close()


async def test_forward_applies_the_sender_and_allow_list_checks(relay: RelayServer) -> None:
    b = await login(relay, bob)
    a = await login(relay, alice)
    answer = await a.request("forward", sealed=fake_sealed(alice, bob))
    assert answer["reason"] == "not-allowed"
    await b.allow(alice)
    answer = await a.request("forward", sealed=fake_sealed(carol, bob))
    assert answer["reason"] == "sender-mismatch"
    await a.close()
    await b.close()


async def test_forwards_are_rate_limited(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(forward_rate=Rate(1, MINUTE_MS)))
    b = await login(relay, bob)
    await b.allow(alice)
    a = await login(relay, alice)
    assert (await a.request("forward", sealed=fake_sealed(alice, bob)))["t"] == "forwarded"
    assert (await a.request("forward", sealed=fake_sealed(alice, bob)))["reason"] == "rate-limited"
    await a.close()
    await b.close()


# Invites and pairing rooms.


async def create_invite(client: Client) -> tuple[str, str]:
    """Creates an invite; returns the code and the req used."""
    answer = await client.request("invite-create")
    assert answer["t"] == "invite", answer
    return answer["code"], answer["req"]


async def test_invite_join_and_pair_passthrough(relay: RelayServer, clock: Clock) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    answer = await a.request("invite-create")
    code = answer["code"]
    assert len(code) == 9 and code[4] == "-"
    assert all(c in ALPHABET for c in code.replace("-", ""))
    assert answer["expires_at"] == "2027-01-15T08:10:00.000Z"

    joined_b = await b.request("invite-join", code=code.lower().replace("-", ""))
    assert joined_b["t"] == "invite-joined"
    assert joined_b["peer"] == alice.id
    joined_a = await a.recv()
    assert joined_a == {
        "t": "invite-joined",
        "req": answer["req"],
        "room": joined_b["room"],
        "peer": bob.id,
    }
    room = joined_b["room"]

    commit = {"t": "pair-commit", "commit": "abc", "relay": "wss://relay.example"}
    await b.send({"t": "pair", "room": room, "frame": commit})
    assert await a.recv() == {"t": "pair", "room": room, "frame": commit}
    nonce = {"t": "pair-nonce", "nonce": "xyz"}
    await a.send({"t": "pair", "room": room, "frame": nonce})
    assert await b.recv() == {"t": "pair", "room": room, "frame": nonce}

    await b.send({"t": "pair-end", "room": room})
    assert await a.recv() == {"t": "pair-end", "room": room}
    # The room is gone: a frame sent to it is answered pair-end.
    await a.send({"t": "pair", "room": room, "frame": nonce})
    assert await a.recv() == {"t": "pair-end", "room": room}
    await b.nothing_more()
    await a.close()
    await b.close()


async def test_an_invite_code_works_once(relay: RelayServer) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    c = await login(relay, carol)
    code, _ = await create_invite(a)
    assert (await b.request("invite-join", code=code))["t"] == "invite-joined"
    assert (await c.request("invite-join", code=code))["reason"] == "no-such-invite"
    await a.close()
    await b.close()
    await c.close()


async def test_an_invite_code_expires_after_ten_minutes(relay: RelayServer, clock: Clock) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    code, _ = await create_invite(a)
    clock.advance(10 * MINUTE_MS)
    assert (await b.request("invite-join", code=code))["reason"] == "no-such-invite"
    await a.close()
    await b.close()


async def test_an_invite_is_gone_when_its_creator_disconnects(relay: RelayServer) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    code, _ = await create_invite(a)
    await a.close()
    await asyncio.sleep(0.1)
    assert (await b.request("invite-join", code=code))["reason"] == "no-such-invite"
    await b.close()


async def test_only_one_invite_is_open_per_key(relay: RelayServer) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    first, _ = await create_invite(a)
    second, _ = await create_invite(a)
    assert (await b.request("invite-join", code=first))["reason"] == "no-such-invite"
    assert (await b.request("invite-join", code=second))["t"] == "invite-joined"
    await a.close()
    await b.close()


async def test_the_relay_stores_only_a_hash_of_the_code(relay: RelayServer) -> None:
    a = await login(relay, alice)
    code, _ = await create_invite(a)
    with sqlite3.connect(os.path.join(relay._data_dir, DB_FILE)) as db:
        rows = db.execute("SELECT code_hash, creator FROM invites").fetchall()
    assert rows == [(code_hash(code.replace("-", "")), alice.id)]
    await a.close()


async def test_joining_your_own_invite_is_refused(relay: RelayServer) -> None:
    a = await login(relay, alice)
    code, _ = await create_invite(a)
    assert (await a.request("invite-join", code=code))["reason"] == "no-such-invite"
    await a.close()


async def test_invite_creation_is_rate_limited(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(invite_create_rate=Rate(1, 3_600_000)))
    a = await login(relay, alice)
    await create_invite(a)
    answer = await a.request("invite-create")
    assert answer["reason"] == "rate-limited"
    assert answer["retry_after"] == 3600
    await a.close()


async def test_invite_join_attempts_are_rate_limited(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(invite_join_rate_per_connection=Rate(2, MINUTE_MS)))
    b = await login(relay, bob)
    for _ in range(2):
        assert (await b.request("invite-join", code="0000-0000"))["reason"] == "no-such-invite"
    assert (await b.request("invite-join", code="0000-0000"))["reason"] == "rate-limited"
    await b.close()


async def test_invite_join_attempts_are_limited_per_address(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(invite_join_rate_per_ip=Rate(2, 3_600_000)))
    b = await login(relay, bob)
    c = await login(relay, carol)
    assert (await b.request("invite-join", code="0000-0000"))["reason"] == "no-such-invite"
    assert (await c.request("invite-join", code="0000-0000"))["reason"] == "no-such-invite"
    assert (await b.request("invite-join", code="0000-0000"))["reason"] == "rate-limited"
    await b.close()
    await c.close()


async def test_a_room_ends_after_its_frame_limit(start_relay: RelayFactory) -> None:
    relay = await start_relay(RelayLimits(max_pair_frames=2))
    a = await login(relay, alice)
    b = await login(relay, bob)
    code, _ = await create_invite(a)
    room = (await b.request("invite-join", code=code))["room"]
    await a.recv()
    for _ in range(2):
        await b.send({"t": "pair", "room": room, "frame": {"t": "x"}})
        assert (await a.recv())["t"] == "pair"
    await b.send({"t": "pair", "room": room, "frame": {"t": "x"}})
    assert await a.recv() == {"t": "pair-end", "room": room}
    assert await b.recv() == {"t": "pair-end", "room": room}
    await a.close()
    await b.close()


async def test_a_room_ends_when_one_side_disconnects_or_time_runs_out(
    relay: RelayServer, clock: Clock
) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    code, _ = await create_invite(a)
    room = (await b.request("invite-join", code=code))["room"]
    await a.recv()
    await b.close()
    assert await a.recv() == {"t": "pair-end", "room": room}

    b = await login(relay, bob)
    code, _ = await create_invite(a)
    room = (await b.request("invite-join", code=code))["room"]
    await a.recv()
    clock.advance(10 * MINUTE_MS)
    relay.purge()
    assert await a.recv() == {"t": "pair-end", "room": room}
    assert await b.recv() == {"t": "pair-end", "room": room}
    await a.close()
    await b.close()


async def test_someone_outside_a_room_cannot_use_it(relay: RelayServer) -> None:
    a = await login(relay, alice)
    b = await login(relay, bob)
    c = await login(relay, carol)
    code, _ = await create_invite(a)
    room = (await b.request("invite-join", code=code))["room"]
    await a.recv()
    await c.send({"t": "pair", "room": room, "frame": {"t": "pair-abort"}})
    assert await c.recv() == {"t": "pair-end", "room": room}
    await a.nothing_more()
    await b.nothing_more()
    await a.close()
    await b.close()
    await c.close()


# Plain HTTP.


async def http_get(port: int, path: str) -> tuple[str, str]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    head, _, body = data.decode().partition("\r\n\r\n")
    return head, body


async def test_healthz_answers_status_and_version(relay: RelayServer) -> None:
    head, body = await http_get(relay.port, "/healthz")
    assert head.startswith("HTTP/1.1 200")
    assert "Content-Type: application/json" in head
    assert jsontext.parse(body) == {"status": "ok", "version": VERSION}


async def test_other_plain_http_requests_are_refused(relay: RelayServer) -> None:
    head, _ = await http_get(relay.port, "/")
    assert head.startswith("HTTP/1.1 426")


# Pieces.


def test_new_codes_are_eight_alphabet_characters_with_a_hyphen() -> None:
    for _ in range(50):
        code = new_code()
        assert len(code) == 9 and code[4] == "-"
        assert normalize_code(code) == code.replace("-", "")


def test_codes_ignore_case_and_hyphens() -> None:
    assert normalize_code("k7qm-4xrt") == "K7QM4XRT"
    assert normalize_code("K7QM4XRT") == "K7QM4XRT"
    assert normalize_code("K7-QM-4X-RT") == "K7QM4XRT"
    assert normalize_code("K7QM-4XR") is None
    assert normalize_code("K7QM-4XRU") is None  # U is not in the alphabet


def test_rate_limiter_refills_over_time() -> None:
    clock = Clock()
    limiter = RateLimiter(clock)
    rate = Rate(60, MINUTE_MS, burst=2)
    assert limiter.take("k", "a", rate) is None
    assert limiter.take("k", "a", rate) is None
    assert limiter.take("k", "a", rate) == 1
    assert limiter.take("k", "b", rate) is None  # counted separately per key
    clock.advance(1000)
    assert limiter.take("k", "a", rate) is None
    assert limiter.take("k", "a", rate) == 1
    clock.advance(MINUTE_MS)
    limiter.forget_full({"k": rate})
    assert limiter._buckets == {}


# Keys mode (docs/plan/relay-access.md, "The allowed keys file").


def write_keys(path: str, *lines: str) -> None:
    """Writes the allowed keys file, making sure its change is noticed even
    when two writes fall in the same clock tick."""
    try:
        previous = os.stat(path).st_mtime_ns
    except OSError:
        previous = 0
    with open(path, "w", encoding="utf-8") as file:
        file.write("".join(f"{line}\n" for line in lines))
    mtime = max(time.time_ns(), previous + 1_000_000)
    os.utime(path, ns=(mtime, mtime))


@pytest.fixture
def keys_file(tmp_path: Any) -> str:
    path = os.path.join(str(tmp_path), "allowed-keys")
    write_keys(path, "# who may use the relay", f"{alice.id}  Alice's laptop  # since May", "")
    return path


def test_allowed_keys_file_lines() -> None:
    text = f"# comment\n\n{alice.id}\n  {bob.id}\tBob # work\n{carol.id} # Carol\n"
    assert parse_allowed_keys(text) == {alice.id: "", bob.id: "Bob", carol.id: ""}


def test_allowed_keys_file_names_every_line_that_is_not_a_key() -> None:
    with pytest.raises(AllowedKeysError) as info:
        parse_allowed_keys(f"{alice.id}\nalice\n\n{alice.id[:-1]} short\n")
    assert str(info.value) == (
        f"line 2: 'alice' is not a squawk key id; line 4: {alice.id[:-1]!r} is not a squawk key id"
    )


def test_a_missing_allowed_keys_file_is_an_error(tmp_path: Any) -> None:
    with pytest.raises(AllowedKeysError, match="cannot read"):
        KeysAccess(os.path.join(str(tmp_path), "nope"))


async def test_keys_mode_admits_listed_keys_and_refuses_others(
    start_relay: RelayFactory, keys_file: str
) -> None:
    relay = await start_relay(access=KeysAccess(keys_file))
    ws, hello = await open_ws(relay)
    assert hello["access"] == "keys"
    await ws.close()
    admitted = await login(relay, alice)
    assert admitted.ok["t"] == "ok"
    refused = await login(relay, bob, expect_ok=False)
    assert await close_code(refused.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(bob.id)
    await admitted.close()


async def test_a_key_removed_from_the_file_is_disconnected_and_its_mailbox_deleted(
    start_relay: RelayFactory, keys_file: str
) -> None:
    write_keys(keys_file, alice.id, bob.id)
    relay = await start_relay(access=KeysAccess(keys_file))
    a = await login(relay, alice)
    b = await login(relay, bob)
    await a.allow(bob)
    await b.allow(alice)
    assert (await b.deposit(alice))["t"] == "deposited"

    write_keys(keys_file, bob.id)
    relay.reload_access()

    assert await close_code(a.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(alice.id)
    assert relay.store.usage(alice.id, 0).messages == 0
    # Bob is still connected, and can no longer leave messages for Alice.
    assert (await b.deposit(alice))["reason"] == "not-allowed"
    again = await login(relay, alice, expect_ok=False)
    assert await close_code(again.ws) == (4003, "not permitted")
    await b.close()


async def test_a_key_added_to_the_file_is_admitted_after_a_reload(
    start_relay: RelayFactory, keys_file: str
) -> None:
    relay = await start_relay(access=KeysAccess(keys_file))
    write_keys(keys_file, alice.id, bob.id)
    relay.reload_access()
    b = await login(relay, bob)
    await b.close()


async def test_a_file_with_a_bad_line_changes_nothing(
    start_relay: RelayFactory, keys_file: str
) -> None:
    access = KeysAccess(keys_file)
    relay = await start_relay(access=access)
    a = await login(relay, alice)
    write_keys(keys_file, "alice", bob.id)
    relay.reload_access()
    assert access.keys == {alice.id: "Alice's laptop"}
    await a.allow(bob)  # still connected
    await a.close()


async def test_a_deleted_file_changes_nothing(start_relay: RelayFactory, keys_file: str) -> None:
    access = KeysAccess(keys_file)
    relay = await start_relay(access=access)
    os.remove(keys_file)
    relay.reload_access()
    a = await login(relay, alice)
    await a.close()


async def test_the_relay_notices_a_changed_file_by_itself(
    start_relay: RelayFactory, keys_file: str
) -> None:
    relay = await start_relay(
        RelayLimits(access_check_interval_s=0.05), access=KeysAccess(keys_file)
    )
    a = await login(relay, alice)
    write_keys(keys_file, bob.id)
    assert await close_code(a.ws) == (4003, "not permitted")


async def test_starting_in_keys_mode_deletes_the_mailboxes_of_keys_not_listed(
    start_relay: RelayFactory, keys_file: str, data_dir: str
) -> None:
    store = RelayStore.open(data_dir)
    store.touch_mailbox(alice.id, START_MS)
    store.touch_mailbox(bob.id, START_MS)
    store.close()
    relay = await start_relay(access=KeysAccess(keys_file))
    assert relay.store.mailbox_keys() == [alice.id]


async def test_sighup_rereads_the_allowed_keys_file(tmp_path: Any, keys_file: str) -> None:
    out: list[str] = []
    stop = asyncio.Event()
    io = CliIo(stdout=out.append, stderr=out.append, env={"SQUAWK_HOME": str(tmp_path)}, stop=stop)
    data = os.path.join(str(tmp_path), "data")
    args = ["relay", "serve", "--port", "0", "--data", data, "--access", "keys"]
    task = asyncio.create_task(run([*args, "--allowed-keys", keys_file], io))
    try:
        port = int(await wait_for_text(out, r"listening on ws://127\.0\.0\.1:(\d+)\n", 1))
        assert f"Access:    keys (1 allowed in {keys_file})\n" in "".join(out)
        relay = PortOnly(port)
        a = await login(relay, alice)  # type: ignore[arg-type]
        write_keys(keys_file, bob.id)
        os.kill(os.getpid(), signal.SIGHUP)
        assert await close_code(a.ws) == (4003, "not permitted")
    finally:
        stop.set()
        assert await asyncio.wait_for(task, 5) == 0


class PortOnly:
    """Enough of a RelayServer for `open_ws`, for a relay started by the CLI."""

    def __init__(self, port: int) -> None:
        self.port = port


async def wait_for_text(out: list[str], pattern: str, group: int, timeout: float = 5.0) -> str:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        match = re.search(pattern, "".join(out))
        if match is not None:
            return match.group(group)
        if loop.time() > deadline:
            raise AssertionError(f"timed out waiting for {pattern!r} in {''.join(out)!r}")
        await asyncio.sleep(0.02)


# GitHub mode (docs/plan/relay-access.md, "Signing in with GitHub").


class FakeGitHub:
    """Stands in for GitHub. Each poll for the token gives the next of
    `answers`; once they run out, the person has approved and `user` is who
    they are. While `hold` is set and not yet released, polls wait for it, so
    a sign-in stays in progress."""

    def __init__(self) -> None:
        self.user: GitHubUser = GitHubUser("alice", 101)
        self.answers: list[PollAnswer | GitHubError] = []
        self.code_error: GitHubError | None = None
        self.hold: asyncio.Event | None = None
        self.codes_given = 0

    async def request_device_code(self) -> DeviceCode:
        if self.code_error is not None:
            raise self.code_error
        self.codes_given += 1
        return DeviceCode(
            device_code="device-secret",
            user_code="ABCD-1234",
            verification_uri="https://github.com/login/device",
            expires_in=900,
            interval=5,
        )

    async def poll_token(self, device_code: str) -> PollAnswer:
        if self.hold is not None:
            await self.hold.wait()
        if self.answers:
            answer = self.answers.pop(0)
            if isinstance(answer, GitHubError):
                raise answer
            return answer
        return Token("gho_token")

    async def read_user(self, token: str) -> GitHubUser:
        return self.user


class SecondsClock:
    """A clock in seconds that moves only when the sign-in sleeps, so tests
    never wait for GitHub's polling interval."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds
        await asyncio.sleep(0)


@pytest.fixture
def users_file(tmp_path: Any) -> str:
    path = os.path.join(str(tmp_path), "allowed-users")
    write_keys(path, "# who may use the relay", "alice", "Bob  202  # pinned", "")
    return path


@pytest.fixture
def github() -> FakeGitHub:
    return FakeGitHub()


def github_access(path: str, github: FakeGitHub, max_keys_per_user: int = 5) -> GitHubAccess:
    seconds = SecondsClock()
    return GitHubAccess(
        path,
        github,
        max_keys_per_user=max_keys_per_user,
        sleep=seconds.sleep,
        clock=seconds,
    )


async def start_sign_in(
    relay: RelayServer, identity: Identity, *, now_ms: int = START_MS
) -> Client:
    """Connects as `identity`, which the relay has not seen, and sends
    `login-start`. Returns the client once the relay has sent the code.
    `now_ms` is the time on the relay's clock, from which the code expires."""
    client = await login(relay, identity, expect_ok=False)
    assert await client.recv() == {"t": "login-required", "provider": "github"}
    await client.send({"t": "login-start"})
    code = await client.recv()
    assert code == {
        "t": "login",
        "verification_uri": "https://github.com/login/device",
        "user_code": "ABCD-1234",
        "expires_at": iso_from_ms(now_ms + 900_000),
    }
    return client


async def sign_in_fails(relay: RelayServer, identity: Identity, reason: str) -> None:
    client = await start_sign_in(relay, identity)
    assert await client.recv() == {"t": "login-failed", "reason": reason}
    assert await close_code(client.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(identity.id)
    assert relay.store.key_owner(identity.id) is None


async def busy_sign_in(relay: RelayServer, identity: Identity) -> None:
    client = await login(relay, identity, expect_ok=False)
    assert (await client.recv())["t"] == "login-required"
    await client.send({"t": "login-start"})
    assert await client.recv() == {"t": "login-failed", "reason": "busy"}
    assert await close_code(client.ws) == (4003, "not permitted")


def test_allowed_users_file_lines() -> None:
    text = "# comment\n\nalice\n  Bob\t202 # work\ncarol-x   # Carol\n"
    assert parse_allowed_users(text) == {"alice": None, "bob": 202, "carol-x": None}


def test_allowed_users_file_names_every_line_that_is_not_a_user() -> None:
    with pytest.raises(AllowedUsersError) as info:
        parse_allowed_users("alice\n-bob\ncarol x\ndave 12 13\nALICE\nerin 0\n")
    assert str(info.value) == (
        "line 2: '-bob' is not a GitHub user name; "
        "line 3: after the user name there can only be a numeric GitHub id; "
        "line 4: after the user name there can only be a numeric GitHub id; "
        "line 5: 'ALICE' is listed more than once; "
        "line 6: 0 is not a GitHub id"
    )


def test_a_missing_allowed_users_file_is_an_error(tmp_path: Any, github: FakeGitHub) -> None:
    with pytest.raises(AllowedUsersError, match="cannot read"):
        github_access(os.path.join(str(tmp_path), "nope"), github)


async def test_a_new_key_signs_in_with_github_and_carries_on(
    start_relay: RelayFactory,
    users_file: str,
    github: FakeGitHub,
    capsys: pytest.CaptureFixture[str],
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    ws, hello = await open_ws(relay)
    assert hello["access"] == "github"
    await ws.close()
    client = await start_sign_in(relay, alice)
    assert await client.recv() == {"t": "ok", "waiting": 0, "user": "alice"}
    assert relay.store.key_owner(alice.id) == KeyOwner(101, "alice")
    assert relay.store.has_mailbox(alice.id)
    await client.allow(bob)  # an admitted connection like any other
    assert "their GitHub id is 101" in capsys.readouterr().err
    await client.close()


async def test_a_key_that_signed_in_before_is_admitted_at_once(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    first = await start_sign_in(relay, alice)
    assert (await first.recv())["t"] == "ok"
    await first.close()
    again = await login(relay, alice)
    assert again.ok == {"t": "ok", "waiting": 0}
    assert github.codes_given == 1
    await again.close()


async def test_a_sign_in_the_person_declines_fails_as_denied(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.answers = [Pending(), Denied()]
    await sign_in_fails(relay, alice, "denied")


async def test_a_sign_in_github_says_has_expired_fails_as_expired(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.answers = [Pending(), Expired()]
    await sign_in_fails(relay, alice, "expired")


async def test_a_sign_in_is_given_up_when_the_code_runs_out(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.answers = [Pending()] * 1000  # 900 seconds at one poll every 5
    await sign_in_fails(relay, alice, "expired")


async def test_a_sign_in_fails_as_error_when_github_cannot_be_reached_for_the_code(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.code_error = GitHubError("Could not reach GitHub")
    client = await login(relay, alice, expect_ok=False)
    assert (await client.recv())["t"] == "login-required"
    await client.send({"t": "login-start"})
    assert await client.recv() == {"t": "login-failed", "reason": "error"}
    assert await close_code(client.ws) == (4003, "not permitted")


async def test_a_sign_in_fails_as_error_when_github_fails_while_polling(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.answers = [Pending(), GitHubError("GitHub answered 502")]
    await sign_in_fails(relay, alice, "error")


async def test_a_github_user_not_in_the_file_is_not_permitted(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.user = GitHubUser("mallory", 666)
    await sign_in_fails(relay, alice, "not-permitted")


async def test_a_name_first_used_by_one_account_refuses_another_account(
    start_relay: RelayFactory,
    users_file: str,
    github: FakeGitHub,
    capsys: pytest.CaptureFixture[str],
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    first = await start_sign_in(relay, alice)
    assert (await first.recv())["user"] == "alice"
    # Another account with the same name (written in another case), as after
    # the first account was renamed and someone took the name.
    github.user = GitHubUser("ALICE", 999)
    await sign_in_fails(relay, bob, "not-permitted")
    assert "that name first signed in here as GitHub id 101" in capsys.readouterr().err
    await first.close()


async def test_an_id_in_the_file_admits_only_that_account(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.user = GitHubUser("bob", 303)
    await sign_in_fails(relay, alice, "not-permitted")
    github.user = GitHubUser("bob", 202)
    client = await start_sign_in(relay, bob)
    assert await client.recv() == {"t": "ok", "waiting": 0, "user": "bob"}
    await client.close()


async def test_a_user_may_sign_in_at_most_the_most_keys_allowed(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github, max_keys_per_user=1))
    first = await start_sign_in(relay, alice)
    assert (await first.recv())["t"] == "ok"
    await sign_in_fails(relay, bob, "not-permitted")
    await first.close()


async def test_a_new_key_that_does_not_send_login_start_in_time_is_closed(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(
        RelayLimits(login_start_timeout_s=0.1), access=github_access(users_file, github)
    )
    client = await login(relay, alice, expect_ok=False)
    assert (await client.recv())["t"] == "login-required"
    assert await close_code(client.ws) == (4003, "not permitted")
    assert github.codes_given == 0


async def test_a_frame_other_than_login_start_closes_the_connection(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    client = await login(relay, alice, expect_ok=False)
    assert (await client.recv())["t"] == "login-required"
    await client.send({"t": "fetch", "req": "r1"})
    assert await close_code(client.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(alice.id)


async def test_neither_timeout_applies_once_the_sign_in_has_started(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(
        RelayLimits(auth_timeout_s=0.05, login_start_timeout_s=0.05),
        access=github_access(users_file, github),
    )
    github.hold = asyncio.Event()
    client = await start_sign_in(relay, alice)
    await client.nothing_more(0.3)
    github.hold.set()
    assert (await client.recv())["t"] == "ok"
    await client.close()


async def test_sign_ins_started_from_one_address_are_rate_limited(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub, clock: Clock
) -> None:
    relay = await start_relay(
        RelayLimits(sign_in_rate_per_ip=Rate(1, HOUR_MS)), access=github_access(users_file, github)
    )
    github.answers = [Denied()]
    await sign_in_fails(relay, alice, "denied")
    await busy_sign_in(relay, alice)
    assert github.codes_given == 1
    clock.advance(HOUR_MS)
    again = await start_sign_in(relay, alice, now_ms=clock.ms)
    assert (await again.recv())["t"] == "ok"
    await again.close()


async def test_at_most_two_sign_ins_are_in_progress_from_one_address(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.hold = asyncio.Event()
    a = await start_sign_in(relay, alice)
    b = await start_sign_in(relay, bob)
    await busy_sign_in(relay, carol)
    github.hold.set()
    assert (await a.recv())["t"] == "ok"
    assert (await b.recv())["t"] == "ok"
    await a.close()
    await b.close()


async def test_sign_ins_in_progress_on_the_whole_relay_are_limited(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(
        RelayLimits(max_sign_ins=1, max_sign_ins_per_ip=5),
        access=github_access(users_file, github),
    )
    github.hold = asyncio.Event()
    a = await start_sign_in(relay, alice)
    await busy_sign_in(relay, bob)
    github.hold.set()
    assert (await a.recv())["t"] == "ok"
    await a.close()
    # The finished sign-in no longer counts.
    b = await start_sign_in(relay, bob)
    assert (await b.recv())["t"] == "ok"
    await b.close()


async def test_a_sign_in_ends_when_its_connection_closes(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(RelayLimits(max_sign_ins=1), access=github_access(users_file, github))
    github.hold = asyncio.Event()
    a = await start_sign_in(relay, alice)
    await a.close()
    for _ in range(100):
        if not relay._sign_in_tasks:
            break
        await asyncio.sleep(0.01)
    assert relay._sign_in_tasks == set()
    # The closed one no longer counts against the limit.
    b = await start_sign_in(relay, bob)
    github.hold.set()
    assert (await b.recv())["t"] == "ok"
    assert relay.store.key_owner(alice.id) is None
    await b.close()


async def test_stopping_the_relay_ends_sign_ins_in_progress(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    github.hold = asyncio.Event()
    a = await start_sign_in(relay, alice)
    await asyncio.wait_for(relay.stop(), 3)
    with pytest.raises(ConnectionClosed):
        await a.recv()


async def test_a_user_taken_out_of_the_file_is_disconnected_and_their_mailboxes_deleted(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    a = await start_sign_in(relay, alice)
    assert (await a.recv())["t"] == "ok"
    github.user = GitHubUser("bob", 202)
    b = await start_sign_in(relay, bob)
    assert (await b.recv())["t"] == "ok"
    await a.allow(bob)
    await b.allow(alice)
    assert (await b.deposit(alice))["t"] == "deposited"

    write_keys(users_file, "bob 202")
    relay.reload_access()

    assert await close_code(a.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(alice.id)
    assert relay.store.usage(alice.id, 0).messages == 0
    assert (await b.deposit(alice))["reason"] == "not-allowed"
    # The key stays refused; it is not asked to sign in again.
    again = await login(relay, alice, expect_ok=False)
    assert await close_code(again.ws) == (4003, "not permitted")
    await b.close()


async def test_pinning_another_id_in_the_file_disconnects_the_account_that_signed_in(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    a = await start_sign_in(relay, alice)
    assert (await a.recv())["t"] == "ok"
    write_keys(users_file, "alice 555", "bob 202")
    relay.reload_access()
    assert await close_code(a.ws) == (4003, "not permitted")
    assert not relay.store.has_mailbox(alice.id)


async def test_a_users_file_with_a_bad_line_changes_nothing(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    access = github_access(users_file, github)
    relay = await start_relay(access=access)
    a = await start_sign_in(relay, alice)
    assert (await a.recv())["t"] == "ok"
    write_keys(users_file, "bob 202", "not a user")
    relay.reload_access()
    assert access.users == {"alice": None, "bob": 202}
    await a.allow(bob)  # still connected
    await a.close()


async def test_the_relay_notices_a_changed_users_file_by_itself(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub
) -> None:
    relay = await start_relay(
        RelayLimits(access_check_interval_s=0.05), access=github_access(users_file, github)
    )
    a = await start_sign_in(relay, alice)
    assert (await a.recv())["t"] == "ok"
    write_keys(users_file, "bob")
    assert await close_code(a.ws) == (4003, "not permitted")


async def test_starting_in_github_mode_deletes_the_mailboxes_of_users_no_longer_listed(
    start_relay: RelayFactory, users_file: str, github: FakeGitHub, data_dir: str
) -> None:
    relay = await start_relay(access=github_access(users_file, github))
    a = await start_sign_in(relay, alice)
    assert (await a.recv())["t"] == "ok"
    await relay.stop()
    write_keys(users_file, "bob 202")
    restarted = await start_relay(access=github_access(users_file, github))
    assert not restarted.store.has_mailbox(alice.id)
    assert restarted.store.key_owner(alice.id) == KeyOwner(101, "alice")
    again = await login(restarted, alice, expect_ok=False)
    assert await close_code(again.ws) == (4003, "not permitted")
