"""End to end through a relay on one machine: a real relay server and two
services (Alice's and Bob's) with separate homes, discovery off and no
direct route between them, so everything goes through the relay. People
pair with `squawk invite` and `squawk pair --code`; messages go through the
real `squawk send` and `squawk reply` commands into fake Claude Code
sessions. Bob's service is stopped and started again, and so is the relay.
"""

import asyncio
import os
import re
import shutil
import tempfile
from collections.abc import AsyncIterator, Callable

import pytest

from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.daemon import Daemon
from squawk.identity import init_identity
from squawk.network import NetworkTransport
from squawk.pairing import Pairing
from squawk.relay import RelayServer
from squawk.relay.access import AccessPolicy, GitHubAccess
from squawk.relay.github import DeviceCode, GitHubUser, PollAnswer, Token
from squawk.relay_client import RelayClient
from test_e2e import Person, World, always_send, body_of, msg_id_of, wait_for


class RelayWorld(World):
    def __init__(self, relay_dir: str, access: AccessPolicy | None = None) -> None:
        super().__init__()
        self.relay_dir = relay_dir
        self.access = access
        self.relay: RelayServer | None = None
        self.relay_port = 0

    async def start_relay(self) -> None:
        self.relay = RelayServer(self.relay_dir, port=self.relay_port, access=self.access)
        await self.relay.start()
        self.relay_port = self.relay.port

    async def stop_relay(self) -> None:
        assert self.relay is not None
        await self.relay.stop()
        self.relay = None

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.relay_port}"

    async def person(self, name: str, *, connect: bool = True) -> Person:
        home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
        self.homes.append(home)
        init_identity(home, name)
        return await self.start_service(name, home, connect=connect)

    async def start_service(self, name: str, home: str, *, connect: bool = True) -> Person:
        notes: list[tuple[str, str]] = []
        relay = RelayClient(
            self.url,
            allow_plain=True,
            backoff_min_ms=50,
            backoff_max_ms=200,
            allow_check_interval_ms=50,
        )
        transport = NetworkTransport(
            host="127.0.0.1",
            discovery=False,
            retry_interval_ms=50,
            ack_timeout_ms=2000,
            handshake_timeout_ms=2000,
            relay=relay,
        )
        daemon = Daemon(
            home, transport=transport, notify=lambda title, text: notes.append((title, text))
        )
        await daemon.start()
        # Contacts may see every session, as in test_e2e.py.
        daemon.change_session_patterns("allow", "*")
        pairing = Pairing(daemon, transport, timeout_ms=5000)
        pairing.start()
        # No direct address: the other service can reach this one only through the relay.
        person = Person(name, home, daemon, pairing, "", notes)
        self.people.append(person)
        if connect:
            await wait_for(lambda: relay.connected)
        return person

    async def stop_service(self, person: Person) -> None:
        person.pairing.stop()
        await person.daemon.stop()
        self.people.remove(person)

    async def restart_service(self, person: Person) -> Person:
        await self.stop_service(person)
        return await self.start_service(person.name, person.home)


def relay_of(person: Person) -> RelayClient:
    transport = person.daemon.transport
    assert isinstance(transport, NetworkTransport) and transport.relay is not None
    return transport.relay


async def _run_world(w: RelayWorld) -> AsyncIterator[RelayWorld]:
    await w.start_relay()
    try:
        yield w
    finally:
        for person in list(w.people):
            person.pairing.stop()
            await person.daemon.stop()
        await w.inboxes.close()
        if w.relay is not None:
            await w.relay.stop()
        for home in w.homes:
            shutil.rmtree(home, ignore_errors=True)


@pytest.fixture
async def world(tmp_path: object) -> AsyncIterator[RelayWorld]:
    async for w in _run_world(RelayWorld(os.path.join(str(tmp_path), "relay"))):
        yield w


class FakeGitHub:
    """Stands in for GitHub: the person approves at once, as `user`."""

    def __init__(self) -> None:
        self.user = GitHubUser("alice", 101)

    async def request_device_code(self) -> DeviceCode:
        return DeviceCode(
            device_code="device-secret",
            user_code="ABCD-1234",
            verification_uri="https://github.com/login/device",
            expires_in=900,
            interval=5,
        )

    async def poll_token(self, device_code: str) -> PollAnswer:
        return Token("gho_token")

    async def read_user(self, token: str) -> GitHubUser:
        return self.user


async def _no_wait(_seconds: float) -> None:
    await asyncio.sleep(0)


@pytest.fixture
def github() -> FakeGitHub:
    return FakeGitHub()


@pytest.fixture
async def github_world(tmp_path: object, github: FakeGitHub) -> AsyncIterator[RelayWorld]:
    users = os.path.join(str(tmp_path), "allowed-users")
    with open(users, "w", encoding="utf-8") as file:
        file.write("alice\nbob\n")
    access = GitHubAccess(users, github, sleep=_no_wait)
    async for w in _run_world(RelayWorld(os.path.join(str(tmp_path), "relay"), access)):
        yield w


async def test_two_people_on_different_networks_talk_through_the_relay(
    world: RelayWorld,
) -> None:
    alice = await world.person("alice")
    bob = await world.person("bob")

    # Pairing by invite: Alice reads her code to Bob, who joins with it.
    out: list[str] = []
    io = CliIo(
        stdout=out.append,
        stderr=out.append,
        env={"SQUAWK_HOME": alice.home},
        ask=lambda _prompt: _yes(),
        confirm=always_send,
    )
    inviting = asyncio.ensure_future(run(["invite"], io))
    found = await wait_for(lambda: re.search(r"Invite code: (\S+)", "".join(out)))
    joined = await world.cli(bob, "pair", "--code", found.group(1))
    assert joined.code == 0, joined.err
    assert await inviting == 0, "".join(out)
    assert 'Paired with "alice"' in joined.out
    assert 'Paired with "bob"' in "".join(out)
    contact = alice.daemon.store.get_contact(bob.daemon.identity.id)
    assert contact is not None and contact.relay_url == world.url

    bob_api, _ = await world.open_session(bob, "api", "/tmp/no-repo/api", "b-1")
    alice_a, _ = await world.open_session(alice, "a", "/tmp/no-repo/work", "a-1")

    # Alice lists Bob's sessions through the relay.
    listed = await world.cli(alice, "sessions", "bob")
    assert listed.code == 0, listed.err
    assert listed.out == "bob's open sessions:\nLABEL  BRANCH\napi    -\n"

    # A question to Bob's session and his reply, both through the relay.
    sent = await world.cli(alice, "send", "bob", "is the build green?", "--session", "api",
                           session=alice_a)  # fmt: skip
    assert sent.code == 0, sent.err
    assert "delivered to their squawk service" in sent.out
    [received] = await wait_for(lambda: bob_api.messages or None)
    assert body_of(received) == "is the build green?"
    # The text Bob's session gets does not claim a route the message did not take.
    assert "local network" not in received
    replied = await world.cli(bob, "reply", msg_id_of(received), "yes, green", session=bob_api)
    assert replied.code == 0, replied.err
    assert "delivered to their squawk service" in replied.out
    [answer] = await wait_for(lambda: alice_a.messages or None)
    assert body_of(answer) == "yes, green"

    # Bob goes offline. Alice's next message waits at the relay.
    bob_home_person = bob
    await world.stop_service(bob)
    offline = await world.cli(alice, "sessions", "bob")
    assert offline.code != 0
    assert "bob is offline" in offline.err
    # Discovery is off, so the local-network attempt only found nothing:
    # the error does not repeat that in brackets.
    assert "not on the network)" not in offline.err
    waiting = await world.cli(alice, "send", "bob", "ping while you were away")
    assert waiting.code == 0, waiting.err
    assert "waiting at the relay" in waiting.out
    waiting_id = re.search(r"msg_id=(\S+)", waiting.out)
    assert waiting_id is not None
    held = alice.daemon.store.get_message(waiting_id.group(1))
    assert held is not None and held.state == "sent"

    # The relay restarts while the message waits, then Bob comes back: the
    # message survives, reaches Bob, and Alice gets Bob's receipt.
    await world.stop_relay()
    await wait_for(lambda: not relay_of(alice).connected)
    await world.start_relay()
    await wait_for(lambda: relay_of(alice).connected)
    bob = await world.start_service("bob", bob_home_person.home)
    arrived = await wait_for(lambda: bob.daemon.store.get_message(waiting_id.group(1)))
    assert arrived.body == "ping while you were away"
    await wait_for(lambda: alice.daemon.store.acked_at(waiting_id.group(1)))
    assert alice.daemon.store.count_relayed() == 0

    # Bob, back online, can send again.
    back = await world.cli(bob, "send", "alice", "back now")
    assert back.code == 0, back.err
    assert "delivered to their squawk service" in back.out
    for inbox in (alice_a, bob_api):
        assert inbox.problems == []


async def _yes() -> str:
    return "y"


def _needs_sign_in(person: Person) -> Callable[[], bool]:
    return lambda: relay_of(person).access_problem == "needs-sign-in"


def _connected(person: Person) -> Callable[[], bool]:
    return lambda: relay_of(person).connected


async def _pair_by_invite(world: RelayWorld, alice: Person, bob: Person) -> None:
    out: list[str] = []
    io = CliIo(
        stdout=out.append,
        stderr=out.append,
        env={"SQUAWK_HOME": alice.home},
        ask=lambda _prompt: _yes(),
        confirm=always_send,
    )
    inviting = asyncio.ensure_future(run(["invite"], io))
    found = await wait_for(lambda: re.search(r"Invite code: (\S+)", "".join(out)))
    joined = await world.cli(bob, "pair", "--code", found.group(1))
    assert joined.code == 0, joined.err
    assert await inviting == 0, "".join(out)


async def test_people_sign_in_with_github_then_pair_and_talk_through_the_relay(
    github_world: RelayWorld, github: FakeGitHub
) -> None:
    world = github_world
    alice = await world.person("alice", connect=False)
    bob = await world.person("bob", connect=False)
    for person in (alice, bob):
        await wait_for(_needs_sign_in(person))
    status = await world.cli(alice, "relay", "status")
    assert f"Relay:           {world.url} (needs sign-in: run `squawk relay login`)" in status.out

    for person, user in ((alice, GitHubUser("alice", 101)), (bob, GitHubUser("Bob", 202))):
        github.user = user
        signed = await world.cli(person, "relay", "login")
        assert signed.code == 0, signed.err
        assert signed.out == (
            "Open https://github.com/login/device and enter ABCD-1234 (valid for 15 minutes).\n"
            "GitHub should ask only to read your public profile. If it asks for\n"
            "anything more, deny it: the relay should never need more.\n"
            f"Signed in to the relay as {user.login}\n"
        )
        await wait_for(_connected(person))
    assert relay_of(alice).access_problem is None

    again = await world.cli(alice, "relay", "login")
    assert again.code == 0, again.err
    assert "no sign-in is needed" in again.out

    await _pair_by_invite(world, alice, bob)
    there = await world.cli(alice, "send", "bob", "signed in and paired")
    assert there.code == 0, there.err
    assert "delivered to their squawk service" in there.out
    back = await world.cli(bob, "send", "alice", "and back")
    assert back.code == 0, back.err
    assert "delivered to their squawk service" in back.out

    # A restarted service is let in without signing in again.
    bob = await world.restart_service(bob)
    assert relay_of(bob).connected


async def test_a_github_user_not_listed_is_refused(
    github_world: RelayWorld, github: FakeGitHub
) -> None:
    carol = await github_world.person("carol", connect=False)
    github.user = GitHubUser("carol", 303)
    refused = await github_world.cli(carol, "relay", "login")
    assert refused.code == 1
    assert "Open https://github.com/login/device and enter ABCD-1234" in refused.out
    assert refused.err == (
        "squawk relay login: the relay does not permit this GitHub account; "
        "ask the person who runs it\n"
    )
    await wait_for(lambda: relay_of(carol).access_problem == "not-permitted")
    status = await github_world.cli(carol, "relay", "status")
    assert "(not permitted by this relay; ask the person who runs it)" in status.out


async def test_relay_login_without_a_relay_or_service(world: RelayWorld) -> None:
    alice = await world.person("alice")
    already = await world.cli(alice, "relay", "login")
    assert already.code == 0, already.err
    assert "no sign-in is needed" in already.out
    await world.cli(alice, "relay", "set", "--off")
    none = await world.cli(alice, "relay", "login")
    assert none.code == 1
    assert "no relay is set" in none.err
