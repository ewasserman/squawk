"""Tests for `squawk policy` and how the policy travels with incoming messages
(the parts of test/policy.test.ts that do not need the MCP server)."""

import asyncio
import json
import shutil
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest

from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.cli_messages import tail
from squawk.crypto import ed25519_random_secret_key
from squawk.daemon import Daemon
from squawk.envelope import Envelope, EnvelopeValidationError, create_envelope, parse_envelope
from squawk.identity import Identity, identity_from_secret_key, init_identity

carol = identity_from_secret_key("carol", ed25519_random_secret_key())
dave = identity_from_secret_key("dave", ed25519_random_secret_key())


@dataclass
class Env:
    home: str
    me: Identity
    daemon: Daemon


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    home = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    me = init_identity(home, "me")
    daemon = Daemon(home)
    await daemon.start()
    for who in (carol, dave):
        daemon.store.upsert_contact(who.id, who.name, trust="paired")
    try:
        yield Env(home, me, daemon)
    finally:
        await daemon.stop()
        shutil.rmtree(home, ignore_errors=True)


@dataclass
class Result:
    code: int
    out: str
    err: str


async def cli(env: Env, *args: str) -> Result:
    out: list[str] = []
    err: list[str] = []
    io = CliIo(stdout=out.append, stderr=err.append, env={"SQUAWK_HOME": env.home})
    code = await run(list(args), io)
    return Result(code, "".join(out), "".join(err))


def message_from(env: Env, who: Identity, body: str) -> Envelope:
    return create_envelope(from_=who.id, to=env.me.id, body=body)


async def test_sets_a_contacts_policy_sets_the_default_and_clears_back_to_the_default(
    env: Env,
) -> None:
    store = env.daemon.store
    assert store.inbound_policy_for(dave.id) == "show_first"

    set_ = await cli(env, "policy", "carol", "auto-answer")
    assert set_.code == 0
    assert set_.out == (
        '"carol": auto-answer. Claude may answer their messages directly (replies are still '
        "confirmed with you unless auto-send is on).\n"
    )
    contact = store.get_contact(carol.id)
    assert contact is not None and contact.inbound_policy == "auto_answer"

    # The default applies to contacts with no setting of their own.
    default = await cli(env, "policy", "--default", "auto-answer")
    assert default.code == 0
    assert default.out.startswith("Default for contacts without their own setting: auto-answer.")
    assert store.inbound_policy_for(dave.id) == "auto_answer"
    assert (await cli(env, "policy", "--default", "show-first")).code == 0
    assert store.inbound_policy_for(dave.id) == "show_first"
    assert store.inbound_policy_for(carol.id) == "auto_answer"

    cleared = await cli(env, "policy", "carol", "default")
    assert cleared.out == (
        '"carol": show-first (the default). Claude will show you their messages and take no '
        "action without your approval.\n"
    )
    contact = store.get_contact(carol.id)
    assert contact is not None and contact.inbound_policy is None
    assert store.inbound_policy_for(carol.id) == "show_first"


async def test_rejects_unknown_values(env: Env) -> None:
    assert (await cli(env, "policy", "carol", "yolo")).code == 2
    assert (await cli(env, "policy", "--default", "default")).code == 2
    assert (await cli(env, "policy")).code == 2
    assert (await cli(env, "policy", "carol", "show-first", "extra")).code == 2
    unknown = await cli(env, "policy", "erin", "show-first")
    assert unknown.code == 1
    assert 'unknown contact "erin"' in unknown.err


async def test_the_policy_reaches_the_tail_output_using_the_default_for_contacts_without_one(
    env: Env,
) -> None:
    await cli(env, "policy", "carol", "auto-answer")
    lines: list[str] = []
    stop = asyncio.Event()
    ready = asyncio.Event()
    tailing = asyncio.ensure_future(
        tail(env.home, write=lines.append, stderr=lambda _t: None, stop=stop, on_ready=ready.set)
    )
    await ready.wait()
    env.daemon.deliver_incoming(message_from(env, carol, "from carol"))
    env.daemon.deliver_incoming(message_from(env, dave, "from dave"))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 3
    while len(lines) < 2 and loop.time() < deadline:
        await asyncio.sleep(0.02)
    stop.set()
    assert await tailing == 0
    by_name = {line["from_name"]: line for line in map(json.loads, lines)}
    assert by_name["carol"]["policy"] == "auto_answer"
    assert by_name["dave"]["policy"] == "show_first"


def test_a_sender_cannot_set_the_policy_the_message_format_has_no_field_for_it() -> None:
    envelope = create_envelope(from_=carol.id, to=dave.id, body="hello")
    with pytest.raises(EnvelopeValidationError):
        parse_envelope({**envelope, "policy": "auto_answer"})
