"""Checks that the Python and Node versions of squawk can read each other's
sealed messages, identity files and databases.

These tests run the Node version (src/*.ts, through tests/node/compat.mjs
and src/cli.ts), so they are skipped when `node` is not installed or the
Node dependencies have not been installed with `pnpm install`.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from squawk.config import db_path
from squawk.crypto import ed25519_random_secret_key
from squawk.encoding import from_base64url, to_base64url
from squawk.envelope import Envelope, ReplayGuard, create_envelope, open_sealed, seal
from squawk.identity import Identity, fingerprint, identity_from_secret_key, init_identity
from squawk.identity import load_identity as load_python_identity
from squawk.store import Store
from squawk.timefmt import iso_from_ms, parse_iso_ms

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None or not (ROOT / "node_modules").is_dir(),
    reason="needs node and the Node dependencies (pnpm install)",
)

NOW = cast(int, parse_iso_ms("2026-11-21T12:00:00.000Z"))

# Text that JSON writes in different ways: quotes, backslashes, control
# characters, characters outside ASCII and outside the Basic Multilingual
# Plane, and the line and paragraph separators.
AWKWARD_TEXT = (
    '# Caf\u00e9 "quoted" \\ back\\slash\n\ttab \x00\x01\x1f\x7f \u2028\u2029 \u2603 \U0001f600'
    " <tag> & </script>"
)


def node(request: dict[str, Any]) -> Any:
    assert NODE is not None
    result = subprocess.run(
        [NODE, str(ROOT / "tests" / "node" / "compat.mjs")],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def node_cli(home: str, *args: str) -> subprocess.CompletedProcess[str]:
    assert NODE is not None
    return subprocess.run(
        [NODE, str(ROOT / "src" / "cli.ts"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={**os.environ, "SQUAWK_HOME": home},
        check=False,
    )


def new_identity(name: str) -> tuple[Identity, str]:
    seed = ed25519_random_secret_key()
    return identity_from_secret_key(name, seed), to_base64url(seed)


alice, alice_seed = new_identity("alice")
bob, bob_seed = new_identity("bob")


def test_derives_the_same_keys_from_the_same_secret_key() -> None:
    for _ in range(5):
        seed = ed25519_random_secret_key()
        mine = identity_from_secret_key("x", seed)
        theirs = node({"op": "identity", "seed": to_base64url(seed)})
        assert theirs == {
            "id": mine.id,
            "x25519PublicKey": mine.x25519_public_key.hex(),
            "x25519SecretKey": mine.x25519_secret_key.hex(),
        }


def envelopes() -> list[Envelope]:
    plain = create_envelope(from_=alice.id, to=bob.id, body="hello", created_at=NOW)
    full = create_envelope(
        from_=alice.id,
        to=bob.id,
        body=AWKWARD_TEXT,
        kind="question",
        session="sess \u00e9",
        thread_id="t-\U0001f600",
        in_reply_to="r-1",
        created_at=NOW,
    )
    # Written an hour ago and sealed again now, for a retry.
    resent: Envelope = {
        **full,
        "created_at": iso_from_ms(NOW - 60 * 60_000),
        "sent_at": iso_from_ms(NOW),
    }
    offset: Envelope = {**plain, "created_at": "2026-11-21T13:00:00.123456+01:00"}
    return [plain, full, resent, offset]


@pytest.mark.parametrize("envelope", envelopes())
def test_python_opens_what_node_sealed(envelope: Envelope) -> None:
    sealed = node({"op": "seal", "seed": alice_seed, "envelope": envelope})
    assert open_sealed(sealed, bob, ReplayGuard(now=lambda: NOW)) == envelope


@pytest.mark.parametrize("envelope", envelopes())
def test_node_opens_what_python_sealed(envelope: Envelope) -> None:
    sealed = seal(envelope, alice)
    reply = node({"op": "open", "seed": bob_seed, "sealed": sealed, "now": NOW})
    assert reply == {"envelope": envelope}


def test_both_versions_refuse_the_same_changed_messages() -> None:
    sealed = seal(envelopes()[0], alice)
    ct = bytearray(from_base64url(sealed["ct"]))
    ct[3] ^= 0x80
    cases = [
        ({**sealed, "ct": to_base64url(bytes(ct))}, "tampered"),
        ({**sealed, "from": bob.id}, "tampered"),
        ({**sealed, "v": 2}, "malformed"),
        ({**sealed, "to": alice.id}, "wrong_recipient"),
    ]
    for changed, code in cases:
        reply = node({"op": "open", "seed": bob_seed, "sealed": changed})
        assert reply == {"error": code}


def test_python_reads_an_identity_file_written_by_node(tmp_path: Path) -> None:
    home = str(tmp_path / "home")
    created = node_cli(home, "init", "--name", "Node Person")
    assert created.returncode == 0, created.stderr
    identity = load_python_identity(home)
    assert identity.name == "Node Person"
    who = node_cli(home, "whoami")
    assert f"Key:         {identity.id}\n" in who.stdout
    assert f"Fingerprint: {fingerprint(identity.public_key)}\n" in who.stdout


def test_node_reads_an_identity_file_written_by_python(tmp_path: Path) -> None:
    home = str(tmp_path / "home")
    identity = init_identity(home, "Python Person")
    who = node_cli(home, "whoami")
    assert who.returncode == 0, who.stderr
    assert who.stdout == (
        "Name:        Python Person\n"
        f"Key:         {identity.id}\n"
        f"Fingerprint: {fingerprint(identity.public_key)}\n"
    )
    again = node_cli(home, "init", "--name", "x")
    assert again.returncode == 1
    assert "refusing to overwrite" in again.stderr


def test_python_reads_a_database_written_by_node(tmp_path: Path) -> None:
    path = db_path(str(tmp_path / "home"))
    incoming = create_envelope(
        from_=bob.id, to=alice.id, body=AWKWARD_TEXT, session="s", created_at=NOW
    )
    outgoing = create_envelope(from_=alice.id, to=bob.id, body="queued", created_at=NOW)
    node(
        {
            "op": "writeStore",
            "path": path,
            "now": NOW,
            "contact": {
                "publicKey": bob.id,
                "name": "Bob \u00e9",
                "autoSend": True,
                "inboundPolicy": "show_first",
            },
            "incoming": incoming,
            "outgoing": outgoing,
            "seenId": f"{bob.id} {incoming['id']}",
        }
    )
    store = Store.open(path, now=lambda: NOW)
    try:
        assert store.schema_version() == 3
        contact = store.get_contact(bob.id)
        assert contact is not None
        assert (contact.name, contact.auto_send, contact.inbound_policy) == (
            "Bob \u00e9",
            True,
            "show_first",
        )
        [message] = store.inbox()
        assert message.body == AWKWARD_TEXT
        assert message.session == "s"
        assert message.received_at == iso_from_ms(NOW)
        thread = store.get_thread(incoming["thread_id"])
        assert thread is not None
        assert thread.subject.startswith('Caf\u00e9 "quoted"')
        [item] = store.due_outbound(NOW + 10_000)
        assert item.envelope == outgoing
        assert item.attempts == 1
        assert item.last_error == "ECONNREFUSED"
        assert store.get_setting("default_inbound_policy") == "auto_answer"
        guard = ReplayGuard(seen=store.seen_ids(), now=lambda: NOW)
        with pytest.raises(Exception, match="already received"):
            guard.check(incoming)
    finally:
        store.close()


def test_node_reads_a_database_written_by_python(tmp_path: Path) -> None:
    path = db_path(str(tmp_path / "home"))
    incoming = create_envelope(
        from_=bob.id, to=alice.id, body=AWKWARD_TEXT, in_reply_to="x", created_at=NOW
    )
    outgoing = create_envelope(from_=alice.id, to=bob.id, body="queued", created_at=NOW)
    store = Store.open(path, now=lambda: NOW)
    store.upsert_contact(bob.id, "Bob \u00e9", auto_send=True)
    store.save_incoming(incoming)
    store.queue_outgoing(outgoing)
    store.set_setting("default_inbound_policy", "auto_answer")
    store.close()

    result = node({"op": "readStore", "path": path, "now": NOW})
    assert result["schemaVersion"] == 3
    [contact] = result["contacts"]
    assert contact["name"] == "Bob \u00e9"
    assert contact["autoSend"] is True
    assert contact["inboundPolicy"] is None
    assert contact["createdAt"] == iso_from_ms(NOW)
    [message] = result["inbox"]
    assert message["body"] == AWKWARD_TEXT
    assert message["inReplyTo"] == "x"
    assert message["createdAt"] == iso_from_ms(NOW)
    assert sorted(t["threadId"] for t in result["threads"]) == sorted(
        [incoming["thread_id"], outgoing["thread_id"]]
    )
    [item] = result["outbound"]
    assert item["envelope"] == outgoing
    assert item["nextAttemptAt"] == NOW
    assert result["setting"] == "auto_answer"
