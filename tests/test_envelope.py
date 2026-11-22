from collections.abc import Callable
from dataclasses import replace
from typing import Any, cast

import pytest

from squawk.crypto import ed25519_random_secret_key
from squawk.encoding import from_base64url, to_base64url
from squawk.envelope import (
    Envelope,
    EnvelopeError,
    EnvelopeErrorCode,
    EnvelopeValidationError,
    ReplayGuard,
    Sealed,
    create_envelope,
    create_receipt,
    open_sealed,
    parse_envelope,
    parse_receipt,
    seal,
)
from squawk.identity import Identity, identity_from_secret_key
from squawk.jsontext import parse, stringify
from squawk.timefmt import iso_from_ms, parse_iso_ms


def make_identity(name: str) -> Identity:
    return identity_from_secret_key(name, ed25519_random_secret_key())


alice = make_identity("alice")
bob = make_identity("bob")
carol = make_identity("carol")
mallory = make_identity("mallory")

NOW = cast(int, parse_iso_ms("2026-11-21T12:00:00.000Z"))


def clock() -> int:
    return NOW


def message(**overrides: Any) -> Envelope:
    fields: dict[str, Any] = {
        "from_": alice.id,
        "to": bob.id,
        "body": "# Hello\n\nAre you **there**?",
        "kind": "question",
        "session": "sess-1",
        "created_at": NOW,
    }
    fields.update(overrides)
    return create_envelope(**fields)


def expect_code(fn: Callable[[], object], code: EnvelopeErrorCode) -> None:
    with pytest.raises(EnvelopeError) as info:
        fn()
    assert info.value.code == code


class TestSealAndOpen:
    def test_round_trips_a_message(self) -> None:
        env = message()
        sealed = seal(env, alice)
        opened = open_sealed(sealed, bob, ReplayGuard(now=clock))
        assert opened == env
        assert opened["thread_id"] == env["id"]

    def test_survives_a_json_round_trip_of_the_sealed_object(self) -> None:
        env = message(in_reply_to="abc", thread_id="t-1")
        wire = parse(stringify(seal(env, alice)))
        assert open_sealed(wire, bob) == env

    def test_does_not_reveal_the_body_or_envelope_outside_the_ciphertext(self) -> None:
        sealed = seal(message(body="secret plans"), alice)
        text = stringify(sealed)
        assert "secret" not in text
        assert "sess-1" not in text
        assert sorted(sealed) == sorted(["ct", "epk", "from", "nonce", "to", "v"])
        assert sealed["from"] == alice.id
        assert sealed["to"] == bob.id

    def test_rejects_a_flipped_bit_in_the_ciphertext_as_tampered(self) -> None:
        sealed = seal(message(), alice)
        ct = bytearray(from_base64url(sealed["ct"]))
        ct[10] ^= 0x01
        tampered: Sealed = {**sealed, "ct": to_base64url(bytes(ct))}
        expect_code(lambda: open_sealed(tampered, bob), "tampered")

    def test_rejects_a_changed_outer_sender_as_tampered(self) -> None:
        sealed = seal(message(), alice)
        expect_code(lambda: open_sealed({**sealed, "from": carol.id}, bob), "tampered")

    def test_rejects_a_message_opened_by_someone_other_than_the_recipient(self) -> None:
        sealed = seal(message(), alice)
        expect_code(lambda: open_sealed(sealed, carol), "wrong_recipient")

    def test_cannot_be_redirected_by_rewriting_the_outer_recipient(self) -> None:
        sealed = seal(message(), alice)
        expect_code(lambda: open_sealed({**sealed, "to": carol.id}, carol), "tampered")

    def test_rejects_a_forged_signature_from_an_attacker_claiming_to_be_another_sender(
        self,
    ) -> None:
        # Mallory encrypts correctly to Bob and names Alice as sender, but can
        # only sign with her own key.
        forged = message(from_=alice.id)
        posing_as_alice = replace(mallory, id=alice.id)
        sealed = seal(forged, posing_as_alice)
        expect_code(lambda: open_sealed(sealed, bob), "bad_signature")

    def test_refuses_to_seal_an_envelope_whose_from_is_not_the_sealing_key(self) -> None:
        expect_code(lambda: seal(message(from_=carol.id), alice), "sender_mismatch")

    def test_rejects_input_that_is_not_a_sealed_message_as_malformed(self) -> None:
        expect_code(lambda: open_sealed({"hello": "world"}, bob), "malformed")
        expect_code(lambda: open_sealed(None, bob), "malformed")
        sealed = seal(message(), alice)
        expect_code(lambda: open_sealed({**sealed, "v": True}, bob), "malformed")
        expect_code(lambda: open_sealed({**sealed, "extra": 1}, bob), "malformed")
        expect_code(lambda: open_sealed({**sealed, "nonce": sealed["epk"]}, bob), "malformed")

    def test_accepts_a_version_written_as_1_point_0(self) -> None:
        # JSON has one number type: 1.0 is the same value as 1.
        sealed = seal(message(), alice)
        assert open_sealed({**sealed, "v": 1.0}, bob)["body"].startswith("# Hello")

    def test_carries_text_outside_ascii(self) -> None:
        env = message(body="caf\u00e9 \u2603 \U0001f600")
        assert open_sealed(seal(env, alice), bob)["body"] == env["body"]


class TestEnvelopeValidation:
    def test_create_envelope_fills_defaults(self) -> None:
        env = create_envelope(from_=alice.id, to=bob.id, body="hi")
        assert env["kind"] == "text"
        assert env["thread_id"] == env["id"]
        assert "session" not in env
        assert "in_reply_to" not in env
        assert parse_iso_ms(env["created_at"]) is not None
        assert env["created_at"].endswith("Z")

    def test_keeps_fields_in_the_same_order_as_the_node_version(self) -> None:
        env = message(in_reply_to="r", thread_id="t")
        shuffled = dict(reversed(list({**env, "sent_at": env["created_at"]}.items())))
        assert list(parse_envelope(shuffled)) == [
            "id",
            "from",
            "to",
            "session",
            "thread_id",
            "in_reply_to",
            "created_at",
            "sent_at",
            "kind",
            "body",
        ]

    @pytest.mark.parametrize(
        "change",
        [
            {"id": ""},
            {"id": "x" * 129},
            {"from": "not-a-key"},
            {"session": None},
            {"session": "s" * 257},
            {"thread_id": ""},
            {"in_reply_to": ""},
            {"created_at": "2026-11-21T12:00:00"},
            {"created_at": "2026-11-21T12:00Z"},
            {"created_at": "2026-02-30T12:00:00Z"},
            {"created_at": "2026-11-21T12:00:00Z\n"},
            {"sent_at": "yesterday"},
            {"kind": "shout"},
            {"body": 5},
            {"extra": "field"},
        ],
    )
    def test_refuses_invalid_envelopes(self, change: dict[str, object]) -> None:
        with pytest.raises(EnvelopeValidationError):
            parse_envelope({**message(), **change})

    def test_counts_lengths_in_utf16_code_units(self) -> None:
        # An emoji is two UTF-16 code units, so 64 of them are 128 units (allowed)
        # and 65 are 130 (refused), although Python counts them as 64 and 65.
        assert parse_envelope({**message(), "id": "\U0001f600" * 64})
        with pytest.raises(EnvelopeValidationError):
            parse_envelope({**message(), "id": "\U0001f600" * 65})

    def test_refuses_a_missing_field(self) -> None:
        env = dict(message())
        del env["body"]
        with pytest.raises(EnvelopeValidationError):
            parse_envelope(env)


class TestReplayGuard:
    def test_rejects_a_replayed_message_id(self) -> None:
        guard = ReplayGuard(now=clock)
        sealed = seal(message(), alice)
        guard.record(open_sealed(sealed, bob, guard))
        expect_code(lambda: open_sealed(sealed, bob, guard), "replay")

    def test_rejects_a_different_message_reusing_an_id(self) -> None:
        guard = ReplayGuard(now=clock)
        first = message()
        guard.record(open_sealed(seal(first, alice), bob, guard))
        second: Envelope = {**message(), "id": first["id"]}
        expect_code(lambda: open_sealed(seal(second, alice), bob, guard), "replay")

    def test_rejects_created_at_more_than_5_minutes_in_the_past_or_future(self) -> None:
        guard = ReplayGuard(now=clock)
        old = message(created_at=NOW - 5 * 60_000 - 1)
        with pytest.raises(EnvelopeError, match="more than 300s from the local clock") as info:
            open_sealed(seal(old, alice), bob, guard)
        assert info.value.code == "stale"
        future = message(created_at=NOW + 5 * 60_000 + 1)
        expect_code(lambda: open_sealed(seal(future, alice), bob, guard), "stale")

    def test_accepts_created_at_within_5_minutes(self) -> None:
        guard = ReplayGuard(now=clock)
        edge = message(created_at=NOW - 5 * 60_000)
        assert open_sealed(seal(edge, alice), bob, guard)["id"] == edge["id"]

    def test_does_not_record_ids_of_messages_that_fail_other_checks(self) -> None:
        guard = ReplayGuard(now=clock)
        old = message(created_at=NOW - 60 * 60_000)
        expect_code(lambda: open_sealed(seal(old, alice), bob, guard), "stale")
        assert not guard.seen.has(f"{alice.id} {old['id']}")

    def test_uses_sent_at_when_present_for_freshness(self) -> None:
        guard = ReplayGuard(now=clock)
        # Written an hour ago, but sealed again just now for a retry.
        queued = message(created_at=NOW - 60 * 60_000)
        resent: Envelope = {**queued, "sent_at": iso_from_ms(NOW)}
        assert open_sealed(seal(resent, alice), bob, guard)["created_at"] == queued["created_at"]
        stale_resend: Envelope = {**queued, "sent_at": iso_from_ms(NOW - 6 * 60_000)}
        expect_code(lambda: open_sealed(seal(stale_resend, alice), bob, guard), "stale")

    def test_reads_times_with_an_offset(self) -> None:
        guard = ReplayGuard(now=clock)
        env: Envelope = {**message(), "created_at": "2026-11-21T13:00:00.000+01:00"}
        assert open_sealed(seal(env, alice), bob, guard)["id"] == env["id"]

    def test_keeps_ids_per_sender_so_one_sender_cannot_block_anothers_message(self) -> None:
        guard = ReplayGuard(now=clock)
        from_alice = message()
        guard.record(open_sealed(seal(from_alice, alice), bob, guard))
        from_carol: Envelope = {**from_alice, "from": carol.id}
        assert open_sealed(seal(from_carol, carol), bob, guard)["id"] == from_alice["id"]

    def test_does_not_record_an_id_until_told_to(self) -> None:
        guard = ReplayGuard(now=clock)
        sealed = seal(message(), alice)
        open_sealed(sealed, bob, guard)
        # Storing failed, so the caller did not record it: the retry is accepted.
        assert "Hello" in open_sealed(sealed, bob, guard)["body"]

    def test_forgets_ids_once_they_are_too_old_to_be_replayed(self) -> None:
        now = NOW
        guard = ReplayGuard(now=lambda: now)
        env = message()
        guard.accept(env)
        # Kept long enough to refuse a replay through a relay (7 days).
        now += 7 * DAY + 10 * 60_000
        guard.prune()
        assert guard.seen.has(f"{alice.id} {env['id']}")
        now += 1
        guard.prune()
        assert not guard.seen.has(f"{alice.id} {env['id']}")


DAY = 24 * 60 * 60_000


class TestRelayedMessages:
    def test_accepts_a_6_day_old_message_that_came_through_a_relay(self) -> None:
        guard = ReplayGuard(now=clock)
        old = message(created_at=NOW - 6 * DAY)
        opened = open_sealed(seal(old, alice), bob, guard, route="relay")
        assert opened["id"] == old["id"]

    def test_refuses_the_same_6_day_old_message_sent_directly(self) -> None:
        guard = ReplayGuard(now=clock)
        old = message(created_at=NOW - 6 * DAY)
        expect_code(lambda: open_sealed(seal(old, alice), bob, guard), "stale")

    def test_refuses_a_replay_of_a_relayed_message_on_either_route(self) -> None:
        now = NOW
        guard = ReplayGuard(now=lambda: now)
        sealed = seal(message(created_at=NOW - 6 * DAY), alice)
        guard.record(open_sealed(sealed, bob, guard, route="relay"))
        # A day later, after pruning, the relay delivers it again.
        now += DAY - 60_000
        guard.prune()
        expect_code(lambda: open_sealed(sealed, bob, guard, route="relay"), "replay")

    def test_refuses_a_relayed_message_older_than_the_relay_keeps_them(self) -> None:
        guard = ReplayGuard(now=clock)
        edge = message(created_at=NOW - 7 * DAY - 5 * 60_000)
        assert open_sealed(seal(edge, alice), bob, guard, route="relay")["id"] == edge["id"]
        too_old = message(created_at=NOW - 7 * DAY - 5 * 60_000 - 1)
        with pytest.raises(EnvelopeError, match="longer ago than a relay keeps") as info:
            open_sealed(seal(too_old, alice), bob, guard, route="relay")
        assert info.value.code == "stale"

    def test_refuses_a_relayed_message_from_the_future(self) -> None:
        guard = ReplayGuard(now=clock)
        future = message(created_at=NOW + 5 * 60_000 + 1)
        expect_code(lambda: open_sealed(seal(future, alice), bob, guard, route="relay"), "stale")


class TestReceipts:
    def test_round_trips_an_ack(self) -> None:
        original = message()
        receipt = create_receipt(from_=bob.id, message=original, status="ack")
        opened = open_sealed(seal(receipt, bob), alice, ReplayGuard(), "relay")
        assert parse_receipt(opened) == {"of": original["id"], "status": "ack", "reason": ""}
        assert opened["thread_id"] == original["thread_id"]
        assert opened["to"] == alice.id

    def test_a_nack_carries_the_reason(self) -> None:
        receipt = create_receipt(
            from_=bob.id, message=message(), status="nack", reason="bad_signature"
        )
        assert parse_receipt(receipt)["reason"] == "bad_signature"

    def test_only_the_recipient_can_make_a_receipt(self) -> None:
        expect_code(
            lambda: create_receipt(from_=carol.id, message=message(), status="ack"),
            "sender_mismatch",
        )

    def test_a_forged_ack_is_refused(self) -> None:
        # The relay (or anyone else) makes an ack that claims to come from Bob,
        # encrypted correctly to Alice, but can only sign with its own key.
        forged = create_receipt(from_=bob.id, message=message(), status="ack")
        posing_as_bob = replace(mallory, id=bob.id)
        expect_code(lambda: open_sealed(seal(forged, posing_as_bob), alice), "bad_signature")

    def test_a_message_that_is_not_a_receipt_is_refused_as_one(self) -> None:
        expect_code(lambda: parse_receipt(message()), "malformed")

    def test_an_ack_with_a_body_is_malformed(self) -> None:
        receipt = create_receipt(from_=bob.id, message=message(), status="ack")
        expect_code(lambda: parse_receipt({**receipt, "body": "hi"}), "malformed")
