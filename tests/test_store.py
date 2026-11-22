import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from squawk.config import db_path
from squawk.crypto import ed25519_random_secret_key
from squawk.envelope import (
    Envelope,
    EnvelopeError,
    ReplayGuard,
    create_envelope,
    open_sealed,
    seal,
)
from squawk.identity import identity_from_secret_key
from squawk.store import MIGRATIONS, Store, subject_of
from squawk.timefmt import iso_from_ms, parse_iso_ms

alice = identity_from_secret_key("alice", ed25519_random_secret_key())
bob = identity_from_secret_key("bob", ed25519_random_secret_key())

START = cast(int, parse_iso_ms("2026-11-21T12:00:00.000Z"))


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> int:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def path(tmp_path: Path) -> str:
    return db_path(str(tmp_path / "home"))


@pytest.fixture
def store(path: str, clock: Clock) -> Iterator[Store]:
    s = Store.open(path, now=clock)
    yield s
    s.close()


def outgoing(clock: Clock, body: str = "Hello Bob", **extra: Any) -> Envelope:
    fields: dict[str, Any] = {
        "from_": alice.id,
        "to": bob.id,
        "body": body,
        "created_at": clock.now,
    }
    fields.update(extra)
    return create_envelope(**fields)


def mode(file: str) -> int:
    return stat.S_IMODE(os.stat(file).st_mode)


def test_creates_the_database_file_with_mode_0600(store: Store, path: str) -> None:
    assert mode(path) == 0o600


def test_creates_sqlites_companion_files_with_mode_0600_too(store: Store, path: str) -> None:
    store.upsert_contact(bob.id, "bob")
    for suffix in ["-wal", "-shm"]:
        assert mode(path + suffix) == 0o600


def test_tightens_files_left_open_by_an_older_version(path: str, clock: Clock) -> None:
    os.makedirs(os.path.dirname(path))
    sqlite3.connect(path).close()
    os.chmod(path, 0o644)
    Store.open(path, now=clock).close()
    assert mode(path) == 0o600


def test_skips_a_migration_that_another_process_applied_first(store: Store) -> None:
    # This process read version 1 before another process finished
    # migrating, so its first read is out of date. Applying migration 2
    # again would fail with "duplicate column name".
    actual = store.schema_version
    first = True

    def stale_once() -> int:
        nonlocal first
        if first:
            first = False
            return 1
        return actual()

    store.schema_version = stale_once  # type: ignore[method-assign]
    store.migrate()
    assert actual() == len(MIGRATIONS)


def test_rolls_back_a_failed_transaction(store: Store) -> None:
    def fail() -> None:
        store.set_setting("k", "v")
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        store.transaction(fail)
    assert store.get_setting("k") is None
    assert not store.db.in_transaction


def test_marks_messages_failed_when_they_have_waited_too_long(store: Store, clock: Clock) -> None:
    env = outgoing(clock)
    store.queue_outgoing(env)
    assert store.fail_expired(60_000) == []
    clock.now += 60_001
    assert store.fail_expired(60_000) == [env["id"]]
    assert store.get_outbound(env["id"]) is None
    message = store.get_message(env["id"])
    assert message is not None
    assert message.state == "failed"


def test_reports_incoming_ids_and_threads_that_belong_to_someone_else(
    store: Store, clock: Clock
) -> None:
    carol = identity_from_secret_key("carol", ed25519_random_secret_key())
    mine = create_envelope(from_=bob.id, to=alice.id, body="hi")
    store.save_incoming(mine)
    # The same message again from the same sender is not a conflict.
    assert store.incoming_conflict(mine) is None
    assert store.incoming_conflict({**mine, "from": carol.id}) == "message id already in use"
    into_thread = create_envelope(
        from_=carol.id, to=alice.id, body="me too", thread_id=mine["thread_id"]
    )
    assert store.incoming_conflict(into_thread) == "thread id already in use"
    sent = outgoing(clock)
    store.save_outgoing(sent)
    assert store.incoming_conflict({**sent, "from": bob.id}) == "message id already in use"


def test_applies_migrations_once_and_is_unchanged_on_reopen(
    store: Store, path: str, clock: Clock
) -> None:
    assert store.schema_version() == len(MIGRATIONS)
    store.upsert_contact(bob.id, "bob")
    store.close()
    reopened = Store.open(path, now=clock)
    try:
        assert reopened.schema_version() == len(MIGRATIONS)
        reopened.migrate()
        assert reopened.schema_version() == len(MIGRATIONS)
        contact = reopened.get_contact(bob.id)
        assert contact is not None
        assert contact.name == "bob"
    finally:
        reopened.close()


def test_works_in_memory(clock: Clock) -> None:
    s = Store.open(":memory:", now=clock)
    assert s.schema_version() == len(MIGRATIONS)
    s.close()


def test_queues_a_message_and_returns_it_when_due(store: Store, clock: Clock) -> None:
    env = outgoing(clock)
    store.queue_outgoing(env)

    due = store.due_outbound()
    assert len(due) == 1
    [item] = due
    assert item.message_id == env["id"]
    assert item.recipient == bob.id
    assert item.attempts == 0
    assert item.envelope == env
    message = store.get_message(env["id"])
    assert message is not None
    assert message.state == "queued"
    assert store.count_outbound() == 1


def test_backs_off_after_a_failed_attempt(store: Store, clock: Clock) -> None:
    env = outgoing(clock)
    store.queue_outgoing(env)

    first = store.record_attempt(env["id"], error="ECONNREFUSED")
    assert first == clock.now + 2_000
    assert len(store.due_outbound()) == 0
    assert len(store.due_outbound(first)) == 1

    second = store.record_attempt(env["id"])
    assert second == clock.now + 4_000
    item = store.get_outbound(env["id"])
    assert item is not None
    assert item.attempts == 2
    assert item.last_error is None

    store.record_attempt(env["id"], next_attempt_at=clock.now + 99)
    item = store.get_outbound(env["id"])
    assert item is not None
    assert item.next_attempt_at == clock.now + 99

    with pytest.raises(KeyError, match="is not in the outbound queue"):
        store.record_attempt("nope")


def test_caps_the_retry_delay(path: str, clock: Clock, tmp_path: Path) -> None:
    s = Store.open(str(tmp_path / "capped.db"), now=clock, retry_base_ms=1_000, retry_max_ms=3_000)
    env = outgoing(clock)
    s.queue_outgoing(env)
    delays = [s.record_attempt(env["id"]) - clock.now for _ in range(4)]
    assert delays == [1_000, 2_000, 3_000, 3_000]
    s.close()


def test_marking_a_message_acknowledged_removes_it_from_the_queue(
    store: Store, clock: Clock
) -> None:
    env = outgoing(clock)
    store.queue_outgoing(env)

    assert store.mark_acknowledged(env["id"]) is True
    assert len(store.due_outbound()) == 0
    assert store.get_outbound(env["id"]) is None
    assert store.acked_at(env["id"]) == iso_from_ms(clock.now)
    message = store.get_message(env["id"])
    assert message is not None
    assert message.state == "acked"
    assert message.sent_at is not None
    assert store.mark_acknowledged(env["id"]) is False


def test_lists_a_thread_in_order_and_tracks_the_thread_record(store: Store, clock: Clock) -> None:
    first = outgoing(clock, "# Deploy plan\n\nCan you review?", kind="question")
    store.save_outgoing(first, "sent")
    clock.now += 1_000
    reply = create_envelope(
        from_=bob.id,
        to=alice.id,
        body="Looks fine.",
        kind="answer",
        thread_id=first["thread_id"],
        in_reply_to=first["id"],
        created_at=clock.now,
    )
    assert store.save_incoming(reply) is True
    assert store.save_incoming(reply) is False

    thread = store.list_thread(first["thread_id"])
    assert [m.id for m in thread] == [first["id"], reply["id"]]
    assert thread[0].direction == "out"
    assert thread[0].peer == bob.id
    assert thread[1].direction == "in"
    assert thread[1].peer == bob.id
    assert thread[1].in_reply_to == first["id"]

    record = store.get_thread(first["thread_id"])
    assert record is not None
    assert record.subject == "Deploy plan"
    assert record.updated_at == iso_from_ms(clock.now)
    assert len(store.list_threads(bob.id)) == 1
    assert len(store.list_threads(alice.id)) == 0
    assert len(store.list_threads()) == 1


def test_stores_created_at_in_utc_with_milliseconds(store: Store, clock: Clock) -> None:
    env: Envelope = {**outgoing(clock), "created_at": "2026-11-21T13:00:00+01:00"}
    store.save_outgoing(env)
    message = store.get_message(env["id"])
    assert message is not None
    assert message.created_at == "2026-11-21T12:00:00.000Z"


def test_lists_unread_incoming_messages_and_marks_them_read(store: Store, clock: Clock) -> None:
    a = create_envelope(from_=bob.id, to=alice.id, body="one")
    b = create_envelope(from_=bob.id, to=alice.id, body="two")
    store.save_incoming(a)
    store.save_incoming(b)
    store.save_outgoing(outgoing(clock))
    assert [m.body for m in store.inbox()] == ["one", "two"]
    assert store.mark_read(a["id"]) == 1
    assert [m.body for m in store.inbox()] == ["two"]
    assert store.mark_read([a["id"], b["id"]]) == 1
    assert len(store.inbox()) == 0
    message = store.get_message(b["id"])
    assert message is not None
    assert message.read_at is not None


def test_tracks_which_incoming_messages_were_delivered(store: Store) -> None:
    a = create_envelope(from_=bob.id, to=alice.id, body="one")
    store.save_incoming(a)
    assert [m.id for m in store.undelivered_incoming()] == [a["id"]]
    assert store.count_undelivered_incoming() == 1
    assert store.mark_delivered(a["id"]) is True
    assert store.mark_delivered(a["id"]) is False
    assert store.count_undelivered_incoming() == 0


def test_adds_and_updates_contact_settings(store: Store) -> None:
    added = store.upsert_contact(bob.id, "bob")
    assert added.name == "bob"
    assert added.trust == "paired"
    assert added.auto_send is False
    assert added.inbound_policy is None
    assert store.inbound_policy_for(bob.id) == "show_first"

    store.set_setting("default_inbound_policy", "auto_answer")
    assert store.inbound_policy_for(bob.id) == "auto_answer"

    updated = store.update_contact(bob.id, auto_send=True, inbound_policy="show_first")
    assert updated.auto_send is True
    assert store.inbound_policy_for(bob.id) == "show_first"

    store.update_contact(bob.id, trust="blocked", inbound_policy=None)
    blocked = store.get_contact(bob.id)
    assert blocked is not None
    assert blocked.trust == "blocked"
    assert blocked.inbound_policy is None
    assert blocked.auto_send is True

    store.upsert_contact(bob.id, "Bob B.")
    contact = store.get_contact(bob.id)
    assert contact is not None
    assert contact.name == "Bob B."
    assert contact.trust == "blocked"
    assert len(store.list_contacts()) == 1

    with pytest.raises(KeyError):
        store.update_contact(alice.id, name="x")


def test_stores_settings(store: Store) -> None:
    assert store.get_setting("k") is None
    store.set_setting("k", "1")
    store.set_setting("k", "2")
    assert store.get_setting("k") == "2"
    store.delete_setting("k")
    assert store.get_setting("k") is None


def test_auto_send_own_setting_wins_over_the_default(store: Store) -> None:
    store.upsert_contact(bob.id, "bob")
    assert store.auto_send_for(bob.id) == (False, True)
    store.set_setting("default_auto_send", "on")
    assert store.auto_send_for(bob.id) == (True, True)
    off = store.set_auto_send(bob.id, False)
    assert off.auto_send is False
    assert store.auto_send_for(bob.id) == (False, False)
    store.set_auto_send(bob.id, True)
    store.set_setting("default_auto_send", "off")
    assert store.auto_send_for(bob.id) == (True, False)
    cleared = store.set_auto_send(bob.id, None)
    assert cleared.auto_send is False
    assert store.auto_send_for(bob.id) == (False, True)
    with pytest.raises(KeyError):
        store.set_auto_send(alice.id, True)
    assert store.get_setting(f"auto_send:{alice.id}") is None


def test_backs_a_replay_guard_with_the_seen_ids_table_across_reopen(
    store: Store, path: str, clock: Clock
) -> None:
    env = create_envelope(from_=alice.id, to=bob.id, body="hi", created_at=clock.now)
    sealed = seal(env, alice)
    guard = ReplayGuard(seen=store.seen_ids(), now=clock)
    guard.record(open_sealed(sealed, bob, guard))

    store.close()
    reopened = Store.open(path, now=clock)
    try:
        guard2 = ReplayGuard(seen=reopened.seen_ids(), now=clock)
        with pytest.raises(EnvelopeError):
            open_sealed(sealed, bob, guard2)

        assert reopened.seen_ids().prune(clock.now + 1) == 1
        assert not guard2.seen.has(f"{alice.id} {env['id']}")
    finally:
        reopened.close()


class TestSubject:
    def test_uses_the_first_non_empty_line_without_heading_marks(self) -> None:
        assert subject_of("\n\n## Deploy plan  \nmore") == "Deploy plan"
        assert subject_of("") == ""
        assert subject_of("\u00a0\n\ufeffhi\u3000") == "hi"

    def test_shortens_long_subjects_counting_utf16_code_units(self) -> None:
        assert subject_of("x" * 120) == "x" * 120
        assert subject_of("x" * 121) == "x" * 119 + "\u2026"
        # 60 emoji are 120 UTF-16 code units: kept whole.
        assert subject_of("\U0001f600" * 60) == "\U0001f600" * 60
        # Cutting at 119 units splits an emoji; the leftover half becomes U+FFFD.
        assert subject_of("\U0001f600" * 61) == "\U0001f600" * 59 + "\ufffd\u2026"
