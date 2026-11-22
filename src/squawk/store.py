"""Local SQLite storage for contacts, messages, the outbound queue,
acknowledgements, threads, seen message ids and settings.

Timestamps in text columns are ISO 8601 strings in UTC (as produced by
JavaScript's `Date.prototype.toISOString`, see `squawk.timefmt`), so they
sort correctly as text. Columns used for scheduling or expiry
(`next_attempt_at`, `seen_ids.created_at_ms`) are milliseconds since the
epoch.

This is the Python version of src/store.ts. It uses the same file, schema
and migrations, so either version can open a database the other wrote.
"""

import os
import re
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal, TypeVar, cast

from squawk import jsontext
from squawk.envelope import Envelope, MessageKind, parse_envelope
from squawk.timefmt import iso_from_ms, ms_from_datetime, now_ms, parse_iso_ms

MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE contacts (
        public_key     TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        trust          TEXT NOT NULL DEFAULT 'paired'
                       CHECK (trust IN ('paired', 'blocked')),
        auto_send      INTEGER NOT NULL DEFAULT 0 CHECK (auto_send IN (0, 1)),
        inbound_policy TEXT CHECK (inbound_policy IN ('show_first', 'auto_answer')),
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL
    );

    CREATE TABLE messages (
        id          TEXT PRIMARY KEY,
        direction   TEXT NOT NULL CHECK (direction IN ('in', 'out')),
        peer        TEXT NOT NULL,
        session     TEXT,
        thread_id   TEXT NOT NULL,
        in_reply_to TEXT,
        kind        TEXT NOT NULL CHECK (kind IN ('text', 'question', 'answer')),
        body        TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        received_at TEXT,
        sent_at     TEXT,
        read_at     TEXT,
        state       TEXT NOT NULL
                    CHECK (state IN ('queued', 'sent', 'acked', 'failed', 'unread', 'read'))
    );
    CREATE INDEX messages_thread ON messages (thread_id, created_at);
    CREATE INDEX messages_inbox ON messages (direction, state, created_at);

    CREATE TABLE outbox (
        message_id      TEXT PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE,
        recipient       TEXT NOT NULL,
        payload         TEXT NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL,
        last_error      TEXT
    );
    CREATE INDEX outbox_due ON outbox (next_attempt_at);

    CREATE TABLE acks (
        message_id TEXT PRIMARY KEY,
        acked_at   TEXT NOT NULL
    );

    CREATE TABLE threads (
        thread_id  TEXT PRIMARY KEY,
        peer       TEXT NOT NULL,
        subject    TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX threads_updated ON threads (updated_at);

    CREATE TABLE seen_ids (
        id            TEXT PRIMARY KEY,
        created_at_ms INTEGER NOT NULL
    );
    CREATE INDEX seen_ids_created ON seen_ids (created_at_ms);

    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    # When an incoming message was pushed to a local session by the background
    # service. NULL means it is still waiting for a session to open.
    """
    ALTER TABLE messages ADD COLUMN delivered_at TEXT;
    CREATE INDEX messages_undelivered ON messages (direction, delivered_at, created_at);
    """,
    # The outbound queue now holds the envelope rather than a sealed copy, so
    # each attempt can be sealed with a fresh sent_at. Rows queued in the old
    # form cannot be converted (they are encrypted), so they are marked failed.
    # Seen ids are now recorded per sender under a different key, so the old
    # rows are no longer useful.
    """
    UPDATE messages SET state = 'failed'
     WHERE id IN (SELECT message_id FROM outbox);
    DELETE FROM outbox;
    DELETE FROM seen_ids;
    """,
)
"""Schema migrations, applied in order. The database's `PRAGMA user_version`
holds how many have been applied. Never edit or reorder an entry that has
shipped; add a new one at the end instead. The text is the same as in
src/store.ts
apart from indentation."""

Trust = Literal["paired", "blocked"]
InboundPolicy = Literal["show_first", "auto_answer"]
Direction = Literal["in", "out"]
MessageState = Literal["queued", "sent", "acked", "failed", "unread", "read"]
"""Outgoing: queued, sent, acked, failed. Incoming: unread, read."""

DEFAULT_INBOUND_POLICY_KEY = "default_inbound_policy"
"""Setting key holding the inbound policy for contacts that have none of their own."""


class _Unset(Enum):
    UNSET = "unset"


UNSET = _Unset.UNSET
"""Marks an argument that was not given, where None has its own meaning
(for `inbound_policy`, None means "use the default")."""


@dataclass(frozen=True)
class Contact:
    public_key: str
    name: str
    trust: Trust
    auto_send: bool
    inbound_policy: InboundPolicy | None
    """None means "use the default inbound policy setting"."""
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class StoredMessage:
    id: str
    direction: Direction
    peer: str
    """The other party's key identifier: the recipient for "out", the sender for "in"."""
    session: str | None
    thread_id: str
    in_reply_to: str | None
    kind: MessageKind
    body: str
    created_at: str
    received_at: str | None
    sent_at: str | None
    read_at: str | None
    delivered_at: str | None
    """Incoming only: when the background service pushed it to a local session."""
    state: MessageState


@dataclass(frozen=True)
class OutboundItem:
    message_id: str
    recipient: str
    envelope: Envelope
    """The message to seal and send; sealed afresh at each attempt."""
    attempts: int
    next_attempt_at: int
    """Milliseconds since the epoch."""
    last_error: str | None


@dataclass(frozen=True)
class Thread:
    thread_id: str
    peer: str
    subject: str
    """First line of the first message in the thread, shortened."""
    created_at: str
    updated_at: str


SUBJECT_MAX = 120

_T = TypeVar("_T")
_Param = str | int | float | bytes | None
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_HEADING_MARK = re.compile(f"^#+[{jsontext.JS_WHITESPACE}]*")


def _bind(value: _Param) -> _Param:
    # A lone UTF-16 surrogate cannot be written as UTF-8; Node writes it as
    # U+FFFD, and Python's sqlite3 would raise instead.
    return _LONE_SURROGATE.sub("\ufffd", value) if isinstance(value, str) else value


def _to_contact(row: sqlite3.Row) -> Contact:
    return Contact(
        public_key=row["public_key"],
        name=row["name"],
        trust=row["trust"],
        auto_send=row["auto_send"] == 1,
        inbound_policy=row["inbound_policy"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _to_message(row: sqlite3.Row) -> StoredMessage:
    return StoredMessage(
        id=row["id"],
        direction=row["direction"],
        peer=row["peer"],
        session=row["session"],
        thread_id=row["thread_id"],
        in_reply_to=row["in_reply_to"],
        kind=row["kind"],
        body=row["body"],
        created_at=row["created_at"],
        received_at=row["received_at"],
        sent_at=row["sent_at"],
        read_at=row["read_at"],
        delivered_at=row["delivered_at"],
        state=row["state"],
    )


def _to_outbound(row: sqlite3.Row) -> OutboundItem:
    return OutboundItem(
        message_id=row["message_id"],
        recipient=row["recipient"],
        envelope=parse_envelope(jsontext.parse(row["payload"])),
        attempts=int(row["attempts"]),
        next_attempt_at=int(row["next_attempt_at"]),
        last_error=row["last_error"],
    )


def _to_thread(row: sqlite3.Row) -> Thread:
    return Thread(
        thread_id=row["thread_id"],
        peer=row["peer"],
        subject=row["subject"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def subject_of(body: str) -> str:
    """The first non-empty line of `body`, without a leading Markdown heading
    mark, shortened to SUBJECT_MAX characters (counted as JavaScript counts)."""
    first_line = next(
        (
            line
            for line in (jsontext.js_trim(_HEADING_MARK.sub("", raw)) for raw in body.split("\n"))
            if line != ""
        ),
        "",
    )
    if jsontext.js_length(first_line) > SUBJECT_MAX:
        return jsontext.js_slice(first_line, SUBJECT_MAX - 1) + "\u2026"
    return first_line


def _iso(time: str | int | datetime) -> str:
    """The time as `new Date(time).toISOString()` gives it."""
    if isinstance(time, datetime):
        return iso_from_ms(ms_from_datetime(time))
    if isinstance(time, int):
        return iso_from_ms(time)
    ms = parse_iso_ms(time)
    if ms is None:
        raise ValueError(f"invalid time value: {time}")
    return iso_from_ms(ms)


class Store:
    """The database. Open it with `Store.open`.

    Every method is synchronous and runs on the calling thread; the
    connection may only be used from the thread that opened it (Python's
    sqlite3 default).
    """

    def __init__(
        self,
        db: sqlite3.Connection,
        now: Callable[[], int] | None = None,
        retry_base_ms: int = 2_000,
        retry_max_ms: int = 5 * 60_000,
    ) -> None:
        self.db = db
        self.db.row_factory = sqlite3.Row
        self._now = now_ms if now is None else now
        self._retry_base_ms = retry_base_ms
        self._retry_max_ms = retry_max_ms

    @classmethod
    def open(
        cls,
        path: str,
        *,
        now: Callable[[], int] | None = None,
        retry_base_ms: int = 2_000,
        retry_max_ms: int = 5 * 60_000,
    ) -> "Store":
        """Opens (creating if needed) the database at `path` and applies any
        migrations not yet applied. Use ":memory:" for a throwaway database.

        The database file and SQLite's companion files (`-wal`, which holds
        recent message text, and `-shm`) are created with mode 0600, since
        they hold private messages.

        `now` returns the current time in milliseconds since the epoch.
        `retry_base_ms` is the delay before the first retry, doubled on each
        attempt up to `retry_max_ms`.
        """

        def make(db: sqlite3.Connection) -> Store:
            return cls(db, now=now, retry_base_ms=retry_base_ms, retry_max_ms=retry_max_ms)

        # autocommit=True: Python's sqlite3 module does not begin or commit
        # transactions on its own (and executescript does not commit first),
        # so `transaction` controls them, as in the Node version.
        if path == ":memory:":
            store = make(sqlite3.connect(path, autocommit=True))
            store._configure()
            return store
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        # SQLite creates its files with the process umask; make that
        # owner-only while opening so no file is ever readable by others.
        previous_umask = os.umask(0o077)
        try:
            store = make(sqlite3.connect(path, autocommit=True))
            store.db.execute("PRAGMA journal_mode = WAL")
            store._configure()
        finally:
            os.umask(previous_umask)
        # Files left by an older version may have been created more openly.
        for file in (path, f"{path}-wal", f"{path}-shm"):
            if os.path.exists(file):
                os.chmod(file, 0o600)
        return store

    def _configure(self) -> None:
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.migrate()

    def close(self) -> None:
        self.db.close()

    def _run(self, sql: str, *params: _Param) -> sqlite3.Cursor:
        return self.db.execute(sql, tuple(_bind(p) for p in params))

    def _one(self, sql: str, *params: _Param) -> sqlite3.Row | None:
        return cast(sqlite3.Row | None, self._run(sql, *params).fetchone())

    def _all(self, sql: str, *params: _Param) -> list[sqlite3.Row]:
        return self._run(sql, *params).fetchall()

    def schema_version(self) -> int:
        """The number of migrations applied (the database's `user_version`)."""
        row = self._one("PRAGMA user_version")
        assert row is not None
        return int(row[0])

    def migrate(self) -> None:
        """Applies, in one transaction each, every migration not yet applied.

        The version is read again inside each transaction, so when two
        processes open the same database at once, the one that waited skips a
        migration the other has just applied.
        """
        for v in range(self.schema_version(), len(MIGRATIONS)):

            def apply(v: int = v) -> None:
                if self.schema_version() > v:
                    return
                self.db.executescript(MIGRATIONS[v])
                self.db.execute(f"PRAGMA user_version = {v + 1}")

            self.transaction(apply)

    def transaction(self, fn: Callable[[], _T]) -> _T:
        """Runs `fn` inside a transaction, rolling back if it raises."""
        if self.db.in_transaction:
            return fn()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            result = fn()
            self.db.execute("COMMIT")
            return result
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def _now_iso(self) -> str:
        return _iso(self._now())

    # Contacts

    def upsert_contact(
        self,
        public_key: str,
        name: str,
        *,
        trust: Trust | None = None,
        auto_send: bool | None = None,
        inbound_policy: InboundPolicy | _Unset | None = UNSET,
    ) -> Contact:
        """Adds a contact, or updates the name and any given fields of an existing one."""
        now = self._now_iso()

        def run() -> None:
            existing = self.get_contact(public_key)
            if existing is None:
                self._run(
                    """INSERT INTO contacts
                     (public_key, name, trust, auto_send, inbound_policy, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    public_key,
                    name,
                    trust or "paired",
                    1 if auto_send else 0,
                    None if inbound_policy is UNSET else inbound_policy,
                    now,
                    now,
                )
            else:
                self.update_contact(
                    public_key,
                    name=name,
                    trust=trust,
                    auto_send=auto_send,
                    inbound_policy=inbound_policy,
                )

        self.transaction(run)
        contact = self.get_contact(public_key)
        assert contact is not None
        return contact

    def get_contact(self, public_key: str) -> Contact | None:
        row = self._one("SELECT * FROM contacts WHERE public_key = ?", public_key)
        return None if row is None else _to_contact(row)

    def list_contacts(self) -> list[Contact]:
        return [
            _to_contact(row)
            for row in self._all("SELECT * FROM contacts ORDER BY name, public_key")
        ]

    def update_contact(
        self,
        public_key: str,
        *,
        name: str | None = None,
        trust: Trust | None = None,
        auto_send: bool | None = None,
        inbound_policy: InboundPolicy | _Unset | None = UNSET,
    ) -> Contact:
        """Changes the given fields of a contact. Raises KeyError if there is no such contact.

        Pass `inbound_policy=None` to clear it and fall back to the default.
        """
        sets: list[str] = []
        values: list[_Param] = []
        if name is not None:
            sets.append("name = ?")
            values.append(name)
        if trust is not None:
            sets.append("trust = ?")
            values.append(trust)
        if auto_send is not None:
            sets.append("auto_send = ?")
            values.append(1 if auto_send else 0)
        if inbound_policy is not UNSET:
            sets.append("inbound_policy = ?")
            values.append(inbound_policy)
        sets.append("updated_at = ?")
        values.append(self._now_iso())
        result = self._run(
            f"UPDATE contacts SET {', '.join(sets)} WHERE public_key = ?", *values, public_key
        )
        if result.rowcount == 0:
            raise KeyError(f"no contact with key {public_key}")
        contact = self.get_contact(public_key)
        assert contact is not None
        return contact

    def inbound_policy_for(self, public_key: str) -> InboundPolicy:
        """The contact's own inbound policy, else the default setting, else "show_first"."""
        contact = self.get_contact(public_key)
        if contact is not None and contact.inbound_policy:
            return contact.inbound_policy
        fallback = self.get_setting(DEFAULT_INBOUND_POLICY_KEY)
        return "auto_answer" if fallback == "auto_answer" else "show_first"

    # Messages and threads

    def _insert_message(
        self,
        envelope: Envelope,
        direction: Direction,
        state: MessageState,
        received_at: str | None,
    ) -> bool:
        peer = envelope["to"] if direction == "out" else envelope["from"]
        created_at = _iso(envelope["created_at"])
        result = self._run(
            """INSERT OR IGNORE INTO messages
             (id, direction, peer, session, thread_id, in_reply_to, kind, body,
              created_at, received_at, state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            envelope["id"],
            direction,
            peer,
            envelope.get("session"),
            envelope["thread_id"],
            envelope.get("in_reply_to"),
            envelope["kind"],
            envelope["body"],
            created_at,
            received_at,
            state,
        )
        if result.rowcount == 0:
            return False
        self._run(
            """INSERT INTO threads (thread_id, peer, subject, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT (thread_id) DO UPDATE
             SET updated_at = max(threads.updated_at, excluded.updated_at)""",
            envelope["thread_id"],
            peer,
            subject_of(envelope["body"]),
            created_at,
            created_at,
        )
        return True

    def save_incoming(self, envelope: Envelope, received_at: datetime | int | None = None) -> bool:
        """Saves a message received from a peer as unread.

        Returns False (and changes nothing) if a message with this id is
        already stored. `received_at` defaults to now.
        """
        at = _iso(self._now() if received_at is None else received_at)
        return self.transaction(lambda: self._insert_message(envelope, "in", "unread", at))

    def incoming_conflict(self, envelope: Envelope) -> str | None:
        """Says why an incoming message from `envelope["from"]` must be refused
        because its id or thread already belongs to a different contact or to a
        message this machine sent.

        Senders choose their own ids, so without this check one contact could
        make another's message be silently dropped as a duplicate, or add
        messages to another contact's thread. Returns None when there is no
        conflict (including when this exact message from this sender is
        already stored). Uses only the "id", "from" and "thread_id" fields.
        """
        existing = self.get_message(envelope["id"])
        if existing is not None and (
            existing.direction != "in" or existing.peer != envelope["from"]
        ):
            return "message id already in use"
        thread = self.get_thread(envelope["thread_id"])
        if thread is not None and thread.peer != envelope["from"]:
            return "thread id already in use"
        return None

    def save_outgoing(self, envelope: Envelope, state: MessageState = "queued") -> bool:
        """Saves a message this machine is sending, without queueing it."""
        return self.transaction(lambda: self._insert_message(envelope, "out", state, None))

    def get_message(self, id: str) -> StoredMessage | None:
        row = self._one("SELECT * FROM messages WHERE id = ?", id)
        return None if row is None else _to_message(row)

    def list_thread(self, thread_id: str) -> list[StoredMessage]:
        """Messages in a thread, oldest first."""
        return [
            _to_message(row)
            for row in self._all(
                "SELECT * FROM messages WHERE thread_id = ? ORDER BY created_at, rowid", thread_id
            )
        ]

    def get_thread(self, thread_id: str) -> Thread | None:
        row = self._one("SELECT * FROM threads WHERE thread_id = ?", thread_id)
        return None if row is None else _to_thread(row)

    def list_threads(self, peer: str | None = None) -> list[Thread]:
        """Threads, most recently active first, optionally only those with `peer`."""
        if peer is None:
            rows = self._all("SELECT * FROM threads ORDER BY updated_at DESC")
        else:
            rows = self._all("SELECT * FROM threads WHERE peer = ? ORDER BY updated_at DESC", peer)
        return [_to_thread(row) for row in rows]

    def inbox(self) -> list[StoredMessage]:
        """Unread incoming messages, oldest first."""
        return [
            _to_message(row)
            for row in self._all(
                """SELECT * FROM messages WHERE direction = 'in' AND state = 'unread'
                 ORDER BY created_at, rowid"""
            )
        ]

    def mark_read(self, ids: str | Sequence[str]) -> int:
        """Marks incoming messages as read. Returns how many changed."""
        id_list = [ids] if isinstance(ids, str) else list(ids)
        read_at = self._now_iso()

        def run() -> int:
            return sum(
                self._run(
                    """UPDATE messages SET state = 'read', read_at = ?
                     WHERE id = ? AND direction = 'in' AND state = 'unread'""",
                    read_at,
                    id,
                ).rowcount
                for id in id_list
            )

        return self.transaction(run)

    def undelivered_incoming(self) -> list[StoredMessage]:
        """Unread incoming messages not yet pushed to a local session, oldest first."""
        return [
            _to_message(row)
            for row in self._all(
                """SELECT * FROM messages
                 WHERE direction = 'in' AND state = 'unread' AND delivered_at IS NULL
                 ORDER BY created_at, rowid"""
            )
        ]

    def count_undelivered_incoming(self) -> int:
        """How many messages `undelivered_incoming` would return."""
        row = self._one(
            """SELECT count(*) AS n FROM messages
             WHERE direction = 'in' AND state = 'unread' AND delivered_at IS NULL"""
        )
        assert row is not None
        return int(row["n"])

    def mark_delivered(self, id: str) -> bool:
        """Records that an incoming message was pushed to a local session.

        Returns False if it already had been.
        """
        result = self._run(
            """UPDATE messages SET delivered_at = ?
             WHERE id = ? AND direction = 'in' AND delivered_at IS NULL""",
            self._now_iso(),
            id,
        )
        return result.rowcount > 0

    # Outbound queue

    def count_outbound(self) -> int:
        """How many messages are in the outbound queue."""
        row = self._one("SELECT count(*) AS n FROM outbox")
        assert row is not None
        return int(row["n"])

    def enqueue(self, envelope: Envelope, next_attempt_at: int | None = None) -> None:
        """Adds a message to the outbound queue, due immediately unless told otherwise."""
        self._run(
            """INSERT INTO outbox (message_id, recipient, payload, attempts, next_attempt_at)
             VALUES (?, ?, ?, 0, ?)""",
            envelope["id"],
            envelope["to"],
            jsontext.stringify(envelope),
            self._now() if next_attempt_at is None else next_attempt_at,
        )

    def queue_outgoing(self, envelope: Envelope) -> None:
        """Saves an outgoing message and queues it for sending, in one transaction."""

        def run() -> None:
            self.save_outgoing(envelope, "queued")
            self.enqueue(envelope)

        self.transaction(run)

    def fail_expired(self, max_age_ms: int) -> list[str]:
        """Gives up on queued messages created more than `max_age_ms` ago:
        removes them from the outbound queue and marks them failed. Returns
        their ids."""
        cutoff = _iso(self._now() - max_age_ms)

        def run() -> list[str]:
            ids: list[str] = [
                row["message_id"]
                for row in self._all(
                    """SELECT o.message_id FROM outbox o JOIN messages m ON m.id = o.message_id
                     WHERE m.created_at < ?""",
                    cutoff,
                )
            ]
            for id in ids:
                self._run("DELETE FROM outbox WHERE message_id = ?", id)
                self._run("UPDATE messages SET state = 'failed' WHERE id = ?", id)
            return ids

        return self.transaction(run)

    def due_outbound(self, now: int | None = None, limit: int = 100) -> list[OutboundItem]:
        """Queue items whose next attempt time has come, earliest first."""
        return [
            _to_outbound(row)
            for row in self._all(
                """SELECT * FROM outbox WHERE next_attempt_at <= ?
                 ORDER BY next_attempt_at, message_id LIMIT ?""",
                self._now() if now is None else now,
                limit,
            )
        ]

    def get_outbound(self, message_id: str) -> OutboundItem | None:
        row = self._one("SELECT * FROM outbox WHERE message_id = ?", message_id)
        return None if row is None else _to_outbound(row)

    def record_attempt(
        self, message_id: str, *, error: str | None = None, next_attempt_at: int | None = None
    ) -> int:
        """Records a failed delivery attempt and schedules the next one.

        The delay is `retry_base_ms * 2^(attempts - 1)`, capped at
        `retry_max_ms`, unless `next_attempt_at` is given. Returns the time
        of the next attempt.
        """

        def run() -> int:
            item = self.get_outbound(message_id)
            if item is None:
                raise KeyError(f"message {message_id} is not in the outbound queue")
            attempts = item.attempts + 1
            delay = min(self._retry_base_ms * 2 ** (attempts - 1), self._retry_max_ms)
            next_at = self._now() + delay if next_attempt_at is None else next_attempt_at
            self._run(
                """UPDATE outbox SET attempts = ?, next_attempt_at = ?, last_error = ?
                 WHERE message_id = ?""",
                attempts,
                next_at,
                error,
                message_id,
            )
            return next_at

        return self.transaction(run)

    def mark_acknowledged(self, message_id: str, acked_at: datetime | int | None = None) -> bool:
        """Records that the recipient acknowledged a message: adds an ack row,
        removes the message from the outbound queue and marks it acked.

        Returns False if it had already been acknowledged. `acked_at`
        defaults to now.
        """
        at = _iso(self._now() if acked_at is None else acked_at)

        def run() -> bool:
            inserted = self._run(
                "INSERT OR IGNORE INTO acks (message_id, acked_at) VALUES (?, ?)", message_id, at
            )
            self._run("DELETE FROM outbox WHERE message_id = ?", message_id)
            self._run(
                """UPDATE messages SET state = 'acked', sent_at = coalesce(sent_at, ?)
                 WHERE id = ? AND direction = 'out'""",
                at,
                message_id,
            )
            return inserted.rowcount > 0

        return self.transaction(run)

    def acked_at(self, message_id: str) -> str | None:
        """When a message was acknowledged, or None if it has not been."""
        row = self._one("SELECT acked_at FROM acks WHERE message_id = ?", message_id)
        return None if row is None else cast(str, row["acked_at"])

    # Settings

    def get_setting(self, key: str) -> str | None:
        row = self._one("SELECT value FROM settings WHERE key = ?", key)
        return None if row is None else cast(str, row["value"])

    def set_setting(self, key: str, value: str) -> None:
        self._run(
            """INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value""",
            key,
            value,
        )

    # Seen message ids (replay protection)

    def seen_ids(self) -> "StoreSeenIds":
        """A `SeenIdStore` backed by the seen_ids table, for use with
        `ReplayGuard(seen=store.seen_ids())`."""
        return StoreSeenIds(self)


class StoreSeenIds:
    """A `SeenIdStore` kept in a store's seen_ids table."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def has(self, id: str) -> bool:
        return self._store._one("SELECT 1 FROM seen_ids WHERE id = ?", id) is not None

    def add(self, id: str, at_ms: int) -> None:
        self._store._run(
            "INSERT OR IGNORE INTO seen_ids (id, created_at_ms) VALUES (?, ?)", id, at_ms
        )

    def prune(self, cutoff_ms: int) -> int:
        """Forgets ids created before `cutoff_ms`; returns how many were removed."""
        return self._store._run("DELETE FROM seen_ids WHERE created_at_ms < ?", cutoff_ms).rowcount
