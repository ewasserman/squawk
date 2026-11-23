"""The relay's SQLite database: its own key, mailboxes, allow lists, waiting
messages, open invites and, in GitHub mode, the GitHub accounts that signed
in and the keys each one owns.

Times are milliseconds since the epoch, passed in by the caller so that
tests can use a fake clock. The database file and SQLite's companion files
are created with mode 0600 and the data directory with mode 0700, as for the
service's own database (`squawk.store`).
"""

import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from squawk.crypto import ed25519_random_secret_key
from squawk.encoding import from_base64url, to_base64url

_T = TypeVar("_T")

DB_FILE = "relay.db"

MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE relay_key (
        only_row   INTEGER PRIMARY KEY CHECK (only_row = 1),
        secret_key TEXT NOT NULL
    );

    CREATE TABLE mailboxes (
        key_id               TEXT PRIMARY KEY,
        created_at_ms        INTEGER NOT NULL,
        last_connected_at_ms INTEGER NOT NULL
    );

    CREATE TABLE allowed (
        owner  TEXT NOT NULL REFERENCES mailboxes (key_id),
        sender TEXT NOT NULL,
        PRIMARY KEY (owner, sender)
    );

    CREATE TABLE messages (
        rid            INTEGER PRIMARY KEY AUTOINCREMENT,
        sender         TEXT NOT NULL,
        recipient      TEXT NOT NULL,
        message_id     TEXT NOT NULL,
        arrived_at_ms  INTEGER NOT NULL,
        sealed         TEXT NOT NULL,
        size           INTEGER NOT NULL,
        UNIQUE (sender, message_id)
    );
    CREATE INDEX messages_recipient ON messages (recipient, rid);
    CREATE INDEX messages_arrived ON messages (arrived_at_ms);

    CREATE TABLE invites (
        code_hash     TEXT PRIMARY KEY,
        creator       TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL
    );
    CREATE INDEX invites_creator ON invites (creator);
    """,
    # GitHub mode (docs/plan/relay-access.md): the GitHub accounts that have
    # signed in, and which account owns each key that signed in. No tokens.
    """
    CREATE TABLE github_users (
        id                    INTEGER PRIMARY KEY,
        login                 TEXT NOT NULL,
        first_signed_in_at_ms INTEGER NOT NULL,
        last_signed_in_at_ms  INTEGER NOT NULL
    );
    CREATE INDEX github_users_login ON github_users (login COLLATE NOCASE);

    CREATE TABLE key_owners (
        key_id         TEXT PRIMARY KEY,
        github_user_id INTEGER NOT NULL REFERENCES github_users (id),
        added_at_ms    INTEGER NOT NULL
    );
    CREATE INDEX key_owners_user ON key_owners (github_user_id);
    """,
)
"""Schema migrations, applied in order; `PRAGMA user_version` counts those applied."""


@dataclass(frozen=True)
class StoredMessage:
    """A message waiting in a mailbox."""

    rid: int
    sender: str
    recipient: str
    message_id: str
    arrived_at_ms: int
    sealed: str
    """The sealed message as JSON text, exactly as it was deposited."""


@dataclass(frozen=True)
class MailboxUsage:
    messages: int
    bytes: int


@dataclass(frozen=True)
class KeyOwner:
    """The GitHub account a key belongs to, as last seen when it signed in."""

    github_id: int
    login: str


class RelayStore:
    """The relay's database. Open it with `RelayStore.open`. Not thread-safe:
    use it only from the thread that opened it."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    @classmethod
    def open(cls, data_dir: str) -> "RelayStore":
        """Opens (creating if needed) the database in `data_dir`."""
        parent = os.path.dirname(os.path.abspath(data_dir))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.mkdir(data_dir, 0o700)
            os.chmod(data_dir, 0o700)  # mkdir's mode is reduced by the umask.
        except FileExistsError:
            pass
        path = os.path.join(data_dir, DB_FILE)
        previous_umask = os.umask(0o077)
        try:
            store = cls(sqlite3.connect(path, autocommit=True))
            store.db.execute("PRAGMA journal_mode = WAL")
            store.db.execute("PRAGMA foreign_keys = ON")
            store.db.execute("PRAGMA busy_timeout = 5000")
            store._migrate()
        finally:
            os.umask(previous_umask)
        for file in (path, f"{path}-wal", f"{path}-shm"):
            if os.path.exists(file):
                os.chmod(file, 0o600)
        return store

    @classmethod
    def open_memory(cls) -> "RelayStore":
        """A throwaway database, for tests."""
        store = cls(sqlite3.connect(":memory:", autocommit=True))
        store.db.execute("PRAGMA foreign_keys = ON")
        store._migrate()
        return store

    def close(self) -> None:
        self.db.close()

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

    def _migrate(self) -> None:
        version = int(self.db.execute("PRAGMA user_version").fetchone()[0])
        for v in range(version, len(MIGRATIONS)):

            def apply(v: int = v) -> None:
                self.db.executescript(MIGRATIONS[v])
                self.db.execute(f"PRAGMA user_version = {v + 1}")

            self.transaction(apply)

    # The relay's key.

    def secret_key(self) -> bytes:
        """The relay's 32-byte ed25519 secret key, made and saved on first use."""

        def get() -> bytes:
            row = self.db.execute("SELECT secret_key FROM relay_key").fetchone()
            if row is not None:
                return from_base64url(str(row[0]))
            key = ed25519_random_secret_key()
            self.db.execute(
                "INSERT INTO relay_key (only_row, secret_key) VALUES (1, ?)", (to_base64url(key),)
            )
            return key

        return self.transaction(get)

    # Mailboxes and allow lists.

    def touch_mailbox(self, key_id: str, now: int) -> None:
        """Creates the mailbox for `key_id` if needed and records that it connected now."""
        self.db.execute(
            "INSERT INTO mailboxes (key_id, created_at_ms, last_connected_at_ms) VALUES (?, ?, ?)"
            " ON CONFLICT (key_id)"
            " DO UPDATE SET last_connected_at_ms = excluded.last_connected_at_ms",
            (key_id, now, now),
        )

    def delete_mailbox(self, key_id: str) -> None:
        """Deletes `key_id`'s mailbox with its allow list, the messages waiting
        in it and its open invite, and forgets which GitHub user owned it (so
        it no longer counts toward their keys, and its owner can sign in again
        if they are admitted later). Used when a key may no longer use the relay."""

        def delete() -> None:
            self.db.execute("DELETE FROM key_owners WHERE key_id = ?", (key_id,))
            self.db.execute("DELETE FROM allowed WHERE owner = ?", (key_id,))
            self.db.execute("DELETE FROM messages WHERE recipient = ?", (key_id,))
            self.db.execute("DELETE FROM invites WHERE creator = ?", (key_id,))
            self.db.execute("DELETE FROM mailboxes WHERE key_id = ?", (key_id,))

        self.transaction(delete)

    def mailbox_keys(self) -> list[str]:
        """The key id of every mailbox."""
        return [str(r[0]) for r in self.db.execute("SELECT key_id FROM mailboxes")]

    def has_mailbox(self, key_id: str) -> bool:
        row = self.db.execute("SELECT 1 FROM mailboxes WHERE key_id = ?", (key_id,)).fetchone()
        return row is not None

    def set_allowed(self, owner: str, senders: list[str]) -> None:
        """Replaces the allow list of `owner`'s mailbox."""

        def replace() -> None:
            self.db.execute("DELETE FROM allowed WHERE owner = ?", (owner,))
            self.db.executemany(
                "INSERT OR IGNORE INTO allowed (owner, sender) VALUES (?, ?)",
                [(owner, s) for s in senders],
            )

        self.transaction(replace)

    def is_allowed(self, owner: str, sender: str) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM allowed WHERE owner = ? AND sender = ?", (owner, sender)
        ).fetchone()
        return row is not None

    # Messages.

    def has_message(self, sender: str, message_id: str, recipient: str, not_before: int) -> bool:
        """True if a message from `sender` with this id waits for `recipient`
        and arrived at or after `not_before` (so it has not expired)."""
        row = self.db.execute(
            "SELECT 1 FROM messages WHERE sender = ? AND message_id = ?"
            " AND recipient = ? AND arrived_at_ms >= ?",
            (sender, message_id, recipient, not_before),
        ).fetchone()
        return row is not None

    def delete_message_copies(self, sender: str, message_id: str) -> None:
        """Deletes any stored message from `sender` with this id."""
        self.db.execute(
            "DELETE FROM messages WHERE sender = ? AND message_id = ?", (sender, message_id)
        )

    def usage(self, recipient: str, not_before: int) -> MailboxUsage:
        """How many messages, and how many bytes of them, wait for `recipient`
        (counting only those that arrived at or after `not_before`)."""
        row = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages"
            " WHERE recipient = ? AND arrived_at_ms >= ?",
            (recipient, not_before),
        ).fetchone()
        return MailboxUsage(int(row[0]), int(row[1]))

    def add_message(
        self, sender: str, recipient: str, message_id: str, sealed: str, now: int
    ) -> int | None:
        """Stores a message and returns its relay id, or None if a message with
        the same sender and id is already stored."""
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO messages"
            " (sender, recipient, message_id, arrived_at_ms, sealed, size)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (sender, recipient, message_id, now, sealed, len(sealed.encode("utf-8"))),
        )
        return cursor.lastrowid if cursor.rowcount == 1 else None

    def messages_after(
        self, recipient: str, after_rid: int, not_before: int, limit: int
    ) -> list[StoredMessage]:
        """Up to `limit` messages for `recipient` with a relay id above
        `after_rid`, oldest first, leaving out those that arrived before
        `not_before`."""
        rows = self.db.execute(
            "SELECT rid, sender, recipient, message_id, arrived_at_ms, sealed FROM messages"
            " WHERE recipient = ? AND rid > ? AND arrived_at_ms >= ? ORDER BY rid LIMIT ?",
            (recipient, after_rid, not_before, limit),
        ).fetchall()
        return [StoredMessage(int(r[0]), r[1], r[2], r[3], int(r[4]), r[5]) for r in rows]

    def delete_message(self, recipient: str, rid: int) -> bool:
        """Deletes a message from `recipient`'s mailbox; False if there was none."""
        cursor = self.db.execute(
            "DELETE FROM messages WHERE rid = ? AND recipient = ?", (rid, recipient)
        )
        return cursor.rowcount == 1

    # Invites.

    def add_invite(self, code_hash: str, creator: str, expires_at: int) -> None:
        """Stores an invite, removing any other invite `creator` had open."""

        def add() -> None:
            self.db.execute("DELETE FROM invites WHERE creator = ?", (creator,))
            self.db.execute(
                "INSERT INTO invites (code_hash, creator, expires_at_ms) VALUES (?, ?, ?)",
                (code_hash, creator, expires_at),
            )

        self.transaction(add)

    def take_invite(self, code_hash: str, now: int) -> str | None:
        """Removes an unexpired invite and returns its creator's key id, or
        None if there is no such invite."""

        def take() -> str | None:
            row = self.db.execute(
                "SELECT creator FROM invites WHERE code_hash = ? AND expires_at_ms > ?",
                (code_hash, now),
            ).fetchone()
            if row is None:
                return None
            self.db.execute("DELETE FROM invites WHERE code_hash = ?", (code_hash,))
            return str(row[0])

        return self.transaction(take)

    def invite_creator(self, code_hash: str) -> str | None:
        row = self.db.execute(
            "SELECT creator FROM invites WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        return None if row is None else str(row[0])

    def delete_invites_of(self, creator: str) -> None:
        self.db.execute("DELETE FROM invites WHERE creator = ?", (creator,))

    def delete_all_invites(self) -> None:
        """Removes every invite. Used at start: an invite lasts only while its
        creator stays connected, and a restart drops every connection."""
        self.db.execute("DELETE FROM invites")

    # GitHub users and the keys they own.

    def key_owner(self, key_id: str) -> KeyOwner | None:
        """The GitHub account that signed in with `key_id`, if any."""
        row = self.db.execute(
            "SELECT u.id, u.login FROM key_owners k JOIN github_users u"
            " ON u.id = k.github_user_id WHERE k.key_id = ?",
            (key_id,),
        ).fetchone()
        return None if row is None else KeyOwner(int(row[0]), str(row[1]))

    def github_ids_named(self, login: str) -> list[int]:
        """The ids of the stored GitHub accounts whose login is `login`,
        ignoring case (GitHub logins are not case-sensitive)."""
        rows = self.db.execute(
            "SELECT id FROM github_users WHERE login = ? COLLATE NOCASE ORDER BY id", (login,)
        )
        return [int(r[0]) for r in rows]

    def count_keys_of(self, github_id: int) -> int:
        """How many keys belong to the GitHub account `github_id`."""
        row = self.db.execute(
            "SELECT COUNT(*) FROM key_owners WHERE github_user_id = ?", (github_id,)
        ).fetchone()
        return int(row[0])

    def record_sign_in(self, key_id: str, github_id: int, login: str, now: int) -> bool:
        """Records that `key_id` signed in as the GitHub account `github_id`,
        whose login is now `login`. Returns True if that account had never
        signed in before."""

        def record() -> bool:
            known = self.db.execute(
                "SELECT 1 FROM github_users WHERE id = ?", (github_id,)
            ).fetchone()
            self.db.execute(
                "INSERT INTO github_users"
                " (id, login, first_signed_in_at_ms, last_signed_in_at_ms) VALUES (?, ?, ?, ?)"
                " ON CONFLICT (id) DO UPDATE SET login = excluded.login,"
                " last_signed_in_at_ms = excluded.last_signed_in_at_ms",
                (github_id, login, now, now),
            )
            self.db.execute(
                "INSERT INTO key_owners (key_id, github_user_id, added_at_ms) VALUES (?, ?, ?)"
                " ON CONFLICT (key_id) DO UPDATE SET github_user_id = excluded.github_user_id,"
                " added_at_ms = excluded.added_at_ms",
                (key_id, github_id, now),
            )
            return known is None

        return self.transaction(record)

    # Expiry.

    def purge(self, now: int, message_ttl_ms: int) -> tuple[int, int]:
        """Deletes messages older than `message_ttl_ms` and expired invites.
        Returns how many of each were deleted."""

        def run() -> tuple[int, int]:
            messages = self.db.execute(
                "DELETE FROM messages WHERE arrived_at_ms < ?", (now - message_ttl_ms,)
            ).rowcount
            invites = self.db.execute(
                "DELETE FROM invites WHERE expires_at_ms <= ?", (now,)
            ).rowcount
            return messages, invites

        return self.transaction(run)
