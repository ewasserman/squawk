/**
 * Local SQLite storage for contacts, messages, the outbound queue,
 * acknowledgements, threads, seen message ids and settings.
 *
 * Timestamps in text columns are ISO 8601 strings in UTC (as produced by
 * `Date.prototype.toISOString`), so they sort correctly as text. Columns
 * used for scheduling or expiry (`next_attempt_at`, `seen_ids.created_at_ms`)
 * are milliseconds since the epoch.
 */
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type { Envelope, MessageKind, Sealed, SeenIdStore } from "./envelope.ts";

/**
 * Schema migrations, applied in order. The database's `PRAGMA user_version`
 * holds how many have been applied. Never edit or reorder an entry that has
 * shipped; add a new one at the end instead.
 */
export const MIGRATIONS: readonly string[] = [
	`
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
	`,
	// When an incoming message was pushed to a local session by the background
	// service. NULL means it is still waiting for a session to open.
	`
	ALTER TABLE messages ADD COLUMN delivered_at TEXT;
	CREATE INDEX messages_undelivered ON messages (direction, delivered_at, created_at);
	`,
];

export type Trust = "paired" | "blocked";
export type InboundPolicy = "show_first" | "auto_answer";
export type Direction = "in" | "out";
/** Outgoing: queued, sent, acked, failed. Incoming: unread, read. */
export type MessageState =
	| "queued"
	| "sent"
	| "acked"
	| "failed"
	| "unread"
	| "read";

/** Setting key holding the inbound policy for contacts that have none of their own. */
export const DEFAULT_INBOUND_POLICY_KEY = "default_inbound_policy";

export interface Contact {
	publicKey: string;
	name: string;
	trust: Trust;
	autoSend: boolean;
	/** null means "use the default inbound policy setting". */
	inboundPolicy: InboundPolicy | null;
	createdAt: string;
	updatedAt: string;
}

export interface ContactInput {
	publicKey: string;
	name: string;
	trust?: Trust;
	autoSend?: boolean;
	inboundPolicy?: InboundPolicy | null;
}

export interface ContactChanges {
	name?: string;
	trust?: Trust;
	autoSend?: boolean;
	/** Pass null to clear it and fall back to the default. */
	inboundPolicy?: InboundPolicy | null;
}

export interface StoredMessage {
	id: string;
	direction: Direction;
	/** The other party's key identifier: the recipient for "out", the sender for "in". */
	peer: string;
	session: string | null;
	threadId: string;
	inReplyTo: string | null;
	kind: MessageKind;
	body: string;
	createdAt: string;
	receivedAt: string | null;
	sentAt: string | null;
	readAt: string | null;
	/** Incoming only: when the background service pushed it to a local session. */
	deliveredAt: string | null;
	state: MessageState;
}

export interface OutboundItem {
	messageId: string;
	recipient: string;
	sealed: Sealed;
	attempts: number;
	/** Milliseconds since the epoch. */
	nextAttemptAt: number;
	lastError: string | null;
}

export interface Thread {
	threadId: string;
	peer: string;
	/** First line of the first message in the thread, shortened. */
	subject: string;
	createdAt: string;
	updatedAt: string;
}

export interface StoreOptions {
	/** Returns the current time in milliseconds since the epoch. */
	now?: () => number;
	/** Delay before the first retry; doubles on each attempt. Default 2 seconds. */
	retryBaseMs?: number;
	/** Longest delay between retries. Default 5 minutes. */
	retryMaxMs?: number;
}

const SUBJECT_MAX = 120;

type Row = Record<string, unknown>;

function toContact(row: Row): Contact {
	return {
		publicKey: row.public_key as string,
		name: row.name as string,
		trust: row.trust as Trust,
		autoSend: row.auto_send === 1,
		inboundPolicy: (row.inbound_policy as InboundPolicy | null) ?? null,
		createdAt: row.created_at as string,
		updatedAt: row.updated_at as string,
	};
}

function toMessage(row: Row): StoredMessage {
	return {
		id: row.id as string,
		direction: row.direction as Direction,
		peer: row.peer as string,
		session: (row.session as string | null) ?? null,
		threadId: row.thread_id as string,
		inReplyTo: (row.in_reply_to as string | null) ?? null,
		kind: row.kind as MessageKind,
		body: row.body as string,
		createdAt: row.created_at as string,
		receivedAt: (row.received_at as string | null) ?? null,
		sentAt: (row.sent_at as string | null) ?? null,
		readAt: (row.read_at as string | null) ?? null,
		deliveredAt: (row.delivered_at as string | null) ?? null,
		state: row.state as MessageState,
	};
}

function toOutbound(row: Row): OutboundItem {
	return {
		messageId: row.message_id as string,
		recipient: row.recipient as string,
		sealed: JSON.parse(row.payload as string) as Sealed,
		attempts: Number(row.attempts),
		nextAttemptAt: Number(row.next_attempt_at),
		lastError: (row.last_error as string | null) ?? null,
	};
}

function toThread(row: Row): Thread {
	return {
		threadId: row.thread_id as string,
		peer: row.peer as string,
		subject: row.subject as string,
		createdAt: row.created_at as string,
		updatedAt: row.updated_at as string,
	};
}

function subjectOf(body: string): string {
	const firstLine =
		body
			.split("\n")
			.map((line) => line.replace(/^#+\s*/, "").trim())
			.find((line) => line !== "") ?? "";
	return firstLine.length > SUBJECT_MAX
		? `${firstLine.slice(0, SUBJECT_MAX - 1)}…`
		: firstLine;
}

function iso(time: string | number | Date): string {
	return new Date(time).toISOString();
}

export class Store {
	readonly db: DatabaseSync;
	readonly #now: () => number;
	readonly #retryBaseMs: number;
	readonly #retryMaxMs: number;

	private constructor(db: DatabaseSync, options: StoreOptions) {
		this.db = db;
		this.#now = options.now ?? Date.now;
		this.#retryBaseMs = options.retryBaseMs ?? 2_000;
		this.#retryMaxMs = options.retryMaxMs ?? 5 * 60_000;
	}

	/**
	 * Opens (creating if needed) the database at `path` and applies any
	 * migrations not yet applied. Use ":memory:" for a throwaway database.
	 * A database file is given mode 0600, since it holds private messages.
	 */
	static open(path: string, options: StoreOptions = {}): Store {
		const inMemory = path === ":memory:";
		if (!inMemory) {
			mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		}
		const db = new DatabaseSync(path);
		if (!inMemory) {
			chmodSync(path, 0o600);
			db.exec("PRAGMA journal_mode = WAL");
		}
		db.exec("PRAGMA foreign_keys = ON");
		db.exec("PRAGMA busy_timeout = 5000");
		const store = new Store(db, options);
		store.migrate();
		return store;
	}

	close(): void {
		this.db.close();
	}

	/** The number of migrations applied (the database's `user_version`). */
	schemaVersion(): number {
		const row = this.db.prepare("PRAGMA user_version").get() as Row;
		return Number(row.user_version);
	}

	/** Applies, in one transaction each, every migration not yet applied. */
	migrate(): void {
		for (let v = this.schemaVersion(); v < MIGRATIONS.length; v++) {
			this.transaction(() => {
				this.db.exec(MIGRATIONS[v] as string);
				this.db.exec(`PRAGMA user_version = ${v + 1}`);
			});
		}
	}

	/** Runs `fn` inside a transaction, rolling back if it throws. */
	transaction<T>(fn: () => T): T {
		if (this.db.isTransaction) {
			return fn();
		}
		this.db.exec("BEGIN IMMEDIATE");
		try {
			const result = fn();
			this.db.exec("COMMIT");
			return result;
		} catch (err) {
			this.db.exec("ROLLBACK");
			throw err;
		}
	}

	#nowIso(): string {
		return iso(this.#now());
	}

	// Contacts

	/** Adds a contact, or updates the name and any given fields of an existing one. */
	upsertContact(input: ContactInput): Contact {
		const now = this.#nowIso();
		this.transaction(() => {
			const existing = this.getContact(input.publicKey);
			if (existing === undefined) {
				this.db
					.prepare(
						`INSERT INTO contacts
						 (public_key, name, trust, auto_send, inbound_policy, created_at, updated_at)
						 VALUES (?, ?, ?, ?, ?, ?, ?)`,
					)
					.run(
						input.publicKey,
						input.name,
						input.trust ?? "paired",
						input.autoSend ? 1 : 0,
						input.inboundPolicy ?? null,
						now,
						now,
					);
			} else {
				const changes: ContactChanges = { name: input.name };
				if (input.trust !== undefined) changes.trust = input.trust;
				if (input.autoSend !== undefined) changes.autoSend = input.autoSend;
				if (input.inboundPolicy !== undefined)
					changes.inboundPolicy = input.inboundPolicy;
				this.updateContact(input.publicKey, changes);
			}
		});
		return this.getContact(input.publicKey) as Contact;
	}

	getContact(publicKey: string): Contact | undefined {
		const row = this.db
			.prepare("SELECT * FROM contacts WHERE public_key = ?")
			.get(publicKey);
		return row === undefined ? undefined : toContact(row);
	}

	listContacts(): Contact[] {
		return this.db
			.prepare("SELECT * FROM contacts ORDER BY name, public_key")
			.all()
			.map(toContact);
	}

	/** Changes the given fields of a contact. Throws if there is no such contact. */
	updateContact(publicKey: string, changes: ContactChanges): Contact {
		const sets: string[] = [];
		const values: SQLInputValue[] = [];
		if (changes.name !== undefined) {
			sets.push("name = ?");
			values.push(changes.name);
		}
		if (changes.trust !== undefined) {
			sets.push("trust = ?");
			values.push(changes.trust);
		}
		if (changes.autoSend !== undefined) {
			sets.push("auto_send = ?");
			values.push(changes.autoSend ? 1 : 0);
		}
		if (changes.inboundPolicy !== undefined) {
			sets.push("inbound_policy = ?");
			values.push(changes.inboundPolicy);
		}
		sets.push("updated_at = ?");
		values.push(this.#nowIso());
		const result = this.db
			.prepare(`UPDATE contacts SET ${sets.join(", ")} WHERE public_key = ?`)
			.run(...values, publicKey);
		if (result.changes === 0) {
			throw new Error(`no contact with key ${publicKey}`);
		}
		return this.getContact(publicKey) as Contact;
	}

	/** The contact's own inbound policy, else the default setting, else "show_first". */
	inboundPolicyFor(publicKey: string): InboundPolicy {
		const own = this.getContact(publicKey)?.inboundPolicy;
		if (own) return own;
		const fallback = this.getSetting(DEFAULT_INBOUND_POLICY_KEY);
		return fallback === "auto_answer" ? "auto_answer" : "show_first";
	}

	// Messages and threads

	#insertMessage(
		envelope: Envelope,
		direction: Direction,
		state: MessageState,
		receivedAt: string | null,
	): boolean {
		const peer = direction === "out" ? envelope.to : envelope.from;
		const result = this.db
			.prepare(
				`INSERT OR IGNORE INTO messages
				 (id, direction, peer, session, thread_id, in_reply_to, kind, body,
				  created_at, received_at, state)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				envelope.id,
				direction,
				peer,
				envelope.session ?? null,
				envelope.thread_id,
				envelope.in_reply_to ?? null,
				envelope.kind,
				envelope.body,
				iso(envelope.created_at),
				receivedAt,
				state,
			);
		if (result.changes === 0) {
			return false;
		}
		const createdAt = iso(envelope.created_at);
		this.db
			.prepare(
				`INSERT INTO threads (thread_id, peer, subject, created_at, updated_at)
				 VALUES (?, ?, ?, ?, ?)
				 ON CONFLICT (thread_id) DO UPDATE
				 SET updated_at = max(threads.updated_at, excluded.updated_at)`,
			)
			.run(
				envelope.thread_id,
				peer,
				subjectOf(envelope.body),
				createdAt,
				createdAt,
			);
		return true;
	}

	/**
	 * Saves a message received from a peer as unread. Returns false (and
	 * changes nothing) if a message with this id is already stored.
	 */
	saveIncoming(envelope: Envelope, receivedAt: Date = new Date(this.#now())) {
		return this.transaction(() =>
			this.#insertMessage(envelope, "in", "unread", iso(receivedAt)),
		);
	}

	/** Saves a message this machine is sending, without queueing it. */
	saveOutgoing(envelope: Envelope, state: MessageState = "queued"): boolean {
		return this.transaction(() =>
			this.#insertMessage(envelope, "out", state, null),
		);
	}

	getMessage(id: string): StoredMessage | undefined {
		const row = this.db.prepare("SELECT * FROM messages WHERE id = ?").get(id);
		return row === undefined ? undefined : toMessage(row);
	}

	/** Messages in a thread, oldest first. */
	listThread(threadId: string): StoredMessage[] {
		return this.db
			.prepare(
				"SELECT * FROM messages WHERE thread_id = ? ORDER BY created_at, rowid",
			)
			.all(threadId)
			.map(toMessage);
	}

	getThread(threadId: string): Thread | undefined {
		const row = this.db
			.prepare("SELECT * FROM threads WHERE thread_id = ?")
			.get(threadId);
		return row === undefined ? undefined : toThread(row);
	}

	/** Threads, most recently active first, optionally only those with `peer`. */
	listThreads(peer?: string): Thread[] {
		const stmt =
			peer === undefined
				? this.db.prepare("SELECT * FROM threads ORDER BY updated_at DESC")
				: this.db.prepare(
						"SELECT * FROM threads WHERE peer = ? ORDER BY updated_at DESC",
					);
		const rows = peer === undefined ? stmt.all() : stmt.all(peer);
		return rows.map(toThread);
	}

	/** Unread incoming messages, oldest first. */
	inbox(): StoredMessage[] {
		return this.db
			.prepare(
				`SELECT * FROM messages WHERE direction = 'in' AND state = 'unread'
				 ORDER BY created_at, rowid`,
			)
			.all()
			.map(toMessage);
	}

	/** Marks incoming messages as read. Returns how many changed. */
	markRead(ids: string | readonly string[]): number {
		const list = typeof ids === "string" ? [ids] : ids;
		const readAt = this.#nowIso();
		const stmt = this.db.prepare(
			`UPDATE messages SET state = 'read', read_at = ?
			 WHERE id = ? AND direction = 'in' AND state = 'unread'`,
		);
		return this.transaction(() =>
			list.reduce((n, id) => n + Number(stmt.run(readAt, id).changes), 0),
		);
	}

	/**
	 * Unread incoming messages not yet pushed to a local session, oldest first.
	 */
	undeliveredIncoming(): StoredMessage[] {
		return this.db
			.prepare(
				`SELECT * FROM messages
				 WHERE direction = 'in' AND state = 'unread' AND delivered_at IS NULL
				 ORDER BY created_at, rowid`,
			)
			.all()
			.map(toMessage);
	}

	/** How many messages `undeliveredIncoming` would return. */
	countUndeliveredIncoming(): number {
		const row = this.db
			.prepare(
				`SELECT count(*) AS n FROM messages
				 WHERE direction = 'in' AND state = 'unread' AND delivered_at IS NULL`,
			)
			.get() as Row;
		return Number(row.n);
	}

	/** Records that an incoming message was pushed to a local session. Returns false if it already had been. */
	markDelivered(id: string): boolean {
		const result = this.db
			.prepare(
				`UPDATE messages SET delivered_at = ?
				 WHERE id = ? AND direction = 'in' AND delivered_at IS NULL`,
			)
			.run(this.#nowIso(), id);
		return result.changes > 0;
	}

	// Outbound queue

	/** How many messages are in the outbound queue. */
	countOutbound(): number {
		const row = this.db
			.prepare("SELECT count(*) AS n FROM outbox")
			.get() as Row;
		return Number(row.n);
	}

	/** Adds a sealed message to the outbound queue, due immediately unless told otherwise. */
	enqueue(
		messageId: string,
		sealed: Sealed,
		nextAttemptAt: number = this.#now(),
	): void {
		this.db
			.prepare(
				`INSERT INTO outbox (message_id, recipient, payload, attempts, next_attempt_at)
				 VALUES (?, ?, ?, 0, ?)`,
			)
			.run(messageId, sealed.to, JSON.stringify(sealed), nextAttemptAt);
	}

	/** Saves an outgoing message and queues its sealed form in one transaction. */
	queueOutgoing(envelope: Envelope, sealed: Sealed): void {
		this.transaction(() => {
			this.saveOutgoing(envelope, "queued");
			this.enqueue(envelope.id, sealed);
		});
	}

	/** Queue items whose next attempt time has come, earliest first. */
	dueOutbound(now: number = this.#now(), limit = 100): OutboundItem[] {
		return this.db
			.prepare(
				`SELECT * FROM outbox WHERE next_attempt_at <= ?
				 ORDER BY next_attempt_at, message_id LIMIT ?`,
			)
			.all(now, limit)
			.map(toOutbound);
	}

	getOutbound(messageId: string): OutboundItem | undefined {
		const row = this.db
			.prepare("SELECT * FROM outbox WHERE message_id = ?")
			.get(messageId);
		return row === undefined ? undefined : toOutbound(row);
	}

	/**
	 * Records a failed delivery attempt and schedules the next one. The delay
	 * is `retryBaseMs * 2^(attempts - 1)`, capped at `retryMaxMs`, unless
	 * `nextAttemptAt` is given. Returns the time of the next attempt.
	 */
	recordAttempt(
		messageId: string,
		options: { error?: string; nextAttemptAt?: number } = {},
	): number {
		return this.transaction(() => {
			const item = this.getOutbound(messageId);
			if (item === undefined) {
				throw new Error(`message ${messageId} is not in the outbound queue`);
			}
			const attempts = item.attempts + 1;
			const delay = Math.min(
				this.#retryBaseMs * 2 ** (attempts - 1),
				this.#retryMaxMs,
			);
			const next = options.nextAttemptAt ?? this.#now() + delay;
			this.db
				.prepare(
					`UPDATE outbox SET attempts = ?, next_attempt_at = ?, last_error = ?
					 WHERE message_id = ?`,
				)
				.run(attempts, next, options.error ?? null, messageId);
			return next;
		});
	}

	/**
	 * Records that the recipient acknowledged a message: adds an ack row,
	 * removes the message from the outbound queue and marks it acked.
	 * Returns false if it had already been acknowledged.
	 */
	markAcknowledged(
		messageId: string,
		ackedAt: Date = new Date(this.#now()),
	): boolean {
		const at = iso(ackedAt);
		return this.transaction(() => {
			const inserted = this.db
				.prepare(
					"INSERT OR IGNORE INTO acks (message_id, acked_at) VALUES (?, ?)",
				)
				.run(messageId, at);
			this.db.prepare("DELETE FROM outbox WHERE message_id = ?").run(messageId);
			this.db
				.prepare(
					`UPDATE messages SET state = 'acked', sent_at = coalesce(sent_at, ?)
					 WHERE id = ? AND direction = 'out'`,
				)
				.run(at, messageId);
			return inserted.changes > 0;
		});
	}

	/** When a message was acknowledged, or undefined if it has not been. */
	ackedAt(messageId: string): string | undefined {
		const row = this.db
			.prepare("SELECT acked_at FROM acks WHERE message_id = ?")
			.get(messageId);
		return row === undefined ? undefined : (row.acked_at as string);
	}

	// Settings

	getSetting(key: string): string | undefined {
		const row = this.db
			.prepare("SELECT value FROM settings WHERE key = ?")
			.get(key);
		return row === undefined ? undefined : (row.value as string);
	}

	setSetting(key: string, value: string): void {
		this.db
			.prepare(
				`INSERT INTO settings (key, value) VALUES (?, ?)
				 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			)
			.run(key, value);
	}

	// Seen message ids (replay protection)

	/**
	 * A `SeenIdStore` backed by the seen_ids table, for use with
	 * `new ReplayGuard({ seen: store.seenIds() })`.
	 */
	seenIds(): SeenIdStore & { prune(cutoffMs: number): number } {
		const db = this.db;
		return {
			has(id) {
				return (
					db.prepare("SELECT 1 FROM seen_ids WHERE id = ?").get(id) !==
					undefined
				);
			},
			add(id, createdAtMs) {
				db.prepare(
					"INSERT OR IGNORE INTO seen_ids (id, created_at_ms) VALUES (?, ?)",
				).run(id, createdAtMs);
			},
			/** Forgets ids created before `cutoffMs`; returns how many were removed. */
			prune(cutoffMs) {
				return Number(
					db
						.prepare("DELETE FROM seen_ids WHERE created_at_ms < ?")
						.run(cutoffMs).changes,
				);
			},
		};
	}
}
