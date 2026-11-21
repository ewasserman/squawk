/**
 * squawkd: the background service. It owns the identity and the database,
 * listens on a unix socket for local clients (Claude Code sessions, the
 * CLI, `squawk tail`) speaking newline-delimited JSON-RPC 2.0, and routes
 * incoming messages to those sessions.
 *
 * Network transports (mDNS discovery, the WebSocket listener) plug in
 * through `deliverIncoming` (for messages that arrive) and the `Transport`
 * interface (for messages to send), so routing does not depend on how a
 * message travels.
 */
import { randomUUID } from "node:crypto";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { z } from "zod";
import { dbPath, pidPath, runDir, socketPath } from "./config.ts";
import { isKeyId, keyFromId } from "./encoding.ts";
import {
	createEnvelope,
	type Envelope,
	type MessageKind,
	MessageKindSchema,
} from "./envelope.ts";
import { fingerprint, type Identity, loadIdentity } from "./identity.ts";
import {
	RpcClient,
	type RpcConnection,
	RpcError,
	RpcErrorCode,
	type RpcHandler,
	RpcServer,
} from "./rpc.ts";
import {
	type Contact,
	DEFAULT_INBOUND_POLICY_KEY,
	type InboundPolicy,
	Store,
	type StoredMessage,
} from "./store.ts";

/**
 * Sends queued outbound messages to other hosts. The daemon calls `kick`
 * after it adds a message to the store's outbound queue; the transport then
 * reads due items with `store.dueOutbound()` and delivers them.
 */
export interface Transport {
	/** Called once when the daemon starts, after the store is open. */
	start?(daemon: Daemon): Promise<void> | void;
	/** Called when the daemon stops, before the store is closed. */
	stop?(): Promise<void> | void;
	/** The outbound queue has a new item (`envelope`, already in the store). */
	kick(envelope: Envelope): Promise<void> | void;
	/** Other services seen on the network. */
	peers?(): Peer[];
	/** The TCP port other hosts connect to, if there is one. */
	readonly port?: number;
}

/** A transport that sends nothing; messages stay in the outbound queue. */
export const noTransport: Transport = { kick() {} };

/** Information about how an incoming message arrived. */
export interface IncomingInfo {
	/** When it was received; defaults to now. */
	receivedAt?: Date;
	/** The address it came from, for logging. */
	remoteAddress?: string;
}

/** What `deliverIncoming` did with a message. */
export interface IncomingResult {
	/** False if a message with the same id was already stored (nothing else happens). */
	stored: boolean;
	/** The label of the session it was pushed to, or null if it stays queued. */
	deliveredTo: string | null;
}

/** Params of the `message` notification sent to sessions and subscribers. */
export interface MessageNotification {
	envelope: Envelope;
	/** The sender's contact name, or null if the sender is not a contact. */
	from_name: string | null;
	policy: InboundPolicy;
}

/** A peer seen on the network. Empty until discovery is added. */
export interface Peer {
	name: string;
	key_id: string;
	fingerprint: string;
	host: string;
	port: number;
	paired: boolean;
}

export const SendParamsSchema = z.object({
	/** A contact name or key identifier. */
	to: z.string().min(1),
	body: z.string(),
	kind: MessageKindSchema.optional(),
	thread_id: z.string().min(1).max(128).optional(),
	in_reply_to: z.string().min(1).max(128).optional(),
	/** The label of the recipient's session that should get the message. */
	session: z.string().max(256).optional(),
});
export type SendParams = z.infer<typeof SendParamsSchema>;

export interface SendResult {
	id: string;
	thread_id: string;
	state: "queued";
}

/** A stored message as returned by the `get_message` method. */
export interface MessageInfo {
	id: string;
	/** "in" for a message received, "out" for one this machine sent. */
	direction: "in" | "out";
	/** The other party's key identifier: the sender for "in", the recipient for "out". */
	peer: string;
	/** The other party's contact name, or null if they are not a contact. */
	peer_name: string | null;
	session: string | null;
	thread_id: string;
	in_reply_to: string | null;
	kind: MessageKind;
	body: string;
	created_at: string;
	state: string;
}

/** A contact as returned by the `contacts` method. */
const InboundPolicySchema = z.enum(["show_first", "auto_answer"]);

const UpdateContactParamsSchema = z.object({
	/** A contact name or key identifier. */
	contact: z.string().min(1),
	auto_send: z.boolean().optional(),
	/** null clears the contact's own policy so the default applies. */
	inbound_policy: InboundPolicySchema.nullable().optional(),
});

const DefaultPolicyParamsSchema = z.object({ policy: InboundPolicySchema });

export interface ContactInfo {
	name: string;
	key_id: string;
	fingerprint: string;
	trust: "paired" | "blocked";
	auto_send: boolean;
	/** The policy that applies to this contact's messages (their own or the default). */
	inbound_policy: InboundPolicy;
	/** True when the contact has no policy of its own and follows the default. */
	policy_is_default: boolean;
}

export interface StatusResult {
	name: string;
	key_id: string;
	fingerprint: string;
	pid: number;
	sessions: Array<{ label: string; last_active: string }>;
	queued_inbound: number;
	queued_outbound: number;
	/** TCP port for other hosts, or null when the service has no network transport. */
	port: number | null;
}

export interface DaemonOptions {
	/** The squawk home directory (identity, database, run/). */
	home: string;
	/** Returns the current time in milliseconds since the epoch. */
	now?: () => number;
	transport?: Transport;
}

interface Session {
	id: string;
	label: string;
	connection: RpcConnection;
	/** Order of registration; larger is newer. */
	registeredSeq: number;
	/** Order of the last call on this connection; larger is more recent. */
	activeSeq: number;
	lastActive: number;
}

const RegisterParamsSchema = z.object({ label: z.string().min(1).max(256) });
const GetMessageParamsSchema = z.object({ id: z.string().min(1).max(128) });
const InboxParamsSchema = z
	.object({ mark_read: z.boolean().optional() })
	.optional();

function parseParams<T>(schema: z.ZodType<T>, params: unknown): T {
	const result = schema.safeParse(params ?? undefined);
	if (!result.success) {
		throw new RpcError(
			RpcErrorCode.InvalidParams,
			`invalid params: ${z.prettifyError(result.error)}`,
		);
	}
	return result.data;
}

/** Thrown by `Daemon.start` when another service is already listening on the socket. */
export class DaemonRunningError extends Error {
	constructor(path: string) {
		super(`squawkd is already running (socket ${path})`);
		this.name = "DaemonRunningError";
	}
}

/** Resolves true if a server answers on the socket at `path`. */
async function socketAnswers(path: string): Promise<boolean> {
	try {
		const client = await RpcClient.connect(path);
		await client.close();
		return true;
	} catch {
		return false;
	}
}

export class Daemon {
	readonly home: string;
	readonly socketPath: string;
	transport: Transport;
	readonly #now: () => number;
	readonly #sessions = new Map<RpcConnection, Session>();
	readonly #subscribers = new Set<RpcConnection>();
	#identity: Identity | undefined;
	#store: Store | undefined;
	#server: RpcServer | undefined;
	#seq = 0;
	#stopping: Promise<void> | undefined;
	#resolveStopped: () => void = () => {};
	readonly #stopped: Promise<void>;

	constructor(options: DaemonOptions) {
		this.home = options.home;
		this.socketPath = socketPath(options.home);
		this.transport = options.transport ?? noTransport;
		this.#now = options.now ?? Date.now;
		this.#stopped = new Promise((resolve) => {
			this.#resolveStopped = resolve;
		});
	}

	get identity(): Identity {
		if (this.#identity === undefined) throw new Error("daemon not started");
		return this.#identity;
	}

	get store(): Store {
		if (this.#store === undefined) throw new Error("daemon not started");
		return this.#store;
	}

	/** Resolves once the daemon has stopped (by `stop()` or the `stop` method). */
	whenStopped(): Promise<void> {
		return this.#stopped;
	}

	/**
	 * Loads the identity, opens the store, and listens on the socket. Throws
	 * `DaemonRunningError` if another service answers on the socket.
	 */
	async start(): Promise<void> {
		this.#identity = await loadIdentity(this.home);
		const run = runDir(this.home);
		mkdirSync(run, { recursive: true, mode: 0o700 });
		chmodSync(run, 0o700);
		if (await socketAnswers(this.socketPath)) {
			throw new DaemonRunningError(this.socketPath);
		}
		// Nothing answered, so any socket file left behind is stale.
		rmSync(this.socketPath, { force: true });

		this.#store = Store.open(dbPath(this.home), { now: this.#now });
		const server = new RpcServer({
			onCall: (connection) => this.#touch(connection),
		});
		this.#registerMethods(server);
		await server.listen(this.socketPath);
		chmodSync(this.socketPath, 0o600);
		this.#server = server;
		writeFileSync(pidPath(this.home), `${process.pid}\n`, { mode: 0o600 });
		try {
			await this.transport.start?.(this);
		} catch (err) {
			// Do not keep running half-started (answering on the socket with no
			// network): shut down and report the failure.
			await this.stop();
			throw err;
		}
	}

	/** Stops listening, closes every connection and the store. Safe to call twice. */
	stop(): Promise<void> {
		this.#stopping ??= (async () => {
			try {
				await this.transport.stop?.();
			} finally {
				await this.#server?.close();
				this.#sessions.clear();
				this.#subscribers.clear();
				if (this.#server !== undefined) {
					rmSync(this.socketPath, { force: true });
					rmSync(pidPath(this.home), { force: true });
				}
				this.#store?.close();
				this.#resolveStopped();
			}
		})();
		return this.#stopping;
	}

	/**
	 * Saves a message that arrived from another host and routes it:
	 *   1. to the session whose label the envelope names, if one is open;
	 *   2. otherwise to the most recently active session;
	 *   3. with no session open, it stays queued and is pushed when a session registers.
	 * Every subscriber also gets it. A duplicate (same id) is ignored.
	 */
	deliverIncoming(envelope: Envelope, info: IncomingInfo = {}): IncomingResult {
		const stored = this.store.saveIncoming(
			envelope,
			info.receivedAt ?? new Date(this.#now()),
		);
		if (!stored) return { stored: false, deliveredTo: null };
		const notification = this.#notification(envelope);
		for (const subscriber of this.#subscribers) {
			subscriber.notify("message", notification);
		}
		const target =
			this.#sessionByLabel(envelope.session) ?? this.#mostRecentlyActive();
		if (target !== undefined && this.#push(target, envelope.id, notification)) {
			return { stored: true, deliveredTo: target.label };
		}
		return { stored: true, deliveredTo: null };
	}

	/**
	 * Creates, saves and queues a message to a contact, then tells the
	 * transport. Throws `RpcError` if `to` is not a known contact, or is a
	 * blocked one (such a message could never be delivered).
	 */
	async send(params: SendParams): Promise<SendResult> {
		const contact = this.resolveContact(params.to);
		if (contact.trust !== "paired") {
			throw new RpcError(
				RpcErrorCode.ApplicationError,
				`"${contact.name}" is blocked; run \`squawk unblock ${contact.name}\` before sending to them`,
			);
		}
		const input: Parameters<typeof createEnvelope>[0] = {
			from: this.identity.id,
			to: contact.publicKey,
			body: params.body,
			created_at: new Date(this.#now()),
		};
		if (params.kind !== undefined) input.kind = params.kind;
		if (params.thread_id !== undefined) input.thread_id = params.thread_id;
		if (params.in_reply_to !== undefined)
			input.in_reply_to = params.in_reply_to;
		if (params.session !== undefined) input.session = params.session;
		const envelope = createEnvelope(input);
		this.store.queueOutgoing(envelope);
		try {
			await this.transport.kick(envelope);
		} catch (err) {
			// The message is safely queued; the transport retries later.
			console.error("squawkd: transport failed:", err);
		}
		return { id: envelope.id, thread_id: envelope.thread_id, state: "queued" };
	}

	/**
	 * Finds a contact by key identifier, or else by name (exact, then
	 * ignoring case). Throws `RpcError` if there is none or the name is ambiguous.
	 */
	resolveContact(to: string): Contact {
		if (isKeyId(to)) {
			const byKey = this.store.getContact(to);
			if (byKey !== undefined) return byKey;
		}
		const contacts = this.store.listContacts();
		let matches = contacts.filter((c) => c.name === to);
		if (matches.length === 0) {
			const lower = to.toLowerCase();
			matches = contacts.filter((c) => c.name.toLowerCase() === lower);
		}
		if (matches.length === 1) return matches[0] as Contact;
		if (matches.length > 1) {
			throw new RpcError(
				RpcErrorCode.ApplicationError,
				`more than one contact is named "${to}"; use the key id instead`,
			);
		}
		throw new RpcError(
			RpcErrorCode.ApplicationError,
			`unknown contact "${to}"; pair with them first or use a contact name from "squawk contacts"`,
		);
	}

	/** Peers seen on the network. Empty until discovery is added. */
	peers(): Peer[] {
		return this.transport.peers?.() ?? [];
	}

	/**
	 * Adds a JSON-RPC method to the local socket. Transports call this from
	 * `start` to offer their own methods (pairing, for example).
	 */
	handle(method: string, handler: RpcHandler): void {
		if (!this.#server) throw new Error("the service is not started");
		this.#server.handle(method, handler);
	}

	/** Every contact, paired or blocked, sorted by name. */
	contacts(): ContactInfo[] {
		return this.store
			.listContacts()
			.map((c) => ({
				name: c.name,
				key_id: c.publicKey,
				fingerprint: fingerprint(keyFromId(c.publicKey)),
				trust: c.trust,
				auto_send: c.autoSend,
				inbound_policy: this.store.inboundPolicyFor(c.publicKey),
				policy_is_default: c.inboundPolicy === null,
			}))
			.sort((a, b) => a.name.localeCompare(b.name));
	}

	status(): StatusResult {
		const sessions = [...this.#sessions.values()]
			.sort((a, b) => b.activeSeq - a.activeSeq)
			.map((s) => ({
				label: s.label,
				last_active: new Date(s.lastActive).toISOString(),
			}));
		return {
			name: this.identity.name,
			key_id: this.identity.id,
			fingerprint: fingerprint(this.identity.publicKey),
			pid: process.pid,
			sessions,
			queued_inbound: this.store.countUndeliveredIncoming(),
			queued_outbound: this.store.countOutbound(),
			port: this.transport.port ?? null,
		};
	}

	#registerMethods(server: RpcServer): void {
		server
			.handle("register_session", (params, connection) => {
				const { label } = parseParams(RegisterParamsSchema, params);
				return this.#registerSession(connection, label);
			})
			.handle("send", (params) =>
				this.send(parseParams(SendParamsSchema, params)),
			)
			.handle("peers", () => ({ peers: this.peers() }))
			.handle("contacts", () => ({ contacts: this.contacts() }))
			.handle("update_contact", (params) => {
				const p = parseParams(UpdateContactParamsSchema, params);
				const contact = this.resolveContact(p.contact);
				const changes: {
					autoSend?: boolean;
					inboundPolicy?: InboundPolicy | null;
				} = {};
				if (p.auto_send !== undefined) changes.autoSend = p.auto_send;
				if (p.inbound_policy !== undefined)
					changes.inboundPolicy = p.inbound_policy;
				this.store.updateContact(contact.publicKey, changes);
				return {
					contact: this.contacts().find((c) => c.key_id === contact.publicKey),
				};
			})
			.handle("set_default_policy", (params) => {
				const { policy } = parseParams(DefaultPolicyParamsSchema, params);
				this.store.setSetting(DEFAULT_INBOUND_POLICY_KEY, policy);
				return { policy };
			})
			.handle("get_message", (params) => {
				const { id } = parseParams(GetMessageParamsSchema, params);
				const message = this.store.getMessage(id);
				if (message === undefined) {
					throw new RpcError(
						RpcErrorCode.ApplicationError,
						`no message with id "${id}"`,
					);
				}
				return { message: this.#messageInfo(message) };
			})
			.handle("inbox", (params) => {
				const options = parseParams(InboxParamsSchema, params);
				const messages = this.store.inbox();
				if (options?.mark_read && messages.length > 0) {
					this.store.markRead(messages.map((m) => m.id));
				}
				return {
					messages: messages.map((m) =>
						this.#notification(this.#envelopeOf(m)),
					),
				};
			})
			.handle("subscribe", (_params, connection) => {
				this.#subscribers.add(connection);
				connection.onClose(() => this.#subscribers.delete(connection));
				return { ok: true };
			})
			.handle("status", () => this.status())
			.handle("stop", () => {
				// Answer first, then shut down.
				setImmediate(() => void this.stop());
				return { ok: true };
			});
	}

	#registerSession(
		connection: RpcConnection,
		label: string,
	): { session_id: string; label: string } {
		const isNew = !this.#sessions.has(connection);
		const seq = ++this.#seq;
		const session: Session = {
			id: randomUUID(),
			label,
			connection,
			registeredSeq: seq,
			activeSeq: seq,
			lastActive: this.#now(),
		};
		this.#sessions.set(connection, session);
		if (isNew) {
			connection.onClose(() => this.#sessions.delete(connection));
		}
		// Push queued messages after the response has been written.
		setImmediate(() => this.#flushQueued(session));
		return { session_id: session.id, label };
	}

	/** Pushes undelivered incoming messages now that `registered` has opened. */
	#flushQueued(registered: Session): void {
		if (this.#store === undefined || registered.connection.closed) return;
		for (const message of this.store.undeliveredIncoming()) {
			const target = this.#sessionByLabel(message.session) ?? registered;
			const envelope = this.#envelopeOf(message);
			this.#push(target, message.id, this.#notification(envelope));
		}
	}

	#push(
		session: Session,
		messageId: string,
		notification: MessageNotification,
	): boolean {
		if (!session.connection.notify("message", notification)) return false;
		this.store.markDelivered(messageId);
		return true;
	}

	#touch(connection: RpcConnection): void {
		const session = this.#sessions.get(connection);
		if (session === undefined) return;
		session.activeSeq = ++this.#seq;
		session.lastActive = this.#now();
	}

	/** The newest registration with this label, if any is open. */
	#sessionByLabel(label: string | null | undefined): Session | undefined {
		if (label === undefined || label === null) return undefined;
		let best: Session | undefined;
		for (const session of this.#sessions.values()) {
			if (
				session.label === label &&
				(best === undefined || session.registeredSeq > best.registeredSeq)
			) {
				best = session;
			}
		}
		return best;
	}

	#mostRecentlyActive(): Session | undefined {
		let best: Session | undefined;
		for (const session of this.#sessions.values()) {
			if (best === undefined || session.activeSeq > best.activeSeq) {
				best = session;
			}
		}
		return best;
	}

	#notification(envelope: Envelope): MessageNotification {
		return {
			envelope,
			from_name: this.store.getContact(envelope.from)?.name ?? null,
			policy: this.store.inboundPolicyFor(envelope.from),
		};
	}

	#messageInfo(message: StoredMessage): MessageInfo {
		return {
			id: message.id,
			direction: message.direction,
			peer: message.peer,
			peer_name: this.store.getContact(message.peer)?.name ?? null,
			session: message.session,
			thread_id: message.threadId,
			in_reply_to: message.inReplyTo,
			kind: message.kind,
			body: message.body,
			created_at: message.createdAt,
			state: message.state,
		};
	}

	/** Rebuilds the envelope of a stored incoming message. */
	#envelopeOf(message: StoredMessage): Envelope {
		const envelope: Envelope = {
			id: message.id,
			from: message.peer,
			to: this.identity.id,
			thread_id: message.threadId,
			created_at: message.createdAt,
			kind: message.kind,
			body: message.body,
		};
		if (message.session !== null) envelope.session = message.session;
		if (message.inReplyTo !== null) envelope.in_reply_to = message.inReplyTo;
		return envelope;
	}
}
