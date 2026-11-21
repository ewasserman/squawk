/**
 * Sending sealed messages between hosts over WebSocket.
 *
 * Every service runs a WebSocket listener. When a connection opens, both
 * sides prove who they are before anything else is exchanged:
 *
 *   1. Each side sends `hello` with its key id and a fresh 32-byte random
 *      challenge.
 *   2. Each side answers with `auth`: an ed25519 signature over the other
 *      side's challenge plus both key ids. Binding both keys means a signature
 *      made for one connection cannot be relayed into another.
 *   3. Each side checks the signature against the claimed key, then asks
 *      whether that key is allowed: normally only paired, unblocked contacts
 *      are. The side that dialled also checks that it reached the key it meant
 *      to reach. Otherwise the connection is closed.
 *   4. Each side that accepts the other sends `ok`. A side treats the
 *      connection as ready only when it has accepted the other side AND
 *      received the other side's `ok`, so neither side starts sending to a
 *      peer that is about to refuse it.
 *
 * After that, the dialling side sends `msg` frames (a message id plus the
 * sealed message). The receiver opens the sealed message (which checks the
 * signature, the recipient, the timestamp and that the id is new), hands it
 * to the daemon, and answers `ack`. Messages without an ack stay in the
 * store's outbound queue and are retried with backoff.
 *
 * Other frame types (used by pairing) can be added with `onFrame`.
 */
import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { ed25519 } from "@noble/curves/ed25519.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { type RawData, WebSocket, WebSocketServer } from "ws";
import type { Daemon, Peer, Transport } from "./daemon.ts";
import { type DiscoveredPeer, Discovery } from "./discovery.ts";
import { fromBase64Url, isKeyId, keyFromId, toBase64Url } from "./encoding.ts";
import {
	EnvelopeError,
	open,
	ReplayGuard,
	type Sealed,
	SealedSchema,
} from "./envelope.ts";
import { fingerprint, type Identity } from "./identity.ts";

export const PROTOCOL_VERSION = 1;
const AUTH_PREFIX = "squawk ws auth v1";

/** Where to reach a peer's WebSocket listener. */
export interface Address {
	host: string;
	port: number;
}

/** A JSON frame on an authenticated connection. */
export type Frame = { t: string } & Record<string, unknown>;

/** What a connection's peer is allowed to do once authenticated. */
export type Authorization = "paired" | "pairing" | false;

/** Text signed in `auth`: the challenge we were sent, our key, their key. */
export function authMessage(
	challenge: string,
	signerKey: string,
	otherKey: string,
): Uint8Array {
	return utf8ToBytes(`${AUTH_PREFIX}\n${challenge}\n${signerKey}\n${otherKey}`);
}

/**
 * One WebSocket connection to another squawk service, with the handshake
 * described at the top of this file.
 */
export class PeerLink {
	readonly ws: WebSocket;
	readonly outgoing: boolean;
	/** The other side's key id, once it has proved it holds that key. */
	peerKey: string | undefined;
	authorization: Authorization = false;
	readonly ready: Promise<string>;
	private readonly challenge = toBase64Url(randomBytes(32));
	private resolveReady!: (key: string) => void;
	private rejectReady!: (err: Error) => void;
	private sentAuth = false;
	private gotAuth = false;
	private gotOk = false;
	private readonly frameListeners = new Set<(frame: Frame) => void>();
	private readonly self: Identity;
	private readonly authorize: (key: string, link: PeerLink) => Authorization;

	constructor(
		ws: WebSocket,
		self: Identity,
		authorize: (key: string, link: PeerLink) => Authorization,
		options: { outgoing: boolean; expectKey?: string; timeoutMs?: number },
	) {
		this.ws = ws;
		this.self = self;
		this.authorize = authorize;
		this.outgoing = options.outgoing;
		this.ready = new Promise((resolve, reject) => {
			this.resolveReady = resolve;
			this.rejectReady = reject;
		});
		this.ready.catch(() => {});
		const timer = setTimeout(
			() => this.fail("handshake timed out"),
			options.timeoutMs ?? 10_000,
		);
		this.ready.finally(() => clearTimeout(timer)).catch(() => {});

		ws.on("message", (data) => this.handle(data, options.expectKey));
		ws.on("close", () => this.fail("connection closed"));
		ws.on("error", (err) => this.fail(err.message));
		const sendHello = () =>
			this.sendRaw({
				t: "hello",
				v: PROTOCOL_VERSION,
				key: self.id,
				challenge: this.challenge,
			});
		if (ws.readyState === WebSocket.OPEN) sendHello();
		else ws.once("open", sendHello);
	}

	/** Sends a frame. Only valid after the handshake. */
	send(frame: Frame): void {
		this.sendRaw(frame);
	}

	/** Calls `fn` for every frame after the handshake. Returns an unsubscribe function. */
	onFrame(fn: (frame: Frame) => void): () => void {
		this.frameListeners.add(fn);
		return () => this.frameListeners.delete(fn);
	}

	get open(): boolean {
		return this.ws.readyState === WebSocket.OPEN;
	}

	close(code = 1000, reason = ""): void {
		this.ws.close(code, reason);
	}

	private sendRaw(frame: Frame): void {
		if (this.ws.readyState === WebSocket.OPEN) {
			this.ws.send(JSON.stringify(frame));
		}
	}

	private fail(reason: string): void {
		this.rejectReady(new Error(reason));
	}

	private refuse(reason: string): void {
		this.fail(reason);
		this.ws.close(4001, reason.slice(0, 100));
	}

	private handle(data: RawData, expectKey: string | undefined): void {
		let frame: Frame;
		try {
			frame = JSON.parse(data.toString()) as Frame;
			if (typeof frame?.t !== "string") throw new Error("no type");
		} catch {
			this.refuse("bad frame");
			return;
		}
		if (frame.t === "hello") {
			const key = frame.key;
			const challenge = frame.challenge;
			if (
				this.peerKey !== undefined ||
				frame.v !== PROTOCOL_VERSION ||
				typeof key !== "string" ||
				!isKeyId(key) ||
				typeof challenge !== "string" ||
				challenge.length < 32 ||
				challenge.length > 128
			) {
				this.refuse("bad hello");
				return;
			}
			if (expectKey !== undefined && key !== expectKey) {
				this.refuse("reached a different key than expected");
				return;
			}
			if (key === this.self.id) {
				this.refuse("connected to myself");
				return;
			}
			this.peerKey = key;
			const sig = ed25519.sign(
				authMessage(challenge, this.self.id, key),
				this.self.secretKey,
			);
			this.sendRaw({ t: "auth", sig: toBase64Url(sig) });
			this.sentAuth = true;
			this.maybeReady();
			return;
		}
		if (frame.t === "auth") {
			const peerKey = this.peerKey;
			if (
				peerKey === undefined ||
				this.gotAuth ||
				typeof frame.sig !== "string"
			) {
				this.refuse("unexpected auth");
				return;
			}
			let valid = false;
			try {
				valid = ed25519.verify(
					fromBase64Url(frame.sig),
					authMessage(this.challenge, peerKey, this.self.id),
					keyFromId(peerKey),
				);
			} catch {
				valid = false;
			}
			if (!valid) {
				this.refuse("bad signature");
				return;
			}
			const authorization = this.authorize(peerKey, this);
			if (!authorization) {
				this.refuse("not a paired contact");
				return;
			}
			this.authorization = authorization;
			this.gotAuth = true;
			this.sendRaw({ t: "ok" });
			this.maybeReady();
			return;
		}
		if (frame.t === "ok") {
			if (this.peerKey === undefined || this.gotOk) {
				this.refuse("unexpected ok");
				return;
			}
			this.gotOk = true;
			this.maybeReady();
			return;
		}
		if (!this.gotAuth || !this.sentAuth || !this.gotOk) {
			this.refuse("frame before handshake");
			return;
		}
		for (const fn of this.frameListeners) fn(frame);
	}

	private maybeReady(): void {
		if (
			this.sentAuth &&
			this.gotAuth &&
			this.gotOk &&
			this.peerKey !== undefined
		) {
			this.resolveReady(this.peerKey);
		}
	}
}

export interface NetworkOptions {
	/** TCP port for the WebSocket listener; 0 picks a free one. */
	port?: number;
	/** Interface to listen on; defaults to all. */
	host?: string;
	/** mDNS discovery; `false` turns it off (tests), default is real mDNS. */
	discovery?: Discovery | false;
	/** Extra address lookup tried before discovery (tests use this). */
	resolve?: (keyId: string) => Address | undefined;
	/** How often due messages are retried, in milliseconds. */
	retryIntervalMs?: number;
	/** How long to wait for an ack, in milliseconds. */
	ackTimeoutMs?: number;
	/** How long the connection handshake may take, in milliseconds. */
	handshakeTimeoutMs?: number;
}

/** The settings key under which a contact's last known address is kept. */
export function addressSettingKey(keyId: string): string {
	return `address:${keyId}`;
}

/**
 * The daemon's transport: a WebSocket listener for other hosts, mDNS
 * discovery, and delivery of the outbound queue with retries.
 */
export class NetworkTransport implements Transport {
	private daemon: Daemon | undefined;
	private http: Server | undefined;
	private wss: WebSocketServer | undefined;
	private discovery: Discovery | undefined;
	private timer: NodeJS.Timeout | undefined;
	private guard: ReplayGuard | undefined;
	private readonly links = new Map<string, PeerLink>();
	private readonly inFlight = new Set<string>();
	private readonly incomingLinks = new Set<PeerLink>();
	private flushing: Promise<void> | undefined;
	private flushAgain = false;
	private listenPort = 0;
	/** Decides on keys that are not paired contacts (pairing sets this). */
	unpairedPolicy: ((key: string, link: PeerLink) => Authorization) | undefined;
	/** Called for every authenticated link, incoming or outgoing. */
	onLink: ((link: PeerLink) => void) | undefined;

	private readonly options: NetworkOptions;

	constructor(options: NetworkOptions = {}) {
		this.options = options;
	}

	/** The port the WebSocket listener is bound to. */
	get port(): number {
		return this.listenPort;
	}

	async start(daemon: Daemon): Promise<void> {
		this.daemon = daemon;
		this.guard = new ReplayGuard({ seen: daemon.store.seenIds() });
		this.http = createServer((_req, res) => {
			res.writeHead(426).end("squawk speaks WebSocket\n");
		});
		this.wss = new WebSocketServer({ server: this.http, maxPayload: 1 << 20 });
		this.wss.on("connection", (ws) => this.acceptIncoming(ws));
		await new Promise<void>((resolve, reject) => {
			this.http?.once("error", reject);
			this.http?.listen(this.options.port ?? 0, this.options.host, () =>
				resolve(),
			);
		});
		this.listenPort = (this.http.address() as AddressInfo).port;

		if (this.options.discovery !== false) {
			const identity = daemon.identity;
			this.discovery =
				this.options.discovery ??
				new Discovery({
					self: {
						name: identity.name,
						keyId: identity.id,
						fingerprint: fingerprint(identity.publicKey),
						port: this.listenPort,
					},
				});
			this.discovery.on("up", (peer) => this.peerCameOnline(peer));
			this.discovery.start();
		}
		this.timer = setInterval(
			() => void this.flush(),
			this.options.retryIntervalMs ?? 1000,
		);
		this.timer.unref();
		void this.flush();
	}

	async stop(): Promise<void> {
		if (this.timer) clearInterval(this.timer);
		await this.discovery?.stop();
		for (const link of [...this.links.values(), ...this.incomingLinks]) {
			link.close(1001, "shutting down");
		}
		this.links.clear();
		this.incomingLinks.clear();
		for (const client of this.wss?.clients ?? []) client.terminate();
		await new Promise<void>((resolve) => this.wss?.close(() => resolve()));
		await new Promise<void>((resolve) => this.http?.close(() => resolve()));
		await this.flushing;
	}

	kick(): void {
		void this.flush();
	}

	/** Peers seen on the network, with whether each one is a paired contact. */
	peers(): Peer[] {
		const store = this.daemon?.store;
		return (this.discovery?.peers() ?? []).map((p) => ({
			name: p.name,
			key_id: p.keyId,
			fingerprint: p.fingerprint,
			host: p.host,
			port: p.port,
			paired: store?.getContact(p.keyId)?.trust === "paired",
		}));
	}

	/** A discovered peer by name or key id, for pairing. */
	findPeer(nameOrKey: string): DiscoveredPeer | undefined {
		const all = this.discovery?.peers() ?? [];
		return (
			all.find((p) => p.keyId === nameOrKey) ??
			all.find((p) => p.name === nameOrKey)
		);
	}

	/** Where to reach a key: the test resolver, then mDNS, then the last address that worked. */
	resolve(keyId: string): Address | undefined {
		const fromOption = this.options.resolve?.(keyId);
		if (fromOption) return fromOption;
		const seen = this.discovery?.peer(keyId);
		if (seen) return { host: seen.addresses[0] ?? seen.host, port: seen.port };
		const saved = this.daemon?.store.getSetting(addressSettingKey(keyId));
		if (saved) {
			const at = saved.lastIndexOf(":");
			return { host: saved.slice(0, at), port: Number(saved.slice(at + 1)) };
		}
		return undefined;
	}

	/** Opens and authenticates a connection to `address`, expecting `expectKey` if given. */
	async dial(address: Address, expectKey?: string): Promise<PeerLink> {
		const daemon = this.requireDaemon();
		const host = address.host.includes(":")
			? `[${address.host}]`
			: address.host;
		const ws = new WebSocket(`ws://${host}:${address.port}/`, {
			maxPayload: 1 << 20,
			handshakeTimeout: this.options.handshakeTimeoutMs ?? 10_000,
		});
		const link = new PeerLink(
			ws,
			daemon.identity,
			(k, l) => this.authorize(k, l),
			{
				outgoing: true,
				...(expectKey !== undefined ? { expectKey } : {}),
				timeoutMs: this.options.handshakeTimeoutMs ?? 10_000,
			},
		);
		try {
			await link.ready;
		} catch (err) {
			ws.terminate();
			throw err;
		}
		this.onLink?.(link);
		return link;
	}

	/** Sends every due message, one connection per recipient. Safe to call often. */
	flush(): Promise<void> {
		if (this.flushing) {
			this.flushAgain = true;
			return this.flushing;
		}
		this.flushing = (async () => {
			try {
				do {
					this.flushAgain = false;
					await this.flushOnce();
				} while (this.flushAgain);
			} finally {
				this.flushing = undefined;
			}
		})();
		return this.flushing;
	}

	private async flushOnce(): Promise<void> {
		const daemon = this.daemon;
		if (!daemon) return;
		const byRecipient = new Map<
			string,
			ReturnType<typeof daemon.store.dueOutbound>
		>();
		for (const item of daemon.store.dueOutbound()) {
			if (this.inFlight.has(item.messageId)) continue;
			const list = byRecipient.get(item.recipient) ?? [];
			list.push(item);
			byRecipient.set(item.recipient, list);
		}
		await Promise.all(
			[...byRecipient].map(([recipient, items]) =>
				this.deliverTo(recipient, items),
			),
		);
	}

	private async deliverTo(
		recipient: string,
		items: ReturnType<Daemon["store"]["dueOutbound"]>,
	): Promise<void> {
		const store = this.requireDaemon().store;
		for (const item of items) this.inFlight.add(item.messageId);
		try {
			if (store.getContact(recipient)?.trust !== "paired") {
				throw new Error("recipient is not a paired contact");
			}
			const link = await this.linkTo(recipient);
			await Promise.all(items.map((item) => this.sendOne(link, item)));
		} catch (err) {
			const error = err instanceof Error ? err.message : String(err);
			for (const item of items) {
				if (store.getOutbound(item.messageId)) {
					store.recordAttempt(item.messageId, { error });
				}
			}
		} finally {
			for (const item of items) this.inFlight.delete(item.messageId);
		}
	}

	private async linkTo(recipient: string): Promise<PeerLink> {
		const existing = this.links.get(recipient);
		if (existing?.open) return existing;
		const address = this.resolve(recipient);
		if (!address) throw new Error("recipient is not on the network");
		const link = await this.dial(address, recipient);
		if (link.authorization !== "paired") {
			link.close();
			throw new Error("recipient is not a paired contact");
		}
		this.links.set(recipient, link);
		link.ws.on("close", () => {
			if (this.links.get(recipient) === link) this.links.delete(recipient);
		});
		this.requireDaemon().store.setSetting(
			addressSettingKey(recipient),
			`${address.host}:${address.port}`,
		);
		return link;
	}

	private sendOne(
		link: PeerLink,
		item: { messageId: string; sealed: Sealed },
	): Promise<void> {
		const store = this.requireDaemon().store;
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				off();
				reject(new Error("no acknowledgement"));
			}, this.options.ackTimeoutMs ?? 10_000);
			const onClose = () => {
				off();
				reject(new Error("connection closed before acknowledgement"));
			};
			const stopListening = link.onFrame((frame) => {
				if (frame.id !== item.messageId) return;
				if (frame.t === "ack") {
					off();
					store.markAcknowledged(item.messageId);
					resolve();
				} else if (frame.t === "nack") {
					off();
					reject(new Error(`refused: ${String(frame.error)}`));
				}
			});
			const off = () => {
				clearTimeout(timer);
				stopListening();
				link.ws.off("close", onClose);
			};
			link.ws.on("close", onClose);
			link.send({ t: "msg", id: item.messageId, sealed: item.sealed });
		});
	}

	private authorize(key: string, link: PeerLink): Authorization {
		const contact = this.daemon?.store.getContact(key);
		if (contact?.trust === "blocked") return false;
		if (contact?.trust === "paired") return "paired";
		return this.unpairedPolicy?.(key, link) ?? false;
	}

	private acceptIncoming(ws: WebSocket): void {
		const daemon = this.requireDaemon();
		const link = new PeerLink(
			ws,
			daemon.identity,
			(k, l) => this.authorize(k, l),
			{
				outgoing: false,
				timeoutMs: this.options.handshakeTimeoutMs ?? 10_000,
			},
		);
		this.incomingLinks.add(link);
		ws.on("close", () => this.incomingLinks.delete(link));
		link.ready.then(
			() => {
				link.onFrame((frame) => {
					if (frame.t === "msg") this.receive(link, frame);
				});
				this.onLink?.(link);
			},
			() => ws.terminate(),
		);
	}

	private receive(link: PeerLink, frame: Frame): void {
		const daemon = this.requireDaemon();
		const id = typeof frame.id === "string" ? frame.id : undefined;
		const nack = (error: string) => link.send({ t: "nack", id, error });
		if (link.authorization !== "paired") {
			nack("not a paired contact");
			return;
		}
		const parsed = SealedSchema.safeParse(frame.sealed);
		if (!parsed.success || id === undefined) {
			nack("malformed");
			return;
		}
		if (parsed.data.from !== link.peerKey) {
			nack("sender does not match the connection");
			return;
		}
		try {
			const envelope = open(parsed.data, daemon.identity, this.guard);
			if (envelope.id !== id) {
				nack("id does not match the message");
				return;
			}
			daemon.deliverIncoming(envelope, {
				remoteAddress: link.ws.url ?? "",
			});
			link.send({ t: "ack", id });
		} catch (err) {
			// A repeat of a message we already stored: the sender missed our
			// ack, so acknowledge again to stop it retrying.
			if (
				err instanceof EnvelopeError &&
				err.code === "replay" &&
				daemon.store.getMessage(id)
			) {
				link.send({ t: "ack", id });
				return;
			}
			nack(err instanceof EnvelopeError ? err.code : "error");
		}
	}

	private peerCameOnline(peer: DiscoveredPeer): void {
		if (this.daemon?.store.getContact(peer.keyId)?.trust === "paired") {
			void this.flush();
		}
	}

	private requireDaemon(): Daemon {
		if (!this.daemon) throw new Error("transport is not started");
		return this.daemon;
	}
}
