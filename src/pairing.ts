/**
 * Pairing: two people confirm each other's keys once, after which their
 * services accept each other's connections and messages.
 *
 * One person runs `squawk pair --accept` (the responder), the other runs
 * `squawk pair <peer>` (the initiator). The initiator's service dials the
 * responder's. The WebSocket handshake (network.ts) already proves that each
 * side holds the private key it claims; pairing then decides whether that
 * key is the person you think it is:
 *
 *   1. initiator → responder  `pair-commit`: SHA-256 over the initiator's key
 *      and a random 32-byte nonce, without revealing the nonce.
 *   2. responder → initiator  `pair-nonce`: the responder's random nonce.
 *   3. initiator → responder  `pair-reveal`: the initiator's nonce. The
 *      responder checks it against the commitment from step 1.
 *   4. Both sides show a 6-digit code computed from both keys and both
 *      nonces. Each person checks that the two screens show the same code
 *      and answers yes or no.
 *   5. Each side sends `pair-confirm` once its person said yes. The contact
 *      is saved only when the local person AND the other side have
 *      confirmed. A "no", a timeout or a mismatch saves nothing.
 *
 * An attacker relaying traffic between the two people has to use keys of its
 * own on each side, so the codes are computed from different inputs. The
 * commitment in step 1 makes the attacker fix its choices before it learns
 * the other side's nonce, so it gets a single one-in-a-million guess at
 * matching codes instead of trying keys until the codes happen to match.
 * See docs/plan/security.md, threat 5.
 */
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { Daemon } from "./daemon.ts";
import { fromBase64Url, keyFromId, toBase64Url } from "./encoding.ts";
import { fingerprint } from "./identity.ts";
import {
	type Address,
	addressSettingKey,
	type Frame,
	type NetworkTransport,
	type PeerLink,
} from "./network.ts";
import { RpcError, RpcErrorCode } from "./rpc.ts";
import type { Contact } from "./store.ts";

const COMMIT_PREFIX = utf8ToBytes("squawk pair commit v1");
const CODE_PREFIX = utf8ToBytes("squawk pair code v1");

/** How long each step may take before pairing gives up, in milliseconds. */
export const DEFAULT_PAIRING_TIMEOUT_MS = 120_000;

/** The commitment the initiator sends before revealing its nonce. */
export function pairCommitment(keyId: string, nonce: Uint8Array): Uint8Array {
	return sha256(concatBytes(COMMIT_PREFIX, keyFromId(keyId), nonce));
}

/** The 6-digit code both people compare. */
export function pairCode(
	initiatorKey: string,
	responderKey: string,
	initiatorNonce: Uint8Array,
	responderNonce: Uint8Array,
): string {
	const digest = sha256(
		concatBytes(
			CODE_PREFIX,
			keyFromId(initiatorKey),
			keyFromId(responderKey),
			initiatorNonce,
			responderNonce,
		),
	);
	const n = new DataView(digest.buffer, digest.byteOffset, 8).getBigUint64(0);
	return (n % 1_000_000n).toString().padStart(6, "0");
}

/** What a person is shown when the code is ready. */
export interface PairingOffer {
	pairing_id: string;
	code: string;
	peer_name: string;
	peer_key: string;
	peer_fingerprint: string;
}

/** Raised when pairing fails; the message is meant for the person. */
export class PairingError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "PairingError";
	}
}

interface Session {
	id: string;
	role: "initiator" | "responder";
	link: PeerLink;
	peerKey: string;
	peerName: string;
	/** The other side's listening address, saved with the contact. */
	peerAddress: Address | undefined;
	code: string | undefined;
	localConfirmed: boolean;
	remoteConfirmed: boolean;
	finished: boolean;
	/** Settles when the code is ready (or pairing fails first). */
	codeReady: Deferred<PairingOffer>;
	/** Settles when both sides have confirmed (or pairing fails). */
	done: Deferred<Contact>;
	timer: NodeJS.Timeout;
}

interface Deferred<T> {
	promise: Promise<T>;
	resolve: (value: T) => void;
	reject: (err: Error) => void;
}

function deferred<T>(): Deferred<T> {
	let resolve!: (value: T) => void;
	let reject!: (err: Error) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	promise.catch(() => {});
	return { promise, resolve, reject };
}

function bytesField(frame: Frame, key: string, length: number): Uint8Array {
	const value = frame[key];
	if (typeof value !== "string") throw new PairingError(`missing ${key}`);
	const bytes = fromBase64Url(value);
	if (bytes.length !== length) throw new PairingError(`bad ${key}`);
	return bytes;
}

function nameField(frame: Frame): string {
	const value = frame.name;
	return typeof value === "string" && value.trim() !== ""
		? value.trim().slice(0, 64)
		: "unnamed";
}

/**
 * Runs pairing inside the service. Created and started by the daemon entry
 * point next to the network transport; offers the `pair_start`,
 * `pair_accept`, `pair_confirm` and `pair_cancel` methods on the local socket.
 */
export class Pairing {
	private readonly daemon: Daemon;
	private readonly transport: NetworkTransport;
	private readonly timeoutMs: number;
	private readonly sessions = new Map<string, Session>();
	/** Set while `pair --accept` is waiting for someone to pair with us. */
	private accepting: Deferred<PairingOffer> | undefined;
	private acceptTimer: NodeJS.Timeout | undefined;
	/** Set while we are dialling someone to pair with them. */
	private dialling = false;

	constructor(
		daemon: Daemon,
		transport: NetworkTransport,
		options: { timeoutMs?: number } = {},
	) {
		this.daemon = daemon;
		this.transport = transport;
		this.timeoutMs = options.timeoutMs ?? DEFAULT_PAIRING_TIMEOUT_MS;
	}

	/** Hooks into the transport and adds the RPC methods. Call after the daemon has started. */
	start(): void {
		this.transport.unpairedPolicy = (_key, link) => {
			if (link.outgoing) return this.dialling ? "pairing" : false;
			return this.accepting ? "pairing" : false;
		};
		this.transport.onLink = (link) => {
			if (!link.outgoing && this.accepting) this.respond(link);
		};
		this.daemon.handle("pair_start", (params) => {
			const p = (params ?? {}) as { peer?: unknown };
			if (typeof p.peer !== "string" || p.peer === "") {
				throw new RpcError(RpcErrorCode.InvalidParams, "peer is required");
			}
			return this.wrap(this.initiate(p.peer));
		});
		this.daemon.handle("pair_accept", () => this.wrap(this.accept()));
		this.daemon.handle("pair_confirm", (params) => {
			const p = (params ?? {}) as { pairing_id?: unknown; match?: unknown };
			if (typeof p.pairing_id !== "string" || typeof p.match !== "boolean") {
				throw new RpcError(
					RpcErrorCode.InvalidParams,
					"pairing_id and match are required",
				);
			}
			return this.wrap(
				this.confirm(p.pairing_id, p.match).then((contact) => ({
					status: "paired",
					contact: {
						name: contact.name,
						key_id: contact.publicKey,
						fingerprint: fingerprint(keyFromId(contact.publicKey)),
					},
				})),
			);
		});
		for (const [method, trust] of [
			["block", "blocked"],
			["unblock", "paired"],
		] as const) {
			this.daemon.handle(method, (params) => {
				const p = (params ?? {}) as { contact?: unknown };
				if (typeof p.contact !== "string") {
					throw new RpcError(RpcErrorCode.InvalidParams, "contact is required");
				}
				const contact = this.daemon.resolveContact(p.contact);
				const updated = this.daemon.store.updateContact(contact.publicKey, {
					trust,
				});
				if (trust === "blocked") this.transport.disconnect(contact.publicKey);
				return { name: updated.name, key_id: updated.publicKey, trust };
			});
		}
		this.daemon.handle("pair_cancel", () => {
			this.cancelAll("cancelled");
			return { ok: true };
		});
	}

	/** Gives up on every pairing in progress. */
	stop(): void {
		this.cancelAll("the service stopped");
	}

	/**
	 * Starts pairing with a peer: a discovered peer's name or key id, or a
	 * `host:port` address. Resolves when the code is ready to compare.
	 */
	async initiate(peer: string): Promise<PairingOffer> {
		const self = this.daemon.identity;
		let address: Address | undefined;
		let expectKey: string | undefined;
		const found = this.transport.findPeer(peer);
		if (found) {
			address = { host: found.addresses[0] ?? found.host, port: found.port };
			expectKey = found.keyId;
		} else {
			const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(peer);
			if (m) address = { host: m[1] ?? "", port: Number(m[2]) };
		}
		if (!address) {
			throw new PairingError(
				`no squawk service called "${peer}" is visible on the network (try \`squawk peers\`, or give host:port)`,
			);
		}

		let link: PeerLink;
		this.dialling = true;
		try {
			link = await this.transport.dial(address, expectKey);
		} catch (err) {
			throw new PairingError(
				`could not connect to ${peer}: ${err instanceof Error ? err.message : String(err)}`,
			);
		} finally {
			this.dialling = false;
		}
		const session = this.newSession("initiator", link, address);
		const nonce = randomBytes(32);
		session.link.onFrame((frame) => {
			try {
				if (frame.t === "pair-nonce") {
					if (session.code !== undefined)
						throw new PairingError("repeated nonce");
					const theirNonce = bytesField(frame, "nonce", 32);
					session.peerName = nameField(frame);
					session.link.send({ t: "pair-reveal", nonce: toBase64Url(nonce) });
					this.codeIsReady(
						session,
						pairCode(self.id, session.peerKey, nonce, theirNonce),
					);
				} else {
					this.handleCommon(session, frame);
				}
			} catch (err) {
				this.abort(session, err);
			}
		});
		link.send({
			t: "pair-commit",
			commit: toBase64Url(pairCommitment(self.id, nonce)),
			name: self.name,
			port: this.transport.port,
		});
		return session.codeReady.promise;
	}

	/** Waits for someone to start pairing with us. Resolves when the code is ready. */
	async accept(): Promise<PairingOffer> {
		if (this.accepting) {
			throw new PairingError("already waiting for a pairing request");
		}
		const waiting = deferred<PairingOffer>();
		this.accepting = waiting;
		this.acceptTimer = setTimeout(() => {
			if (this.accepting === waiting) {
				this.accepting = undefined;
				waiting.reject(
					new PairingError("nobody asked to pair before the timeout"),
				);
			}
		}, this.timeoutMs);
		const clear = () => {
			if (this.accepting === waiting) this.accepting = undefined;
			clearTimeout(this.acceptTimer);
		};
		waiting.promise.then(clear, clear);
		return waiting.promise;
	}

	/**
	 * Records the local person's answer. Resolves with the saved contact once
	 * both sides have said yes.
	 */
	async confirm(pairingId: string, match: boolean): Promise<Contact> {
		const session = this.sessions.get(pairingId);
		if (!session || session.code === undefined) {
			throw new PairingError("there is no pairing waiting for confirmation");
		}
		if (!match) {
			session.link.send({ t: "pair-abort", reason: "the codes did not match" });
			this.finish(
				session,
				new PairingError("pairing cancelled: the codes did not match"),
			);
			return session.done.promise;
		}
		session.localConfirmed = true;
		session.link.send({ t: "pair-confirm" });
		this.maybeComplete(session);
		return session.done.promise;
	}

	private respond(link: PeerLink): void {
		const waiting = this.accepting;
		if (!waiting) return;
		const self = this.daemon.identity;
		const session = this.newSession("responder", link, undefined);
		session.codeReady.promise.then(waiting.resolve, waiting.reject);
		let commitment: Uint8Array | undefined;
		const nonce = randomBytes(32);
		link.onFrame((frame) => {
			try {
				if (frame.t === "pair-commit") {
					if (commitment) throw new PairingError("repeated commitment");
					commitment = bytesField(frame, "commit", 32);
					session.peerName = nameField(frame);
					const port = Number(frame.port);
					const host = link.remoteAddress;
					if (host && Number.isInteger(port) && port > 0 && port < 65536) {
						session.peerAddress = { host, port };
					}
					link.send({
						t: "pair-nonce",
						nonce: toBase64Url(nonce),
						name: self.name,
					});
				} else if (frame.t === "pair-reveal") {
					if (!commitment || session.code !== undefined) {
						throw new PairingError("reveal out of order");
					}
					const theirNonce = bytesField(frame, "nonce", 32);
					const expected = pairCommitment(session.peerKey, theirNonce);
					if (!timingSafeEqual(expected, commitment)) {
						link.send({ t: "pair-abort", reason: "commitment mismatch" });
						throw new PairingError(
							"pairing refused: the other side's commitment did not match (possible tampering)",
						);
					}
					this.codeIsReady(
						session,
						pairCode(session.peerKey, self.id, theirNonce, nonce),
					);
				} else {
					this.handleCommon(session, frame);
				}
			} catch (err) {
				this.abort(session, err);
			}
		});
	}

	private newSession(
		role: Session["role"],
		link: PeerLink,
		peerAddress: Address | undefined,
	): Session {
		const peerKey = link.peerKey;
		if (!peerKey) throw new PairingError("connection is not authenticated");
		const session: Session = {
			id: randomUUID(),
			role,
			link,
			peerKey,
			peerName: "unnamed",
			peerAddress,
			code: undefined,
			localConfirmed: false,
			remoteConfirmed: false,
			finished: false,
			codeReady: deferred(),
			done: deferred(),
			timer: setTimeout(
				() => this.finish(session, new PairingError("pairing timed out")),
				this.timeoutMs,
			),
		};
		this.sessions.set(session.id, session);
		link.ws.on("close", () => {
			this.finish(
				session,
				new PairingError("the other side disconnected before pairing finished"),
			);
		});
		return session;
	}

	private handleCommon(session: Session, frame: Frame): void {
		if (frame.t === "pair-confirm") {
			if (session.code === undefined)
				throw new PairingError("confirm before code");
			session.remoteConfirmed = true;
			this.maybeComplete(session);
		} else if (frame.t === "pair-abort") {
			const reason =
				typeof frame.reason === "string" ? frame.reason.slice(0, 200) : "";
			this.finish(
				session,
				new PairingError(
					`the other side cancelled pairing${reason ? `: ${reason}` : ""}`,
				),
			);
		}
	}

	private codeIsReady(session: Session, code: string): void {
		session.code = code;
		session.codeReady.resolve({
			pairing_id: session.id,
			code,
			peer_name: session.peerName,
			peer_key: session.peerKey,
			peer_fingerprint: fingerprint(keyFromId(session.peerKey)),
		});
	}

	private maybeComplete(session: Session): void {
		if (
			session.finished ||
			!session.localConfirmed ||
			!session.remoteConfirmed
		) {
			return;
		}
		const store = this.daemon.store;
		const contact = store.upsertContact({
			publicKey: session.peerKey,
			name: session.peerName,
			trust: "paired",
		});
		if (session.peerAddress) {
			store.setSetting(
				addressSettingKey(session.peerKey),
				`${session.peerAddress.host}:${session.peerAddress.port}`,
			);
		}
		this.finish(session, contact);
	}

	private abort(session: Session, err: unknown): void {
		const message = err instanceof Error ? err.message : String(err);
		if (!session.finished) {
			session.link.send({ t: "pair-abort", reason: message.slice(0, 200) });
		}
		this.finish(
			session,
			err instanceof PairingError ? err : new PairingError(message),
		);
	}

	/** Ends a session with a saved contact or an error, and closes its connection. */
	private finish(session: Session, outcome: Contact | PairingError): void {
		if (session.finished) return;
		session.finished = true;
		clearTimeout(session.timer);
		this.sessions.delete(session.id);
		if (outcome instanceof PairingError) {
			session.codeReady.reject(outcome);
			session.done.reject(outcome);
		} else {
			session.done.resolve(outcome);
		}
		// Give the last frame a moment to go out before closing.
		setTimeout(() => session.link.close(1000, "pairing finished"), 100).unref();
	}

	private cancelAll(reason: string): void {
		for (const session of [...this.sessions.values()]) {
			session.link.send({ t: "pair-abort", reason });
			this.finish(session, new PairingError(`pairing cancelled: ${reason}`));
		}
		if (this.accepting) {
			this.accepting.reject(new PairingError(`pairing cancelled: ${reason}`));
			this.accepting = undefined;
		}
	}

	/** Turns PairingError into an RPC error the CLI can print. */
	private async wrap<T>(work: Promise<T>): Promise<T> {
		try {
			return await work;
		} catch (err) {
			if (err instanceof PairingError) {
				throw new RpcError(RpcErrorCode.ApplicationError, err.message);
			}
			throw err;
		}
	}
}
