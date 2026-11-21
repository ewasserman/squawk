/**
 * The message envelope and how it is sealed (signed, then encrypted) for one
 * recipient and opened again.
 *
 * Sealing:
 *   1. The envelope is serialised to JSON and signed with the sender's ed25519
 *      key. The signature covers a fixed prefix plus the exact JSON text, so
 *      the receiver verifies the same bytes that were signed.
 *   2. A fresh (ephemeral) x25519 key pair is made. Its secret key and the
 *      recipient's x25519 public key (derived from their ed25519 key) give a
 *      shared secret; HKDF-SHA256 turns that into a 32-byte key.
 *   3. `{ envelope, sig }` is encrypted with XChaCha20-Poly1305 under that key
 *      and a random 24-byte nonce. The plaintext routing fields (version,
 *      sender, recipient, ephemeral key) are passed as associated data, so
 *      changing any of them makes decryption fail.
 *
 * Only the routing fields are readable on the wire; the envelope, including
 * its body, is inside the ciphertext.
 */
import { randomUUID } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { z } from "zod";
import { fromBase64Url, isKeyId, keyFromId, toBase64Url } from "./encoding.ts";
import type { Identity } from "./identity.ts";

/** Wire format version written into every sealed message. */
export const WIRE_VERSION = 1;

/** Messages whose created_at is further than this from the local clock are rejected. */
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

const SIGNATURE_PREFIX = "squawk envelope v1\n";
const HKDF_INFO = utf8ToBytes("squawk v1 xchacha20poly1305 key");

/** A public-key identifier: base64url of a 32-byte ed25519 public key. */
export const KeyIdSchema = z
	.string()
	.refine(isKeyId, { message: "not a squawk key identifier" });

export const MessageKindSchema = z.enum(["text", "question", "answer"]);
export type MessageKind = z.infer<typeof MessageKindSchema>;

/** The message as the sender wrote it. Travels only inside the ciphertext. */
export const EnvelopeSchema = z
	.object({
		id: z.string().min(1).max(128),
		from: KeyIdSchema,
		to: KeyIdSchema,
		session: z.string().max(256).optional(),
		thread_id: z.string().min(1).max(128),
		in_reply_to: z.string().min(1).max(128).optional(),
		created_at: z.iso.datetime({ offset: true }),
		kind: MessageKindSchema,
		/** Markdown text. */
		body: z.string(),
	})
	.strict();
export type Envelope = z.infer<typeof EnvelopeSchema>;

const base64UrlBytes = (length?: number) =>
	z
		.string()
		.regex(/^[A-Za-z0-9_-]*$/, { message: "not base64url" })
		.refine((s) => length === undefined || fromBase64Url(s).length === length, {
			message: `expected ${length} bytes`,
		});

/** What goes over the network. Everything except `ct` is readable by anyone. */
export const SealedSchema = z
	.object({
		v: z.literal(WIRE_VERSION),
		/** Sender's key identifier. */
		from: KeyIdSchema,
		/** Recipient's key identifier; the receiving service uses it to pick its key. */
		to: KeyIdSchema,
		/** Ephemeral x25519 public key, base64url. */
		epk: base64UrlBytes(32),
		/** 24-byte XChaCha20 nonce, base64url. */
		nonce: base64UrlBytes(24),
		/** Ciphertext with the Poly1305 tag, base64url. */
		ct: base64UrlBytes(),
	})
	.strict();
export type Sealed = z.infer<typeof SealedSchema>;

/** What is encrypted: the envelope's JSON text and the signature over it. */
const InnerSchema = z
	.object({
		envelope: z.string(),
		sig: base64UrlBytes(64),
	})
	.strict();

export type EnvelopeErrorCode =
	/** The sealed object or decrypted content does not have the expected shape. */
	| "malformed"
	/** Decryption failed: the ciphertext or routing fields were changed, or the wrong key was used. */
	| "tampered"
	/** The message is addressed to someone other than the opener. */
	| "wrong_recipient"
	/** The signature does not verify against the claimed sender's key. */
	| "bad_signature"
	/** The signed sender does not match the sender named on the outside. */
	| "sender_mismatch"
	/** This message id has been accepted before. */
	| "replay"
	/** created_at is too far from the local clock. */
	| "stale";

/** Raised when a message cannot be sealed or opened, with a `code` saying why. */
export class EnvelopeError extends Error {
	readonly code: EnvelopeErrorCode;
	constructor(
		code: EnvelopeErrorCode,
		message: string,
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "EnvelopeError";
		this.code = code;
	}
}

/** Fields needed to make a new envelope; the rest get defaults. */
export interface NewEnvelopeInput {
	from: string;
	to: string;
	body: string;
	kind?: MessageKind;
	session?: string;
	/** Defaults to the new message's own id (a new thread). */
	thread_id?: string;
	in_reply_to?: string;
	/** Defaults to the current time. */
	created_at?: Date;
}

/** Makes a validated envelope with a fresh random id. */
export function createEnvelope(input: NewEnvelopeInput): Envelope {
	const id = randomUUID();
	const envelope: Envelope = {
		id,
		from: input.from,
		to: input.to,
		thread_id: input.thread_id ?? id,
		created_at: (input.created_at ?? new Date()).toISOString(),
		kind: input.kind ?? "text",
		body: input.body,
	};
	if (input.session !== undefined) envelope.session = input.session;
	if (input.in_reply_to !== undefined) envelope.in_reply_to = input.in_reply_to;
	return EnvelopeSchema.parse(envelope);
}

function associatedData(v: number, from: string, to: string, epk: string) {
	return utf8ToBytes(`squawk/${v}\n${from}\n${to}\n${epk}`);
}

function deriveKey(
	shared: Uint8Array,
	epk: Uint8Array,
	recipientX: Uint8Array,
): Uint8Array {
	return hkdf(sha256, shared, concatBytes(epk, recipientX), HKDF_INFO, 32);
}

/**
 * Signs `envelope` with the sender's key and encrypts it to the recipient.
 * `envelope.from` must be the sender's id and `envelope.to` the recipient's.
 */
export function seal(envelope: Envelope, sender: Identity): Sealed {
	const parsed = EnvelopeSchema.parse(envelope);
	if (parsed.from !== sender.id) {
		throw new EnvelopeError(
			"sender_mismatch",
			"envelope.from is not the sealing identity's key",
		);
	}
	const recipientEd = keyFromId(parsed.to);
	const recipientX = ed25519.utils.toMontgomery(recipientEd);

	const envelopeJson = JSON.stringify(parsed);
	const sig = ed25519.sign(
		utf8ToBytes(SIGNATURE_PREFIX + envelopeJson),
		sender.secretKey,
	);
	const inner = JSON.stringify({
		envelope: envelopeJson,
		sig: toBase64Url(sig),
	});

	const ephemeralSecret = x25519.utils.randomSecretKey();
	const epk = x25519.getPublicKey(ephemeralSecret);
	const key = deriveKey(
		x25519.getSharedSecret(ephemeralSecret, recipientX),
		epk,
		recipientX,
	);
	const nonce = randomBytes(24);
	const epkText = toBase64Url(epk);
	const aad = associatedData(WIRE_VERSION, parsed.from, parsed.to, epkText);
	const ct = xchacha20poly1305(key, nonce, aad).encrypt(utf8ToBytes(inner));

	return {
		v: WIRE_VERSION,
		from: parsed.from,
		to: parsed.to,
		epk: epkText,
		nonce: toBase64Url(nonce),
		ct: toBase64Url(ct),
	};
}

/**
 * Decrypts and checks a sealed message addressed to `recipient`.
 *
 * Checks, in order: wire shape, outer recipient, decryption, envelope shape,
 * signature by the claimed sender, that the signed `from`/`to` match the
 * outer sender and the opener, and finally (when a guard is given) the
 * timestamp and that the id is new. The id is recorded in the guard only
 * after every other check passes. Throws `EnvelopeError` on any failure.
 */
export function open(
	sealed: unknown,
	recipient: Identity,
	guard?: ReplayGuard,
): Envelope {
	const outer = SealedSchema.safeParse(sealed);
	if (!outer.success) {
		throw new EnvelopeError("malformed", "not a sealed squawk message", {
			cause: outer.error,
		});
	}
	const s = outer.data;
	if (s.to !== recipient.id) {
		throw new EnvelopeError(
			"wrong_recipient",
			"message is addressed to a different key",
		);
	}

	let plaintext: Uint8Array;
	try {
		const epk = fromBase64Url(s.epk);
		const key = deriveKey(
			x25519.getSharedSecret(recipient.x25519SecretKey, epk),
			epk,
			recipient.x25519PublicKey,
		);
		const aad = associatedData(s.v, s.from, s.to, s.epk);
		plaintext = xchacha20poly1305(key, fromBase64Url(s.nonce), aad).decrypt(
			fromBase64Url(s.ct),
		);
	} catch (err) {
		throw new EnvelopeError("tampered", "message could not be decrypted", {
			cause: err,
		});
	}

	let inner: z.infer<typeof InnerSchema>;
	let envelope: Envelope;
	try {
		inner = InnerSchema.parse(JSON.parse(new TextDecoder().decode(plaintext)));
		envelope = EnvelopeSchema.parse(JSON.parse(inner.envelope));
	} catch (err) {
		throw new EnvelopeError("malformed", "decrypted content is not valid", {
			cause: err,
		});
	}

	const signedBytes = utf8ToBytes(SIGNATURE_PREFIX + inner.envelope);
	let valid = false;
	try {
		valid = ed25519.verify(
			fromBase64Url(inner.sig),
			signedBytes,
			keyFromId(envelope.from),
		);
	} catch {
		valid = false;
	}
	if (!valid) {
		throw new EnvelopeError(
			"bad_signature",
			"signature does not match the claimed sender",
		);
	}
	if (envelope.from !== s.from) {
		throw new EnvelopeError(
			"sender_mismatch",
			"signed sender differs from the outer sender",
		);
	}
	if (envelope.to !== recipient.id) {
		throw new EnvelopeError(
			"wrong_recipient",
			"signed recipient is not the opener",
		);
	}

	guard?.accept(envelope);
	return envelope;
}

/** Storage for message ids that have already been accepted. */
export interface SeenIdStore {
	has(id: string): boolean;
	/** Records `id`; `createdAtMs` lets the store forget ids too old to be replayed. */
	add(id: string, createdAtMs: number): void;
}

/** A `SeenIdStore` kept in memory. Contents are lost when the process exits. */
export class MemorySeenIds implements SeenIdStore {
	readonly #ids = new Map<string, number>();
	has(id: string): boolean {
		return this.#ids.has(id);
	}
	add(id: string, createdAtMs: number): void {
		this.#ids.set(id, createdAtMs);
	}
	/** Forgets ids whose created_at is before `cutoffMs`. */
	prune(cutoffMs: number): void {
		for (const [id, at] of this.#ids) {
			if (at < cutoffMs) this.#ids.delete(id);
		}
	}
}

export interface ReplayGuardOptions {
	seen?: SeenIdStore;
	/** Returns the current time in milliseconds since the epoch. */
	now?: () => number;
	maxSkewMs?: number;
}

/**
 * Rejects messages whose id was accepted before (`replay`) or whose
 * created_at is more than `maxSkewMs` (default 5 minutes) away from the local
 * clock in either direction (`stale`). Because old messages are refused on
 * time, the seen-id store only needs to keep ids from the last few minutes.
 */
export class ReplayGuard {
	readonly seen: SeenIdStore;
	readonly #now: () => number;
	readonly #maxSkewMs: number;

	constructor(options: ReplayGuardOptions = {}) {
		this.seen = options.seen ?? new MemorySeenIds();
		this.#now = options.now ?? Date.now;
		this.#maxSkewMs = options.maxSkewMs ?? MAX_CLOCK_SKEW_MS;
	}

	/** Throws `stale` or `replay` if the envelope must be refused. Does not record it. */
	check(envelope: Pick<Envelope, "id" | "created_at">): void {
		const created = Date.parse(envelope.created_at);
		if (
			Number.isNaN(created) ||
			Math.abs(this.#now() - created) > this.#maxSkewMs
		) {
			throw new EnvelopeError(
				"stale",
				`created_at ${envelope.created_at} is more than ${this.#maxSkewMs / 1000}s from the local clock`,
			);
		}
		if (this.seen.has(envelope.id)) {
			throw new EnvelopeError(
				"replay",
				`message ${envelope.id} was already received`,
			);
		}
	}

	/** Checks the envelope and, if it passes, records its id as seen. */
	accept(envelope: Pick<Envelope, "id" | "created_at">): void {
		this.check(envelope);
		this.seen.add(envelope.id, Date.parse(envelope.created_at));
	}
}
