import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { hostname, userInfo } from "node:os";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { identityPath } from "./config.ts";
import { fromBase64Url, keyId, toBase64Url } from "./encoding.ts";

/**
 * This machine's identity: one ed25519 key pair used for signing, the
 * x25519 key pair derived from it for encryption, and a display name.
 */
export interface Identity {
	name: string;
	/** base64url of the ed25519 public key; used as the address in messages. */
	id: string;
	publicKey: Uint8Array;
	secretKey: Uint8Array;
	x25519PublicKey: Uint8Array;
	x25519SecretKey: Uint8Array;
}

/** What is written to identity.json. */
interface IdentityFile {
	version: 1;
	name: string;
	publicKey: string;
	secretKey: string;
	createdAt: string;
}

/** Thrown by `initIdentity` when an identity file already exists. */
export class IdentityExistsError extends Error {
	readonly path: string;
	constructor(path: string) {
		super(`an identity already exists at ${path}; refusing to overwrite it`);
		this.name = "IdentityExistsError";
		this.path = path;
	}
}

/** Thrown by `loadIdentity` when there is no identity file yet. */
export class NoIdentityError extends Error {
	readonly path: string;
	constructor(path: string) {
		super(`no identity found at ${path}; run "squawk init" first`);
		this.name = "NoIdentityError";
		this.path = path;
	}
}

/** The name used when `squawk init` is not given one, e.g. "alice@laptop". */
export function defaultDisplayName(): string {
	const host = hostname().split(".")[0] || hostname();
	let user = "";
	try {
		user = userInfo().username;
	} catch {
		// userInfo throws when the user has no passwd entry; use the host alone.
	}
	return user ? `${user}@${host}` : host;
}

/** Builds a full identity (including the derived x25519 keys) from an ed25519 secret key. */
export function identityFromSecretKey(
	name: string,
	secretKey: Uint8Array,
): Identity {
	const publicKey = ed25519.getPublicKey(secretKey);
	return {
		name,
		id: keyId(publicKey),
		publicKey,
		secretKey,
		x25519PublicKey: ed25519.utils.toMontgomery(publicKey),
		x25519SecretKey: ed25519.utils.toMontgomerySecret(secretKey),
	};
}

/**
 * Creates a new key pair and writes it, with the display name, to the
 * identity file under `home`. The file gets mode 0600, and the directory
 * mode 0700 if this call creates it (an existing directory's permissions are
 * left alone). Throws `IdentityExistsError` if the file is already there.
 */
export async function initIdentity(
	home: string,
	name: string = defaultDisplayName(),
): Promise<Identity> {
	const trimmed = name.trim();
	if (trimmed === "") {
		throw new Error("display name must not be empty");
	}
	// mkdir's mode is applied before the umask, so set it again on a directory
	// this call created (mkdir returns the first directory it made).
	if ((await mkdir(home, { recursive: true, mode: 0o700 })) !== undefined) {
		await chmod(home, 0o700);
	}

	const secretKey = ed25519.utils.randomSecretKey();
	const identity = identityFromSecretKey(trimmed, secretKey);
	const file: IdentityFile = {
		version: 1,
		name: trimmed,
		publicKey: toBase64Url(identity.publicKey),
		secretKey: toBase64Url(secretKey),
		createdAt: new Date().toISOString(),
	};
	const path = identityPath(home);
	try {
		// The "wx" flag fails if the file exists, so two concurrent inits cannot both succeed.
		await writeFile(path, `${JSON.stringify(file, null, "\t")}\n`, {
			flag: "wx",
			mode: 0o600,
		});
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "EEXIST") {
			throw new IdentityExistsError(path);
		}
		throw err;
	}
	await chmod(path, 0o600);
	return identity;
}

/** Reads the identity file under `home`. Throws `NoIdentityError` if it is missing. */
export async function loadIdentity(home: string): Promise<Identity> {
	const path = identityPath(home);
	let text: string;
	try {
		text = await readFile(path, "utf8");
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "ENOENT") {
			throw new NoIdentityError(path);
		}
		throw err;
	}
	let file: Partial<IdentityFile>;
	try {
		file = JSON.parse(text) as Partial<IdentityFile>;
	} catch {
		file = {};
	}
	if (
		typeof file !== "object" ||
		file === null ||
		file.version !== 1 ||
		typeof file.name !== "string" ||
		typeof file.secretKey !== "string" ||
		typeof file.publicKey !== "string" ||
		!/^[A-Za-z0-9_-]{43}$/.test(file.secretKey)
	) {
		throw new Error(
			`identity file ${path} is not in a format squawk understands`,
		);
	}
	const identity = identityFromSecretKey(
		file.name,
		fromBase64Url(file.secretKey),
	);
	if (identity.id !== file.publicKey) {
		throw new Error(
			`identity file ${path} is inconsistent: its public key does not match its secret key`,
		);
	}
	return identity;
}

/**
 * A short fingerprint of an ed25519 public key for people to compare by eye:
 * the first 16 bytes of its SHA-256 hash as hex, in dash-separated groups of
 * four characters (e.g. "3f2a-91c0-...").
 */
export function fingerprint(publicKey: Uint8Array): string {
	const hex = bytesToHex(sha256(publicKey).subarray(0, 16));
	return hex.match(/.{4}/g)?.join("-") ?? hex;
}
