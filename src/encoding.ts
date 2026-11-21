/**
 * Conversions between raw key bytes and the text forms squawk stores and
 * sends. Public keys are identified everywhere by the base64url (no padding)
 * encoding of the 32-byte ed25519 public key.
 */

/** Encodes bytes as base64url without padding. */
export function toBase64Url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

/** Decodes a base64url string (padding optional) to bytes. */
export function fromBase64Url(text: string): Uint8Array {
	return new Uint8Array(Buffer.from(text, "base64url"));
}

const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The text identifier for an ed25519 public key (base64url of its 32 bytes). */
export function keyId(publicKey: Uint8Array): string {
	if (publicKey.length !== 32) {
		throw new Error(`expected a 32-byte public key, got ${publicKey.length}`);
	}
	return toBase64Url(publicKey);
}

/**
 * True when `text` is exactly what `keyId` produces for some 32 bytes. The
 * last of the 43 characters carries 2 unused bits, so up to four spellings
 * decode to the same key; only the one with those bits zero is accepted, so
 * that each key has one identifier and text comparisons of ids are safe.
 */
export function isKeyId(text: string): boolean {
	return KEY_ID_PATTERN.test(text) && toBase64Url(fromBase64Url(text)) === text;
}

/** Turns a key identifier back into the 32 raw public-key bytes. */
export function keyFromId(id: string): Uint8Array {
	if (!isKeyId(id)) {
		throw new Error(`not a squawk key identifier: ${id}`);
	}
	return fromBase64Url(id);
}
