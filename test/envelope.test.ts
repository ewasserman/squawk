import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url } from "../src/encoding.ts";
import {
	createEnvelope,
	type Envelope,
	EnvelopeError,
	type EnvelopeErrorCode,
	open,
	ReplayGuard,
	type Sealed,
	seal,
} from "../src/envelope.ts";
import { type Identity, identityFromSecretKey } from "../src/identity.ts";

function makeIdentity(name: string): Identity {
	return identityFromSecretKey(name, ed25519.utils.randomSecretKey());
}

const alice = makeIdentity("alice");
const bob = makeIdentity("bob");
const carol = makeIdentity("carol");
const mallory = makeIdentity("mallory");

const NOW = Date.parse("2026-11-21T12:00:00.000Z");
const clock = () => NOW;

function message(
	overrides: Partial<Parameters<typeof createEnvelope>[0]> = {},
) {
	return createEnvelope({
		from: alice.id,
		to: bob.id,
		body: "# Hello\n\nAre you **there**?",
		kind: "question",
		session: "sess-1",
		created_at: new Date(NOW),
		...overrides,
	});
}

function expectCode(fn: () => unknown, code: EnvelopeErrorCode) {
	try {
		fn();
	} catch (err) {
		expect(err).toBeInstanceOf(EnvelopeError);
		expect((err as EnvelopeError).code).toBe(code);
		return;
	}
	throw new Error(`expected EnvelopeError with code ${code}`);
}

describe("seal and open", () => {
	it("round-trips a message", () => {
		const env = message();
		const sealed = seal(env, alice);
		const opened = open(sealed, bob, new ReplayGuard({ now: clock }));
		expect(opened).toEqual(env);
		expect(opened.thread_id).toBe(env.id);
	});

	it("survives a JSON round trip of the sealed object", () => {
		const env = message({ in_reply_to: "abc", thread_id: "t-1" });
		const wire = JSON.parse(JSON.stringify(seal(env, alice)));
		expect(open(wire, bob)).toEqual(env);
	});

	it("does not reveal the body or envelope outside the ciphertext", () => {
		const sealed = seal(message({ body: "secret plans" }), alice);
		const text = JSON.stringify(sealed);
		expect(text).not.toContain("secret");
		expect(text).not.toContain("sess-1");
		expect(Object.keys(sealed).sort()).toEqual(
			["ct", "epk", "from", "nonce", "to", "v"].sort(),
		);
		expect(sealed.from).toBe(alice.id);
		expect(sealed.to).toBe(bob.id);
	});

	it("rejects a flipped bit in the ciphertext as tampered", () => {
		const sealed = seal(message(), alice);
		const ct = fromBase64Url(sealed.ct);
		ct[10] = (ct[10] ?? 0) ^ 0x01;
		const tampered: Sealed = { ...sealed, ct: toBase64Url(ct) };
		expectCode(() => open(tampered, bob), "tampered");
	});

	it("rejects a changed outer sender as tampered", () => {
		const sealed = seal(message(), alice);
		expectCode(() => open({ ...sealed, from: carol.id }, bob), "tampered");
	});

	it("rejects a message opened by someone other than the recipient", () => {
		const sealed = seal(message(), alice);
		expectCode(() => open(sealed, carol), "wrong_recipient");
	});

	it("cannot be redirected by rewriting the outer recipient", () => {
		const sealed = seal(message(), alice);
		expectCode(() => open({ ...sealed, to: carol.id }, carol), "tampered");
	});

	it("rejects a forged signature from an attacker claiming to be another sender", () => {
		// Mallory encrypts correctly to Bob and names Alice as sender, but can
		// only sign with her own key.
		const forged = message({ from: alice.id });
		const posingAsAlice: Identity = { ...mallory, id: alice.id };
		const sealed = seal(forged, posingAsAlice);
		expectCode(() => open(sealed, bob), "bad_signature");
	});

	it("refuses to seal an envelope whose from is not the sealing key", () => {
		expectCode(
			() => seal(message({ from: carol.id }), alice),
			"sender_mismatch",
		);
	});

	it("rejects input that is not a sealed message as malformed", () => {
		expectCode(() => open({ hello: "world" }, bob), "malformed");
		expectCode(() => open(null, bob), "malformed");
	});
});

describe("ReplayGuard", () => {
	it("rejects a replayed message id", () => {
		const guard = new ReplayGuard({ now: clock });
		const sealed = seal(message(), alice);
		open(sealed, bob, guard);
		expectCode(() => open(sealed, bob, guard), "replay");
	});

	it("rejects a different message reusing an id", () => {
		const guard = new ReplayGuard({ now: clock });
		const first = message();
		open(seal(first, alice), bob, guard);
		const second: Envelope = { ...message(), id: first.id };
		expectCode(() => open(seal(second, alice), bob, guard), "replay");
	});

	it("rejects created_at more than 5 minutes in the past or future", () => {
		const guard = new ReplayGuard({ now: clock });
		const old = message({ created_at: new Date(NOW - 5 * 60_000 - 1) });
		expectCode(() => open(seal(old, alice), bob, guard), "stale");
		const future = message({ created_at: new Date(NOW + 5 * 60_000 + 1) });
		expectCode(() => open(seal(future, alice), bob, guard), "stale");
	});

	it("accepts created_at within 5 minutes", () => {
		const guard = new ReplayGuard({ now: clock });
		const edge = message({ created_at: new Date(NOW - 5 * 60_000) });
		expect(open(seal(edge, alice), bob, guard).id).toBe(edge.id);
	});

	it("does not record ids of messages that fail other checks", () => {
		const guard = new ReplayGuard({ now: clock });
		const old = message({ created_at: new Date(NOW - 60 * 60_000) });
		expectCode(() => open(seal(old, alice), bob, guard), "stale");
		expect(guard.seen.has(old.id)).toBe(false);
	});
});
