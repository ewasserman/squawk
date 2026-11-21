import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dbPath } from "../src/config.ts";
import {
	createEnvelope,
	EnvelopeError,
	open,
	ReplayGuard,
	seal,
} from "../src/envelope.ts";
import { identityFromSecretKey } from "../src/identity.ts";
import { MIGRATIONS, Store } from "../src/store.ts";

const alice = identityFromSecretKey("alice", ed25519.utils.randomSecretKey());
const bob = identityFromSecretKey("bob", ed25519.utils.randomSecretKey());

let base: string;
let path: string;
let now: number;
let store: Store;

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "squawk-store-"));
	path = dbPath(join(base, "home"));
	now = Date.parse("2026-11-21T12:00:00.000Z");
	store = Store.open(path, { now: () => now });
});

afterEach(async () => {
	store.close();
	await rm(base, { recursive: true, force: true });
});

function outgoing(body = "Hello Bob", extra = {}) {
	return createEnvelope({
		from: alice.id,
		to: bob.id,
		body,
		created_at: new Date(now),
		...extra,
	});
}

describe("Store", () => {
	it("creates the database file with mode 0600", async () => {
		expect((await stat(path)).mode & 0o777).toBe(0o600);
	});

	it("applies migrations once and is unchanged on reopen", () => {
		expect(store.schemaVersion()).toBe(MIGRATIONS.length);
		store.upsertContact({ publicKey: bob.id, name: "bob" });
		store.close();
		store = Store.open(path, { now: () => now });
		expect(store.schemaVersion()).toBe(MIGRATIONS.length);
		store.migrate();
		expect(store.schemaVersion()).toBe(MIGRATIONS.length);
		expect(store.getContact(bob.id)?.name).toBe("bob");
	});

	it("queues a message and returns it when due", () => {
		const env = outgoing();
		store.queueOutgoing(env, seal(env, alice));

		const due = store.dueOutbound();
		expect(due).toHaveLength(1);
		const [item] = due;
		expect(item?.messageId).toBe(env.id);
		expect(item?.recipient).toBe(bob.id);
		expect(item?.attempts).toBe(0);
		// The stored sealed payload opens on the recipient's side.
		expect(open(item?.sealed, bob).body).toBe("Hello Bob");
		expect(store.getMessage(env.id)?.state).toBe("queued");
	});

	it("backs off after a failed attempt", () => {
		const env = outgoing();
		store.queueOutgoing(env, seal(env, alice));

		const first = store.recordAttempt(env.id, { error: "ECONNREFUSED" });
		expect(first).toBe(now + 2_000);
		expect(store.dueOutbound()).toHaveLength(0);
		expect(store.dueOutbound(first)).toHaveLength(1);

		const second = store.recordAttempt(env.id);
		expect(second).toBe(now + 4_000);
		const item = store.getOutbound(env.id);
		expect(item?.attempts).toBe(2);
		expect(item?.lastError).toBeNull();

		store.recordAttempt(env.id, { nextAttemptAt: now + 99 });
		expect(store.getOutbound(env.id)?.nextAttemptAt).toBe(now + 99);
	});

	it("marking a message acknowledged removes it from the queue", () => {
		const env = outgoing();
		store.queueOutgoing(env, seal(env, alice));

		expect(store.markAcknowledged(env.id)).toBe(true);
		expect(store.dueOutbound()).toHaveLength(0);
		expect(store.getOutbound(env.id)).toBeUndefined();
		expect(store.ackedAt(env.id)).toBe(new Date(now).toISOString());
		const msg = store.getMessage(env.id);
		expect(msg?.state).toBe("acked");
		expect(msg?.sentAt).not.toBeNull();
		expect(store.markAcknowledged(env.id)).toBe(false);
	});

	it("lists a thread in order and tracks the thread record", () => {
		const first = outgoing("# Deploy plan\n\nCan you review?", {
			kind: "question",
		});
		store.saveOutgoing(first, "sent");
		now += 1_000;
		const reply = createEnvelope({
			from: bob.id,
			to: alice.id,
			body: "Looks fine.",
			kind: "answer",
			thread_id: first.thread_id,
			in_reply_to: first.id,
			created_at: new Date(now),
		});
		expect(store.saveIncoming(reply)).toBe(true);
		expect(store.saveIncoming(reply)).toBe(false);

		const thread = store.listThread(first.thread_id);
		expect(thread.map((m) => m.id)).toEqual([first.id, reply.id]);
		expect(thread[0]?.direction).toBe("out");
		expect(thread[0]?.peer).toBe(bob.id);
		expect(thread[1]?.direction).toBe("in");
		expect(thread[1]?.peer).toBe(bob.id);
		expect(thread[1]?.inReplyTo).toBe(first.id);

		const record = store.getThread(first.thread_id);
		expect(record?.subject).toBe("Deploy plan");
		expect(record?.updatedAt).toBe(new Date(now).toISOString());
		expect(store.listThreads(bob.id)).toHaveLength(1);
		expect(store.listThreads(alice.id)).toHaveLength(0);
	});

	it("lists unread incoming messages and marks them read", () => {
		const a = createEnvelope({ from: bob.id, to: alice.id, body: "one" });
		const b = createEnvelope({ from: bob.id, to: alice.id, body: "two" });
		store.saveIncoming(a);
		store.saveIncoming(b);
		store.saveOutgoing(outgoing());
		expect(store.inbox().map((m) => m.body)).toEqual(["one", "two"]);
		expect(store.markRead(a.id)).toBe(1);
		expect(store.inbox().map((m) => m.body)).toEqual(["two"]);
		expect(store.markRead([a.id, b.id])).toBe(1);
		expect(store.inbox()).toHaveLength(0);
		expect(store.getMessage(b.id)?.readAt).not.toBeNull();
	});

	it("adds and updates contact settings", () => {
		const added = store.upsertContact({ publicKey: bob.id, name: "bob" });
		expect(added).toMatchObject({
			name: "bob",
			trust: "paired",
			autoSend: false,
			inboundPolicy: null,
		});
		expect(store.inboundPolicyFor(bob.id)).toBe("show_first");

		store.setSetting("default_inbound_policy", "auto_answer");
		expect(store.inboundPolicyFor(bob.id)).toBe("auto_answer");

		const updated = store.updateContact(bob.id, {
			autoSend: true,
			inboundPolicy: "show_first",
		});
		expect(updated.autoSend).toBe(true);
		expect(store.inboundPolicyFor(bob.id)).toBe("show_first");

		store.updateContact(bob.id, { trust: "blocked", inboundPolicy: null });
		const blocked = store.getContact(bob.id);
		expect(blocked?.trust).toBe("blocked");
		expect(blocked?.inboundPolicy).toBeNull();
		expect(blocked?.autoSend).toBe(true);

		store.upsertContact({ publicKey: bob.id, name: "Bob B." });
		expect(store.getContact(bob.id)?.name).toBe("Bob B.");
		expect(store.getContact(bob.id)?.trust).toBe("blocked");
		expect(store.listContacts()).toHaveLength(1);

		expect(() => store.updateContact(alice.id, { name: "x" })).toThrow();
	});

	it("stores settings", () => {
		expect(store.getSetting("k")).toBeUndefined();
		store.setSetting("k", "1");
		store.setSetting("k", "2");
		expect(store.getSetting("k")).toBe("2");
	});

	it("backs a ReplayGuard with the seen_ids table across reopen", () => {
		const env = createEnvelope({
			from: alice.id,
			to: bob.id,
			body: "hi",
			created_at: new Date(now),
		});
		const sealed = seal(env, alice);
		const guard = new ReplayGuard({ seen: store.seenIds(), now: () => now });
		open(sealed, bob, guard);

		store.close();
		store = Store.open(path, { now: () => now });
		const guard2 = new ReplayGuard({ seen: store.seenIds(), now: () => now });
		expect(() => open(sealed, bob, guard2)).toThrow(EnvelopeError);

		expect(store.seenIds().prune(now + 1)).toBe(1);
		expect(store.seenIds().has(env.id)).toBe(false);
	});
});
