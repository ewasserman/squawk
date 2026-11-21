import {
	mkdirSync,
	mkdtempSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pidPath, runDir, socketPath } from "../src/config.ts";
import {
	Daemon,
	DaemonRunningError,
	type MessageNotification,
	type Transport,
} from "../src/daemon.ts";
import { createEnvelope, type Envelope } from "../src/envelope.ts";
import {
	type Identity,
	identityFromSecretKey,
	initIdentity,
} from "../src/identity.ts";
import { RpcClient, RpcErrorCode } from "../src/rpc.ts";

const alice = identityFromSecretKey("alice", ed25519.utils.randomSecretKey());

let home: string;
let me: Identity;
let daemon: Daemon;
let kicked: Envelope[];
const clients: RpcClient[] = [];

beforeEach(async () => {
	// Unix socket paths are limited to about 104 bytes on macOS, so keep it short.
	home = mkdtempSync("/tmp/sq-");
	me = await initIdentity(home, "me");
	kicked = [];
	const transport: Transport = {
		kick(envelope) {
			kicked.push(envelope);
		},
	};
	daemon = new Daemon({ home, transport });
	await daemon.start();
	daemon.store.upsertContact({
		publicKey: alice.id,
		name: "alice",
		inboundPolicy: "auto_answer",
	});
});

afterEach(async () => {
	for (const client of clients.splice(0)) {
		if (!client.closed) await client.close();
	}
	await daemon.stop();
	rmSync(home, { recursive: true, force: true });
});

interface FakeSession {
	client: RpcClient;
	label: string;
	messages: MessageNotification[];
}

/** Connects over the real socket and registers a session with `label`. */
async function openSession(label: string): Promise<FakeSession> {
	const client = await RpcClient.connect(socketPath(home));
	clients.push(client);
	const messages: MessageNotification[] = [];
	client.onNotification("message", (params) =>
		messages.push(params as MessageNotification),
	);
	const result = await client.call<{ session_id: string; label: string }>(
		"register_session",
		{ label },
	);
	expect(result.label).toBe(label);
	expect(result.session_id).toMatch(/[0-9a-f-]{36}/);
	return { client, label, messages };
}

function incoming(body: string, session?: string) {
	return createEnvelope({
		from: alice.id,
		to: me.id,
		body,
		...(session === undefined ? {} : { session }),
	});
}

/** Waits for in-flight notifications by making a round trip on each client. */
async function settle(...sessions: FakeSession[]): Promise<void> {
	for (const s of sessions) await s.client.call("status");
}

const bodies = (s: FakeSession) => s.messages.map((m) => m.envelope.body);

describe("Daemon routing", () => {
	it("delivers to the session the envelope names", async () => {
		const a = await openSession("a");
		const b = await openSession("b");
		await a.client.call("status"); // a is now the most recently active
		const result = daemon.deliverIncoming(incoming("for b", "b"));
		expect(result).toEqual({ stored: true, deliveredTo: "b" });
		await expect.poll(() => bodies(b)).toEqual(["for b"]);
		await settle(a);
		expect(bodies(a)).toEqual([]);
		expect(b.messages[0]).toMatchObject({
			from_name: "alice",
			policy: "auto_answer",
			envelope: { from: alice.id, to: me.id, session: "b" },
		});
	});

	it("delivers to the most recently active session when none is named or the named one is not open", async () => {
		const a = await openSession("a");
		const b = await openSession("b");
		// b registered last, so it is the most recent until a makes a call.
		daemon.deliverIncoming(incoming("first"));
		await expect.poll(() => bodies(b)).toEqual(["first"]);

		await a.client.call("peers");
		daemon.deliverIncoming(incoming("second"));
		daemon.deliverIncoming(incoming("third", "nobody"));
		await expect.poll(() => bodies(a)).toEqual(["second", "third"]);
		await settle(b);
		expect(bodies(b)).toEqual(["first"]);
	});

	it("queues messages while no session is open and delivers them once on register", async () => {
		const first = incoming("queued one");
		expect(daemon.deliverIncoming(first)).toEqual({
			stored: true,
			deliveredTo: null,
		});
		daemon.deliverIncoming(incoming("queued two", "elsewhere"));
		expect(daemon.status().queued_inbound).toBe(2);

		const a = await openSession("a");
		await expect.poll(() => bodies(a)).toEqual(["queued one", "queued two"]);
		expect(daemon.status().queued_inbound).toBe(0);
		expect(daemon.store.getMessage(first.id)?.deliveredAt).not.toBeNull();

		const b = await openSession("b");
		await settle(a, b);
		expect(bodies(b)).toEqual([]);
		expect(a.messages).toHaveLength(2);
	});

	it("delivers a queued message to its named session when that label registers", async () => {
		daemon.deliverIncoming(incoming("for b", "b"));
		const b = await openSession("b");
		await expect.poll(() => bodies(b)).toEqual(["for b"]);
	});

	it("unregisters a session when its connection closes", async () => {
		const a = await openSession("a");
		await a.client.close();
		await expect.poll(() => daemon.status().sessions).toEqual([]);
		expect(daemon.deliverIncoming(incoming("later")).deliveredTo).toBeNull();
	});

	it("routes to the newest registration when labels repeat", async () => {
		const old = await openSession("same");
		const newer = await openSession("same");
		await old.client.call("status");
		daemon.deliverIncoming(incoming("hi", "same"));
		await expect.poll(() => bodies(newer)).toEqual(["hi"]);
		await settle(old);
		expect(bodies(old)).toEqual([]);
	});

	it("ignores a message whose id was already stored", async () => {
		const envelope = incoming("once");
		const a = await openSession("a");
		daemon.deliverIncoming(envelope);
		expect(daemon.deliverIncoming(envelope)).toEqual({
			stored: false,
			deliveredTo: null,
		});
		await settle(a);
		expect(bodies(a)).toEqual(["once"]);
	});

	it("sends every incoming message to subscribers", async () => {
		const a = await openSession("a");
		const tail = await RpcClient.connect(socketPath(home));
		clients.push(tail);
		const seen: MessageNotification[] = [];
		tail.onNotification("message", (p) => seen.push(p as MessageNotification));
		expect(await tail.call("subscribe")).toEqual({ ok: true });
		daemon.deliverIncoming(incoming("one"));
		daemon.deliverIncoming(incoming("two", "a"));
		await expect
			.poll(() => seen.map((m) => m.envelope.body))
			.toEqual(["one", "two"]);
		await expect.poll(() => bodies(a)).toEqual(["one", "two"]);
	});
});

describe("Daemon methods", () => {
	it("send queues a message for a contact by name and kicks the transport", async () => {
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		const result = await client.call<{
			id: string;
			thread_id: string;
			state: string;
		}>("send", { to: "alice", body: "hello", kind: "question", session: "x" });
		expect(result.state).toBe("queued");
		expect(result.thread_id).toBe(result.id);
		const item = daemon.store.getOutbound(result.id);
		expect(item?.recipient).toBe(alice.id);
		expect(item?.envelope).toMatchObject({
			id: result.id,
			from: me.id,
			to: alice.id,
			body: "hello",
			kind: "question",
			session: "x",
		});
		expect(kicked).toEqual([item?.envelope]);
		expect(daemon.store.getMessage(result.id)?.state).toBe("queued");
		expect(daemon.status().queued_outbound).toBe(1);

		const byKey = await client.call<{ id: string }>("send", {
			to: alice.id,
			body: "again",
			thread_id: result.thread_id,
			in_reply_to: result.id,
		});
		expect(daemon.store.getMessage(byKey.id)?.threadId).toBe(result.thread_id);
	});

	it("send to an unknown contact is an error with a clear message", async () => {
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		await expect(
			client.call("send", { to: "mallory", body: "hi" }),
		).rejects.toMatchObject({
			code: RpcErrorCode.ApplicationError,
			message: expect.stringContaining('unknown contact "mallory"'),
		});
		await expect(client.call("send", { body: "no to" })).rejects.toMatchObject({
			code: RpcErrorCode.InvalidParams,
		});
	});

	it("inbox lists unread messages and can mark them read", async () => {
		daemon.deliverIncoming(incoming("unread"));
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		const first = await client.call<{ messages: MessageNotification[] }>(
			"inbox",
			{ mark_read: true },
		);
		expect(first.messages.map((m) => m.envelope.body)).toEqual(["unread"]);
		expect(first.messages[0]?.from_name).toBe("alice");
		const second = await client.call<{ messages: unknown[] }>("inbox");
		expect(second.messages).toEqual([]);
	});

	it("get_message returns a stored message, incoming or outgoing", async () => {
		const envelope = incoming("a question");
		daemon.deliverIncoming(envelope);
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		const { message } = await client.call<{
			message: Record<string, unknown>;
		}>("get_message", { id: envelope.id });
		expect(message).toEqual({
			id: envelope.id,
			direction: "in",
			peer: alice.id,
			peer_name: "alice",
			session: null,
			thread_id: envelope.thread_id,
			in_reply_to: null,
			kind: "text",
			body: "a question",
			created_at: envelope.created_at,
			state: "unread",
		});

		const sent = await client.call<{ id: string }>("send", {
			to: "alice",
			body: "out",
		});
		const out = await client.call<{ message: Record<string, unknown> }>(
			"get_message",
			{ id: sent.id },
		);
		expect(out.message).toMatchObject({
			direction: "out",
			peer: alice.id,
			body: "out",
		});

		await expect(
			client.call("get_message", { id: "nope" }),
		).rejects.toMatchObject({
			code: RpcErrorCode.ApplicationError,
			message: expect.stringContaining('no message with id "nope"'),
		});
		await expect(client.call("get_message", {})).rejects.toMatchObject({
			code: RpcErrorCode.InvalidParams,
		});
	});

	it("contacts lists contacts with their fingerprint and policy", async () => {
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		const { contacts } = await client.call<{
			contacts: Array<Record<string, unknown>>;
		}>("contacts");
		expect(contacts).toEqual([
			{
				name: "alice",
				key_id: alice.id,
				fingerprint: expect.any(String),
				trust: "paired",
				auto_send: false,
				inbound_policy: "auto_answer",
			},
		]);
	});

	it("status and peers report the service state", async () => {
		const a = await openSession("a");
		const status = await a.client.call<Record<string, unknown>>("status");
		expect(status).toMatchObject({
			name: "me",
			key_id: me.id,
			pid: process.pid,
			queued_inbound: 0,
			queued_outbound: 0,
		});
		expect(status.sessions).toEqual([
			{ label: "a", last_active: expect.any(String) },
		]);
		expect(await a.client.call("peers")).toEqual({ peers: [] });
	});

	it("stop over the socket shuts the service down", async () => {
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		expect(await client.call("stop")).toEqual({ ok: true });
		await daemon.whenStopped();
		await expect(RpcClient.connect(socketPath(home))).rejects.toThrow();
		expect(() => statSync(pidPath(home))).toThrow();
	});
});

describe("Daemon socket", () => {
	it("uses mode 0700 for run/ and 0600 for the socket, and writes a pid file", () => {
		expect(statSync(runDir(home)).mode & 0o777).toBe(0o700);
		expect(statSync(socketPath(home)).mode & 0o777).toBe(0o600);
		expect(statSync(pidPath(home)).isFile()).toBe(true);
	});

	it("refuses to start a second service on the same socket", async () => {
		const second = new Daemon({ home });
		await expect(second.start()).rejects.toBeInstanceOf(DaemonRunningError);
	});

	it("replaces a stale socket file when nothing is listening", async () => {
		await daemon.stop();
		mkdirSync(runDir(home), { recursive: true });
		writeFileSync(socketPath(home), "");
		daemon = new Daemon({ home });
		await daemon.start();
		const client = await RpcClient.connect(socketPath(home));
		clients.push(client);
		expect(await client.call("peers")).toEqual({ peers: [] });
	});
});
