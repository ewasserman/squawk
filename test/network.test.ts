import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer } from "node:net";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { Daemon } from "../src/daemon.ts";
import {
	Discovery,
	type MdnsBackend,
	type RawService,
} from "../src/discovery.ts";
import { createEnvelope } from "../src/envelope.ts";
import {
	fingerprint,
	identityFromSecretKey,
	initIdentity,
} from "../src/identity.ts";
import {
	type Address,
	dialable,
	NetworkTransport,
	PeerLink,
} from "../src/network.ts";

/** One service with its own home directory, on loopback, without mDNS. */
interface Node {
	home: string;
	daemon: Daemon;
	transport: NetworkTransport;
	port: number;
}

const homes: string[] = [];
const running: Daemon[] = [];
/** key id → address, shared by all nodes in a test (stands in for mDNS). */
let book: Map<string, Address>;

afterEach(async () => {
	await Promise.all(running.splice(0).map((d) => d.stop().catch(() => {})));
	for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});

async function makeHome(name: string): Promise<string> {
	const home = mkdtempSync("/tmp/sq-");
	homes.push(home);
	await initIdentity(home, name);
	return home;
}

async function startNode(home: string, port = 0): Promise<Node> {
	const transport = new NetworkTransport({
		port,
		host: "127.0.0.1",
		discovery: false,
		resolve: (key) => book.get(key),
		retryIntervalMs: 50,
		ackTimeoutMs: 2000,
		handshakeTimeoutMs: 2000,
	});
	const daemon = new Daemon({ home, transport });
	await daemon.start();
	running.push(daemon);
	book.set(daemon.identity.id, { host: "127.0.0.1", port: transport.port });
	return { home, daemon, transport, port: transport.port };
}

async function stopNode(node: Node): Promise<void> {
	await node.daemon.stop();
	running.splice(running.indexOf(node.daemon), 1);
}

function pair(a: Node, b: Node): void {
	a.daemon.store.upsertContact({
		publicKey: b.daemon.identity.id,
		name: b.daemon.identity.name,
		trust: "paired",
	});
	b.daemon.store.upsertContact({
		publicKey: a.daemon.identity.id,
		name: a.daemon.identity.name,
		trust: "paired",
	});
}

async function waitFor<T>(
	check: () => T | undefined | false,
	timeoutMs = 8000,
): Promise<T> {
	const start = Date.now();
	for (;;) {
		const value = check();
		if (value) return value;
		if (Date.now() - start > timeoutMs) throw new Error("timed out waiting");
		await new Promise((r) => setTimeout(r, 25));
	}
}

describe("sending between hosts", () => {
	it("delivers a sealed message and records the acknowledgement", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		pair(alice, bob);

		const sent = await alice.daemon.send({ to: "bob", body: "hello bob" });

		const received = await waitFor(() => bob.daemon.store.getMessage(sent.id));
		expect(received.body).toBe("hello bob");
		expect(received.direction).toBe("in");
		await waitFor(() => alice.daemon.store.ackedAt(sent.id));
		expect(alice.daemon.store.getOutbound(sent.id)).toBeUndefined();
	});

	it("delivers a message that waited in the queue longer than the 5-minute freshness window", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		pair(alice, bob);
		// Written an hour ago while Bob was away; still queued.
		const old = createEnvelope({
			from: alice.daemon.identity.id,
			to: bob.daemon.identity.id,
			body: "written an hour ago",
			created_at: new Date(Date.now() - 60 * 60_000),
		});
		alice.daemon.store.queueOutgoing(old);
		alice.transport.kick();

		const received = await waitFor(() => bob.daemon.store.getMessage(old.id));
		expect(received.body).toBe("written an hour ago");
		expect(received.createdAt).toBe(old.created_at);
		await waitFor(() => alice.daemon.store.ackedAt(old.id));
	});

	it("refuses an incoming id that belongs to a message from someone else", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		const carol = await startNode(await makeHome("carol"));
		pair(alice, bob);
		pair(carol, bob);

		const fromAlice = await alice.daemon.send({
			to: "bob",
			body: "from alice",
		});
		await waitFor(() => alice.daemon.store.ackedAt(fromAlice.id));
		// Carol reuses the id of Alice's message.
		const reused = createEnvelope({
			from: carol.daemon.identity.id,
			to: bob.daemon.identity.id,
			body: "from carol",
		});
		const clash = { ...reused, id: fromAlice.id, thread_id: fromAlice.id };
		carol.daemon.store.queueOutgoing(clash);
		carol.transport.kick();
		await waitFor(() =>
			carol.daemon.store
				.getOutbound(fromAlice.id)
				?.lastError?.includes("message id already in use"),
		);
		expect(bob.daemon.store.getMessage(fromAlice.id)?.body).toBe("from alice");
		expect(carol.daemon.store.ackedAt(fromAlice.id)).toBeUndefined();
	});

	it("falls back to the saved address when the advertised one is someone else", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		const mallory = await startNode(await makeHome("mallory"));
		pair(alice, bob);
		const bobAddress = book.get(bob.daemon.identity.id);
		alice.daemon.store.setSetting(
			`address:${bob.daemon.identity.id}`,
			`127.0.0.1:${bobAddress?.port}`,
		);
		// Mallory advertises Bob's key with her own address.
		book.set(bob.daemon.identity.id, {
			host: "127.0.0.1",
			port: mallory.port,
		});
		const sent = await alice.daemon.send({ to: "bob", body: "for bob" });
		await waitFor(() => bob.daemon.store.getMessage(sent.id));
	});

	it("does not hold up other recipients while one is slow to answer", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		const carol = await startNode(await makeHome("carol"));
		pair(alice, bob);
		pair(alice, carol);
		// Carol's address accepts connections but never answers.
		const silent = createServer(() => {});
		await new Promise<void>((r) => silent.listen(0, "127.0.0.1", () => r()));
		const silentPort = (silent.address() as AddressInfo).port;
		book.set(carol.daemon.identity.id, { host: "127.0.0.1", port: silentPort });
		try {
			await alice.daemon.send({ to: "carol", body: "for carol" });
			await new Promise((r) => setTimeout(r, 100));
			const start = Date.now();
			const sent = await alice.daemon.send({ to: "bob", body: "for bob" });
			await waitFor(() => bob.daemon.store.getMessage(sent.id));
			// Well under the 2 s handshake timeout Carol's dial is stuck in.
			expect(Date.now() - start).toBeLessThan(1500);
		} finally {
			silent.close();
		}
	});

	it("retries after the receiver restarts", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bobHome = await makeHome("bob");
		let bob = await startNode(bobHome);
		pair(alice, bob);
		const bobPort = bob.port;
		await stopNode(bob);

		const sent = await alice.daemon.send({ to: "bob", body: "are you there?" });
		await waitFor(
			() => (alice.daemon.store.getOutbound(sent.id)?.attempts ?? 0) >= 1,
		);
		expect(alice.daemon.store.getOutbound(sent.id)?.lastError).toBeTruthy();

		bob = await startNode(bobHome, bobPort);
		const received = await waitFor(
			() => bob.daemon.store.getMessage(sent.id),
			10_000,
		);
		expect(received.body).toBe("are you there?");
		await waitFor(() => alice.daemon.store.ackedAt(sent.id));
	}, 20_000);

	it("refuses a connection from a key that is not a paired contact", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		// Only alice thinks they are paired; bob has never heard of alice.
		alice.daemon.store.upsertContact({
			publicKey: bob.daemon.identity.id,
			name: "bob",
			trust: "paired",
		});

		const sent = await alice.daemon.send({ to: "bob", body: "let me in" });
		await waitFor(
			() => (alice.daemon.store.getOutbound(sent.id)?.attempts ?? 0) >= 1,
		);
		expect(bob.daemon.store.getMessage(sent.id)).toBeUndefined();
		expect(alice.daemon.store.ackedAt(sent.id)).toBeUndefined();
	});

	it("refuses a blocked contact", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		pair(alice, bob);
		bob.daemon.store.updateContact(alice.daemon.identity.id, {
			trust: "blocked",
		});

		const sent = await alice.daemon.send({ to: "bob", body: "blocked?" });
		await waitFor(
			() => (alice.daemon.store.getOutbound(sent.id)?.attempts ?? 0) >= 1,
		);
		expect(bob.daemon.store.getMessage(sent.id)).toBeUndefined();
	});

	it("drops a stranger who signs the handshake with a key it does not hold", async () => {
		book = new Map();
		const bob = await startNode(await makeHome("bob"));
		const alice = identityFromSecretKey(
			"alice",
			ed25519.utils.randomSecretKey(),
		);
		bob.daemon.store.upsertContact({
			publicKey: alice.id,
			name: "alice",
			trust: "paired",
		});
		// Mallory claims alice's key but signs with her own.
		const mallory = identityFromSecretKey(
			"mallory",
			ed25519.utils.randomSecretKey(),
		);
		const impostor = { ...mallory, id: alice.id };
		const ws = new WebSocket(`ws://127.0.0.1:${bob.port}/`);
		const link = new PeerLink(ws, impostor, () => "paired", {
			outgoing: true,
			timeoutMs: 2000,
		});
		await expect(link.ready).rejects.toThrow();
		const code = await new Promise<number>((resolve) => {
			if (ws.readyState === WebSocket.CLOSED) resolve(-1);
			else ws.on("close", (c) => resolve(c));
		});
		expect([4001, 1005, 1006, -1]).toContain(code);
	});

	it("does not deliver to a host that answers with a different key", async () => {
		book = new Map();
		const alice = await startNode(await makeHome("alice"));
		const bob = await startNode(await makeHome("bob"));
		const carol = await startNode(await makeHome("carol"));
		pair(alice, bob);
		pair(alice, carol);
		// The address book wrongly points bob's key at carol's port.
		book.set(bob.daemon.identity.id, { host: "127.0.0.1", port: carol.port });

		const sent = await alice.daemon.send({ to: "bob", body: "for bob only" });
		await waitFor(
			() => (alice.daemon.store.getOutbound(sent.id)?.attempts ?? 0) >= 1,
		);
		expect(carol.daemon.store.getMessage(sent.id)).toBeUndefined();
		expect(alice.daemon.store.getOutbound(sent.id)?.lastError).toMatch(
			/different key|closed/,
		);
	});
});

describe("peers", () => {
	it("reports peers seen by discovery and whether each is paired", async () => {
		const home = await makeHome("alice");
		const carol = identityFromSecretKey(
			"carol",
			ed25519.utils.randomSecretKey(),
		);
		const dave = identityFromSecretKey("dave", ed25519.utils.randomSecretKey());
		const advert = (who: typeof carol, port: number): RawService => ({
			name: `${who.name} (x)`,
			host: `${who.name}.local`,
			port,
			addresses: ["192.168.1.9"],
			txt: {
				name: who.name,
				id: who.id,
				fp: fingerprint(who.publicKey),
				port: String(port),
			},
		});
		const backend: MdnsBackend = {
			publish() {},
			browse(onUp) {
				onUp(advert(carol, 4001));
				onUp(advert(dave, 4002));
			},
			query() {},
			async destroy() {},
		};
		const transport = new NetworkTransport({
			host: "127.0.0.1",
			discovery: new Discovery({
				self: { name: "alice", keyId: "unused", fingerprint: "00", port: 0 },
				backend,
			}),
		});
		const daemon = new Daemon({ home, transport });
		await daemon.start();
		running.push(daemon);
		daemon.store.upsertContact({
			publicKey: carol.id,
			name: "carol",
			trust: "paired",
		});

		const peers = daemon.peers().sort((a, b) => a.name.localeCompare(b.name));
		expect(peers.map((p) => [p.name, p.port, p.paired])).toEqual([
			["carol", 4001, true],
			["dave", 4002, false],
		]);
		expect(transport.resolve(dave.id)).toEqual({
			host: "192.168.1.9",
			port: 4002,
		});
		expect(daemon.status().port).toBe(transport.port);
	});
});

describe("dialable", () => {
	it("refuses IPv6 link-local addresses, which cannot go in a URL", () => {
		expect(dialable("192.168.1.9")).toBe(true);
		expect(dialable("hal.local")).toBe(true);
		expect(dialable("2001:db8::1")).toBe(true);
		expect(dialable("fe80::1c2b:3d4e")).toBe(false);
		expect(dialable("FE80::1%en0")).toBe(false);
	});
});
