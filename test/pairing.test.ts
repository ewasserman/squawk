import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { socketPath } from "../src/config.ts";
import { Daemon } from "../src/daemon.ts";
import { toBase64Url } from "../src/encoding.ts";
import { identityFromSecretKey, initIdentity } from "../src/identity.ts";
import { NetworkTransport, PeerLink } from "../src/network.ts";
import {
	Pairing,
	type PairingOffer,
	pairCode,
	pairCommitment,
} from "../src/pairing.ts";
import { RpcClient } from "../src/rpc.ts";

interface Node {
	home: string;
	daemon: Daemon;
	transport: NetworkTransport;
	pairing: Pairing;
	rpc: RpcClient;
	address: string;
}

const homes: string[] = [];
const nodes: Node[] = [];

afterEach(async () => {
	for (const n of nodes.splice(0)) {
		n.pairing.stop();
		await n.rpc.close();
		await n.daemon.stop().catch(() => {});
	}
	for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});

/** Starts a service on loopback with no mDNS and no address book, so only saved addresses work. */
async function startNode(name: string, timeoutMs = 10_000): Promise<Node> {
	const home = mkdtempSync("/tmp/sq-");
	homes.push(home);
	await initIdentity(home, name);
	const transport = new NetworkTransport({
		host: "127.0.0.1",
		discovery: false,
		retryIntervalMs: 50,
		handshakeTimeoutMs: 2000,
	});
	const daemon = new Daemon({ home, transport });
	await daemon.start();
	const pairing = new Pairing(daemon, transport, { timeoutMs });
	pairing.start();
	const rpc = await RpcClient.connect(socketPath(home));
	const node = {
		home,
		daemon,
		transport,
		pairing,
		rpc,
		address: `127.0.0.1:${transport.port}`,
	};
	nodes.push(node);
	return node;
}

async function waitFor<T>(check: () => T | undefined | false, ms = 5000) {
	const start = Date.now();
	for (;;) {
		const v = check();
		if (v) return v;
		if (Date.now() - start > ms) throw new Error("timed out waiting");
		await new Promise((r) => setTimeout(r, 25));
	}
}

describe("pairCode", () => {
	const k1 = identityFromSecretKey("a", ed25519.utils.randomSecretKey()).id;
	const k2 = identityFromSecretKey("b", ed25519.utils.randomSecretKey()).id;
	const k3 = identityFromSecretKey("c", ed25519.utils.randomSecretKey()).id;
	const n1 = randomBytes(32);
	const n2 = randomBytes(32);

	it("is six digits and the same for the same inputs", () => {
		const code = pairCode(k1, k2, n1, n2);
		expect(code).toMatch(/^\d{6}$/);
		expect(pairCode(k1, k2, n1, n2)).toBe(code);
	});

	it("changes when a key is replaced, as an attacker in the middle would", () => {
		expect(pairCode(k1, k3, n1, n2)).not.toBe(pairCode(k1, k2, n1, n2));
		expect(pairCode(k3, k2, n1, n2)).not.toBe(pairCode(k1, k2, n1, n2));
	});
});

describe("pairing between two services", () => {
	it("pairs when both people confirm matching codes, and messages then flow both ways", async () => {
		const alice = await startNode("alice");
		const bob = await startNode("bob");

		const bobWaits = bob.rpc.call<PairingOffer>("pair_accept");
		await new Promise((r) => setTimeout(r, 20));
		const aliceOffer = await alice.rpc.call<PairingOffer>("pair_start", {
			peer: bob.address,
		});
		const bobOffer = await bobWaits;

		expect(aliceOffer.code).toMatch(/^\d{6}$/);
		expect(aliceOffer.code).toBe(bobOffer.code);
		expect(aliceOffer.peer_name).toBe("bob");
		expect(bobOffer.peer_name).toBe("alice");
		expect(aliceOffer.peer_key).toBe(bob.daemon.identity.id);
		expect(bobOffer.peer_key).toBe(alice.daemon.identity.id);

		const [a, b] = await Promise.all([
			alice.rpc.call<{ status: string }>("pair_confirm", {
				pairing_id: aliceOffer.pairing_id,
				match: true,
			}),
			bob.rpc.call<{ status: string }>("pair_confirm", {
				pairing_id: bobOffer.pairing_id,
				match: true,
			}),
		]);
		expect(a.status).toBe("paired");
		expect(b.status).toBe("paired");
		expect(alice.daemon.store.getContact(bob.daemon.identity.id)?.trust).toBe(
			"paired",
		);
		expect(bob.daemon.store.getContact(alice.daemon.identity.id)?.name).toBe(
			"alice",
		);

		// Each side saved the other's address during pairing.
		const toBob = await alice.daemon.send({ to: "bob", body: "hi bob" });
		await waitFor(() => bob.daemon.store.getMessage(toBob.id));
		const toAlice = await bob.daemon.send({ to: "alice", body: "hi alice" });
		await waitFor(() => alice.daemon.store.getMessage(toAlice.id));
	});

	it("saves nothing when one person says the codes do not match", async () => {
		const alice = await startNode("alice");
		const bob = await startNode("bob");

		const bobWaits = bob.pairing.accept();
		await new Promise((r) => setTimeout(r, 20));
		const aliceOffer = await alice.pairing.initiate(bob.address);
		const bobOffer = await bobWaits;

		const aliceDone = alice.pairing.confirm(aliceOffer.pairing_id, true);
		await expect(
			bob.pairing.confirm(bobOffer.pairing_id, false),
		).rejects.toThrow(/did not match/);
		await expect(aliceDone).rejects.toThrow(/cancelled/);
		expect(
			alice.daemon.store.getContact(bob.daemon.identity.id),
		).toBeUndefined();
		expect(
			bob.daemon.store.getContact(alice.daemon.identity.id),
		).toBeUndefined();
	});

	it("does not save the contact if only one side confirms", async () => {
		const alice = await startNode("alice", 500);
		const bob = await startNode("bob", 500);

		const bobWaits = bob.pairing.accept();
		await new Promise((r) => setTimeout(r, 20));
		const aliceOffer = await alice.pairing.initiate(bob.address);
		await bobWaits;

		await expect(
			alice.pairing.confirm(aliceOffer.pairing_id, true),
		).rejects.toThrow(/timed out|disconnected/);
		expect(
			alice.daemon.store.getContact(bob.daemon.identity.id),
		).toBeUndefined();
		expect(
			bob.daemon.store.getContact(alice.daemon.identity.id),
		).toBeUndefined();
	});

	it("leaves a paired contact's message connection alone while waiting to pair", async () => {
		const alice = await startNode("alice");
		const bob = await startNode("bob");
		for (const [a, b] of [
			[alice, bob],
			[bob, alice],
		] as const) {
			a.daemon.store.upsertContact({
				publicKey: b.daemon.identity.id,
				name: b.daemon.identity.name,
				trust: "paired",
			});
			a.daemon.store.setSetting(`address:${b.daemon.identity.id}`, b.address);
		}
		const waiting = bob.pairing.accept();
		let settled = false;
		waiting.then(
			() => {
				settled = true;
			},
			() => {
				settled = true;
			},
		);
		const sent = await alice.daemon.send({ to: "bob", body: "just a message" });
		await waitFor(() => bob.daemon.store.getMessage(sent.id));
		// Alice's service restarts, closing its connection to Bob.
		await alice.daemon.stop();
		await new Promise((r) => setTimeout(r, 100));
		expect(settled).toBe(false);
		bob.pairing.stop();
		await waiting.catch(() => {});
	});

	it("refuses an unpaired key when nobody is waiting to pair", async () => {
		const alice = await startNode("alice");
		const bob = await startNode("bob");
		await expect(alice.pairing.initiate(bob.address)).rejects.toThrow(
			/is not waiting to pair\. Ask them to run `squawk pair --accept`/,
		);
	});

	it("refuses an initiator whose reveal does not match its commitment", async () => {
		const bob = await startNode("bob");
		const bobWaits = bob.pairing.accept();
		await new Promise((r) => setTimeout(r, 20));

		// Mallory commits to one nonce and then reveals a different one.
		const mallory = identityFromSecretKey(
			"mallory",
			ed25519.utils.randomSecretKey(),
		);
		const ws = new WebSocket(`ws://${bob.address}/`);
		const link = new PeerLink(ws, mallory, () => "pairing", {
			outgoing: true,
			timeoutMs: 2000,
		});
		await link.ready;
		const frames: Array<{ t: string; reason?: unknown }> = [];
		link.onFrame((f) => {
			frames.push(f);
			if (f.t === "pair-nonce") {
				link.send({ t: "pair-reveal", nonce: toBase64Url(randomBytes(32)) });
			}
		});
		link.send({
			t: "pair-commit",
			commit: toBase64Url(pairCommitment(mallory.id, randomBytes(32))),
			name: "alice",
			port: 1,
		});

		await expect(bobWaits).rejects.toThrow(/commitment did not match/);
		await waitFor(() => frames.some((f) => f.t === "pair-abort"));
		expect(bob.daemon.store.getContact(mallory.id)).toBeUndefined();
		ws.terminate();
	});

	it("refuses to pair with a discovered name that is not on the network", async () => {
		const alice = await startNode("alice");
		await expect(
			alice.rpc.call("pair_start", { peer: "nobody" }),
		).rejects.toThrow(/no squawk service called "nobody"/);
	});
});
