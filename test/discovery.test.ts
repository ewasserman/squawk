import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, describe, expect, it } from "vitest";
import {
	type Advertisement,
	type DiscoveredPeer,
	Discovery,
	type MdnsBackend,
	parseDnsSdTxt,
	peerFromService,
	type RawService,
} from "../src/discovery.ts";
import { keyId } from "../src/encoding.ts";
import { fingerprint } from "../src/identity.ts";

function makeAd(name: string, port: number): Advertisement {
	const pub = ed25519.getPublicKey(ed25519.utils.randomSecretKey());
	return { name, keyId: keyId(pub), fingerprint: fingerprint(pub), port };
}

/** A fake mDNS "network": every backend attached to it sees every other's adverts. */
class FakeNetwork {
	backends = new Set<FakeBackend>();
	services = new Map<string, { owner: FakeBackend; service: RawService }>();

	announce(owner: FakeBackend, service: RawService): void {
		this.services.set(service.name, { owner, service });
		for (const b of this.backends) b.onUp?.(service);
	}

	withdraw(owner: FakeBackend): void {
		for (const [name, entry] of this.services) {
			if (entry.owner !== owner) continue;
			this.services.delete(name);
			// A goodbye packet carries only the instance name.
			for (const b of this.backends) b.onDown?.({ ...entry.service, txt: {} });
		}
	}
}

class FakeBackend implements MdnsBackend {
	onUp?: (s: RawService) => void;
	onDown?: (s: RawService) => void;
	private readonly net: FakeNetwork;
	constructor(net: FakeNetwork) {
		this.net = net;
	}

	publish(name: string, port: number, txt: Record<string, string>): void {
		this.net.announce(this, {
			name,
			host: `${name}.local`,
			port,
			addresses: ["fe80::1", "192.168.1.5"],
			txt,
		});
	}

	browse(onUp: (s: RawService) => void, onDown: (s: RawService) => void) {
		this.onUp = onUp;
		this.onDown = onDown;
		this.net.backends.add(this);
		for (const { service } of this.net.services.values()) onUp(service);
	}

	query(): void {
		for (const { service } of this.net.services.values()) this.onUp?.(service);
	}

	async destroy(): Promise<void> {
		this.net.backends.delete(this);
		this.net.withdraw(this);
	}
}

describe("peerFromService", () => {
	const ad = makeAd("alice", 4100);
	const base: RawService = {
		name: "alice (abcd)",
		host: "alice.local",
		port: 4100,
		txt: { name: "alice", id: ad.keyId, fp: ad.fingerprint, port: "4100" },
	};

	it("reads name, key id, fingerprint and port from the TXT record", () => {
		const peer = peerFromService(
			{ ...base, addresses: ["fe80::1", "10.0.0.2"] },
			42,
		);
		expect(peer).toEqual({
			name: "alice",
			keyId: ad.keyId,
			fingerprint: ad.fingerprint,
			host: "alice.local",
			addresses: ["10.0.0.2", "fe80::1"],
			port: 4100,
			lastSeen: 42,
		});
	});

	it("accepts TXT values given as bytes", () => {
		const enc = new TextEncoder();
		const txt = Object.fromEntries(
			Object.entries(base.txt ?? {}).map(([k, v]) => [
				k,
				enc.encode(String(v)),
			]),
		);
		expect(peerFromService({ ...base, txt }, 0)?.name).toBe("alice");
	});

	it("rejects records without a valid key id or with a bad port", () => {
		expect(
			peerFromService({ ...base, txt: { ...base.txt, id: "nope" } }, 0),
		).toBeNull();
		expect(
			peerFromService({ ...base, txt: { ...base.txt, port: "99999" } }, 0),
		).toBeNull();
		expect(peerFromService({ ...base, txt: {} }, 0)).toBeNull();
	});
});

describe("Discovery with mDNS mocked out", () => {
	it("finds other services, ignores itself, and notices when one leaves", async () => {
		const net = new FakeNetwork();
		const a = new Discovery({
			self: makeAd("alice", 4100),
			backend: new FakeBackend(net),
		});
		const bAd = makeAd("bob", 4200);
		const b = new Discovery({ self: bAd, backend: new FakeBackend(net) });
		const downs: DiscoveredPeer[] = [];
		a.on("down", (p) => downs.push(p));

		a.start();
		b.start();

		expect(a.peers().map((p) => p.name)).toEqual(["bob"]);
		expect(b.peers().map((p) => p.name)).toEqual(["alice"]);
		expect(a.peer(bAd.keyId)?.port).toBe(4200);

		await b.stop();
		expect(a.peers()).toEqual([]);
		expect(downs.map((p) => p.keyId)).toEqual([bAd.keyId]);
		await a.stop();
	});

	it("uses a unique instance name built from the name and fingerprint", () => {
		const ad = makeAd("alice", 1);
		const d = new Discovery({
			self: ad,
			backend: new FakeBackend(new FakeNetwork()),
		});
		expect(d.instanceName()).toBe(
			`alice (${ad.fingerprint.replace(/-/g, "").slice(0, 8)})`,
		);
	});
});

// Real multicast DNS. Hosted CI runners often block multicast, so this runs
// only on a developer machine (or when SQUAWK_TEST_MDNS=1).
const realMdns = !process.env.CI || process.env.SQUAWK_TEST_MDNS === "1";

describe.runIf(realMdns)("Discovery over real mDNS on this machine", () => {
	const running: Discovery[] = [];
	afterEach(async () => {
		await Promise.all(running.splice(0).map((d) => d.stop()));
	});

	it("two services find each other", async () => {
		const aAd = makeAd(`sq-test-a-${process.pid}`, 47001);
		const bAd = makeAd(`sq-test-b-${process.pid}`, 47002);
		const a = new Discovery({ self: aAd });
		const b = new Discovery({ self: bAd });
		running.push(a, b);

		const aSeesB = new Promise<DiscoveredPeer>((resolve) => {
			a.on("up", (p) => p.keyId === bAd.keyId && resolve(p));
		});
		const bSeesA = new Promise<DiscoveredPeer>((resolve) => {
			b.on("up", (p) => p.keyId === aAd.keyId && resolve(p));
		});
		a.start();
		b.start();
		const timer = setInterval(() => {
			a.refresh();
			b.refresh();
		}, 1000);
		try {
			const [seenB, seenA] = await Promise.all([aSeesB, bSeesA]);
			expect(seenB.port).toBe(47002);
			expect(seenA.port).toBe(47001);
			expect(seenB.fingerprint).toBe(bAd.fingerprint);
		} finally {
			clearInterval(timer);
		}
	}, 15_000);
});

describe("parseDnsSdTxt", () => {
	it("splits on unescaped spaces and keeps escaped ones", () => {
		expect(
			parseDnsSdTxt(" name=Alice\\ Smith id=abc fp=12-34 port=4100"),
		).toEqual({
			name: "Alice Smith",
			id: "abc",
			fp: "12-34",
			port: "4100",
		});
	});
});
