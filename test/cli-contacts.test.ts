import { mkdtempSync, rmSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli.ts";
import type { ContactsIo } from "../src/cli-contacts.ts";
import { Daemon } from "../src/daemon.ts";
import { initIdentity } from "../src/identity.ts";
import { NetworkTransport } from "../src/network.ts";
import { Pairing } from "../src/pairing.ts";

interface Node {
	home: string;
	daemon: Daemon;
	pairing: Pairing;
	address: string;
}

const nodes: Node[] = [];

afterEach(async () => {
	for (const n of nodes.splice(0)) {
		n.pairing.stop();
		await n.daemon.stop().catch(() => {});
		rmSync(n.home, { recursive: true, force: true });
	}
});

async function startNode(name: string): Promise<Node> {
	const home = mkdtempSync("/tmp/sq-");
	await initIdentity(home, name);
	const transport = new NetworkTransport({
		host: "127.0.0.1",
		discovery: false,
	});
	const daemon = new Daemon({ home, transport });
	await daemon.start();
	const pairing = new Pairing(daemon, transport, { timeoutMs: 5000 });
	pairing.start();
	const node = {
		home,
		daemon,
		pairing,
		address: `127.0.0.1:${transport.port}`,
	};
	nodes.push(node);
	return node;
}

/** Runs the CLI in-process against `home`, answering any question with `answer`. */
async function run(home: string, args: string[], answer = "y") {
	let out = "";
	let err = "";
	const io: ContactsIo = {
		stdout: (t) => {
			out += t;
		},
		stderr: (t) => {
			err += t;
		},
		env: { ...process.env, SQUAWK_HOME: home },
		ask: async (prompt) => {
			out += prompt;
			return answer;
		},
	};
	const code = await main(args, io);
	return { code, out, err };
}

describe("squawk pair, contacts, block", () => {
	it("pairs two people who both answer yes, then lists, blocks and unblocks", async () => {
		const alice = await startNode("alice");
		const bob = await startNode("bob");

		const bobRun = run(bob.home, ["pair", "--accept"]);
		await new Promise((r) => setTimeout(r, 50));
		const aliceRun = run(alice.home, ["pair", bob.address]);
		const [a, b] = await Promise.all([aliceRun, bobRun]);

		expect(a.code).toBe(0);
		expect(b.code).toBe(0);
		const codeOf = (out: string) => /Code: (\d{3} \d{3})/.exec(out)?.[1];
		expect(codeOf(a.out)).toBeDefined();
		expect(codeOf(a.out)).toBe(codeOf(b.out));
		expect(a.out).toContain('Paired with "bob"');
		expect(b.out).toContain('Paired with "alice"');

		const listed = await run(alice.home, ["contacts", "--json"]);
		expect(JSON.parse(listed.out)).toMatchObject([
			{ name: "bob", trust: "paired" },
		]);

		expect((await run(alice.home, ["block", "bob"])).out).toContain(
			'Blocked "bob"',
		);
		expect(alice.daemon.store.getContact(bob.daemon.identity.id)?.trust).toBe(
			"blocked",
		);
		expect((await run(alice.home, ["unblock", "bob"])).code).toBe(0);
		expect(alice.daemon.store.getContact(bob.daemon.identity.id)?.trust).toBe(
			"paired",
		);
	});

	it("saves nothing when a person answers no", async () => {
		const alice = await startNode("alice");
		const bob = await startNode("bob");

		const bobRun = run(bob.home, ["pair", "--accept"], "n");
		await new Promise((r) => setTimeout(r, 50));
		const a = await run(alice.home, ["pair", bob.address], "y");
		const b = await bobRun;

		expect(b.code).toBe(1);
		expect(b.out).toContain("Nothing was saved");
		expect(a.code).toBe(1);
		expect(a.err).toMatch(/cancelled/);
		expect(alice.daemon.store.listContacts()).toEqual([]);
		expect(bob.daemon.store.listContacts()).toEqual([]);
	});

	it("explains usage and a missing service", async () => {
		const home = mkdtempSync("/tmp/sq-");
		try {
			expect((await run(home, ["pair"])).code).toBe(2);
			const r = await run(home, ["contacts"]);
			expect(r.code).toBe(1);
			expect(r.err).toContain("not running");
		} finally {
			rmSync(home, { recursive: true, force: true });
		}
	});
});
