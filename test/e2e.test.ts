/**
 * The whole flow on one machine, as two people would use it: two services
 * with separate home directories, each with a "Claude" (a fake MCP client
 * talking to `squawk mcp`'s server code). No mDNS, so it also runs in CI.
 *
 *   pairing → Alice's Claude sends (Alice confirms in the form) → the message
 *   is pushed into Bob's session with Bob's policy → Bob's Claude replies →
 *   the reply is pushed into Alice's session in the same thread.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { Daemon } from "../src/daemon.ts";
import { DaemonLink } from "../src/daemon-link.ts";
import { initIdentity } from "../src/identity.ts";
import { createMcpServer } from "../src/mcp.ts";
import { NetworkTransport } from "../src/network.ts";
import { Pairing } from "../src/pairing.ts";

const ChannelSchema = z.object({
	method: z.literal("notifications/claude/channel"),
	params: z.object({
		content: z.string(),
		meta: z.record(z.string(), z.string()),
	}),
});
type Pushed = z.infer<typeof ChannelSchema>["params"];

interface Person {
	home: string;
	daemon: Daemon;
	pairing: Pairing;
	link: DaemonLink;
	claude: Client;
	pushed: Pushed[];
	forms: string[];
	address: string;
}

const people: Person[] = [];

afterEach(async () => {
	for (const p of people.splice(0)) {
		await p.claude.close();
		await p.link.close();
		p.pairing.stop();
		await p.daemon.stop();
		rmSync(p.home, { recursive: true, force: true });
	}
});

/** Starts one person's service and a Claude session connected to it. */
async function person(name: string, session: string): Promise<Person> {
	const home = mkdtempSync("/tmp/sq-");
	await initIdentity(home, name);
	const transport = new NetworkTransport({
		host: "127.0.0.1",
		discovery: false,
		retryIntervalMs: 50,
	});
	const daemon = new Daemon({ home, transport });
	await daemon.start();
	const pairing = new Pairing(daemon, transport, { timeoutMs: 5000 });
	pairing.start();

	const link = new DaemonLink({ home, label: session, log: () => {} });
	expect(await link.open()).toBe(true);
	const server = createMcpServer({ daemon: link, log: () => {} });
	const claude = new Client(
		{ name: `claude-${name}`, version: "0" },
		{ capabilities: { elicitation: { form: {} } } },
	);
	const pushed: Pushed[] = [];
	const forms: string[] = [];
	claude.setNotificationHandler(ChannelSchema, (n) => {
		pushed.push(n.params);
	});
	// The human accepts every confirmation form without editing.
	claude.setRequestHandler(ElicitRequestSchema, (request) => {
		const params = request.params as unknown as {
			message: string;
			requestedSchema: { properties: { text: { default: string } } };
		};
		forms.push(params.message);
		return {
			action: "accept",
			content: { text: params.requestedSchema.properties.text.default },
		};
	});
	const [a, b] = InMemoryTransport.createLinkedPair();
	await server.connect(b);
	await claude.connect(a);

	const p: Person = {
		home,
		daemon,
		pairing,
		link,
		claude,
		pushed,
		forms,
		address: `127.0.0.1:${transport.port}`,
	};
	people.push(p);
	return p;
}

async function waitFor<T>(check: () => T | undefined, ms = 8000): Promise<T> {
	const start = Date.now();
	for (;;) {
		const value = check();
		if (value !== undefined) return value;
		if (Date.now() - start > ms) throw new Error("timed out waiting");
		await new Promise((r) => setTimeout(r, 25));
	}
}

function textOf(result: Awaited<ReturnType<Client["callTool"]>>): string {
	return (result.content as Array<{ text: string }>)
		.map((c) => c.text)
		.join("");
}

describe("end to end on one machine", () => {
	it("pairs, sends from Claude with confirmation, pushes with the recipient's policy, and carries the reply back", async () => {
		const alice = await person("alice", "alice-project");
		const bob = await person("bob", "bob-project");

		// 1. Pairing: Bob waits, Alice connects, both confirm the same code.
		const bobOffer = bob.pairing.accept();
		await new Promise((r) => setTimeout(r, 20));
		const aliceOffer = await alice.pairing.initiate(bob.address);
		expect(aliceOffer.code).toBe((await bobOffer).code);
		await Promise.all([
			alice.pairing.confirm(aliceOffer.pairing_id, true),
			bob.pairing.confirm((await bobOffer).pairing_id, true),
		]);

		// Bob lets his Claude answer Alice directly.
		bob.daemon.store.updateContact(alice.daemon.identity.id, {
			inboundPolicy: "auto_answer",
		});

		// 2. Alice's Claude sends a question; Alice confirms it in the form.
		const sent = await alice.claude.callTool({
			name: "send",
			arguments: {
				to: "bob",
				text: "Is the staging build green?",
				kind: "question",
			},
		});
		expect(textOf(sent)).toMatch(/^Sent to bob/);
		expect(alice.forms).toHaveLength(1);
		expect(alice.forms[0]).toContain("to bob");

		// 3. It is pushed into Bob's session, with Bob's policy for Alice.
		const question = await waitFor(() => bob.pushed[0]);
		expect(question.content).toBe("Is the staging build green?");
		expect(question.meta).toMatchObject({
			sender: "alice",
			kind: "question",
			policy: "auto_answer",
		});

		// 4. Bob's Claude replies; Bob confirms it in the form.
		const replied = await bob.claude.callTool({
			name: "reply",
			arguments: { msg_id: question.meta.msg_id, text: "Yes, all green." },
		});
		expect(textOf(replied)).toMatch(/^Sent to alice/);
		expect(bob.forms[0]).toContain("reply to alice");

		// 5. The reply reaches Alice's session in the same thread, with Alice's
		//    own (default) policy for Bob.
		const answer = await waitFor(() => alice.pushed[0]);
		expect(answer.content).toBe("Yes, all green.");
		expect(answer.meta).toMatchObject({
			sender: "bob",
			kind: "answer",
			policy: "show_first",
			thread: question.meta.thread,
			in_reply_to: question.meta.msg_id,
		});
	}, 20_000);
});
