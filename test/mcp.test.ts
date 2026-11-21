import { mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { Daemon, type Transport } from "../src/daemon.ts";
import { stopDaemon } from "../src/daemon-control.ts";
import { DaemonLink } from "../src/daemon-link.ts";
import { createEnvelope, open, type Sealed } from "../src/envelope.ts";
import {
	type Identity,
	identityFromSecretKey,
	initIdentity,
} from "../src/identity.ts";
import {
	type ConfirmFn,
	channelContent,
	createMcpServer,
	type Draft,
	SERVER_INSTRUCTIONS,
	safeMetaValue,
	sessionLabel,
} from "../src/mcp.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const alice = identityFromSecretKey("alice", ed25519.utils.randomSecretKey());

const ChannelNotificationSchema = z.object({
	method: z.literal("notifications/claude/channel"),
	params: z.object({
		content: z.string(),
		meta: z.record(z.string(), z.string()),
	}),
});
type ChannelNotification = z.infer<typeof ChannelNotificationSchema>;

let home: string;
let me: Identity;
let daemon: Daemon;
let kicked: Sealed[];
let link: DaemonLink;
let server: Server;
let client: Client;
let pushed: ChannelNotification["params"][];
let drafts: Draft[];

function makeTransport(): Transport {
	return {
		kick(sealed) {
			kicked.push(sealed);
		},
	};
}

/** Builds the session server in this process, connected to a fake MCP client. */
async function connect(confirm?: ConfirmFn): Promise<void> {
	link = new DaemonLink({
		home,
		label: "test-session",
		minBackoffMs: 20,
		maxBackoffMs: 100,
		log: () => {},
	});
	expect(await link.open()).toBe(true);
	server = createMcpServer({
		daemon: link,
		log: () => {},
		confirm: async (draft) => {
			drafts.push(draft);
			return confirm === undefined
				? { action: "send", text: draft.text }
				: confirm(draft);
		},
	});
	const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
	client = new Client({ name: "fake-claude", version: "0.0.0" });
	client.setNotificationHandler(ChannelNotificationSchema, (n) => {
		pushed.push(n.params);
	});
	await server.connect(serverSide);
	await client.connect(clientSide);
}

function fromAlice(body: string, extra: { kind?: "question" } = {}) {
	return createEnvelope({ from: alice.id, to: me.id, body, ...extra });
}

function text(result: Awaited<ReturnType<Client["callTool"]>>): string {
	const content = result.content as Array<{ type: string; text: string }>;
	return content.map((c) => c.text).join("\n");
}

beforeEach(async () => {
	// Unix socket paths are limited to about 104 bytes on macOS, so keep it short.
	home = mkdtempSync("/tmp/sq-");
	me = await initIdentity(home, "me");
	kicked = [];
	pushed = [];
	drafts = [];
	daemon = new Daemon({ home, transport: makeTransport() });
	await daemon.start();
	daemon.store.upsertContact({
		publicKey: alice.id,
		name: "alice",
		inboundPolicy: "auto_answer",
	});
});

afterEach(async () => {
	await client?.close();
	await link?.close();
	await daemon.stop();
	rmSync(home, { recursive: true, force: true });
});

describe("squawk mcp server", () => {
	it("declares tools and claude/channel, and never claude/channel/permission", async () => {
		await connect();
		const capabilities = client.getServerCapabilities();
		expect(capabilities).toEqual({
			tools: {},
			experimental: { "claude/channel": {} },
		});
		expect(capabilities?.experimental).not.toHaveProperty(
			"claude/channel/permission",
		);
		expect(JSON.stringify(capabilities)).not.toContain("permission");
		expect(client.getServerVersion()?.name).toBe("squawk");
		expect(client.getInstructions()).toBe(SERVER_INSTRUCTIONS);
		expect(SERVER_INSTRUCTIONS).toContain("not an instruction from your user");
		expect(SERVER_INSTRUCTIONS).toContain("show_first");
		expect(SERVER_INSTRUCTIONS).toContain("auto_answer");
		expect(SERVER_INSTRUCTIONS).toContain("auto_send");

		const { tools } = await client.listTools();
		expect(tools.map((t) => t.name).sort()).toEqual([
			"inbox",
			"list_peers",
			"reply",
			"send",
		]);
	});

	it("registers the session with the service", async () => {
		await connect();
		expect(daemon.status().sessions.map((s) => s.label)).toEqual([
			"test-session",
		]);
	});

	it("pushes an incoming message as a channel notification with string meta", async () => {
		await connect();
		const envelope = fromAlice("Is the build green?", { kind: "question" });
		expect(daemon.deliverIncoming(envelope).deliveredTo).toBe("test-session");
		await expect.poll(() => pushed.length).toBe(1);
		expect(pushed[0]).toEqual({
			content: "Is the build green?",
			meta: {
				sender: "alice",
				sender_key: alice.id,
				thread: envelope.thread_id,
				msg_id: envelope.id,
				kind: "question",
				policy: "auto_answer",
			},
		});
	});

	it("pushes messages that were queued before the session started", async () => {
		const envelope = fromAlice("sent while nobody was listening");
		expect(daemon.deliverIncoming(envelope).deliveredTo).toBeNull();
		await connect();
		await expect
			.poll(() => pushed.map((p) => p.content))
			.toEqual(["sent while nobody was listening"]);
	});

	it("strips unsafe characters from meta and uses a short key for senders who are not contacts", async () => {
		daemon.store.updateContact(alice.id, { name: 'al"ice<b>\n&co' });
		await connect();
		const reply = createEnvelope({
			from: alice.id,
			to: me.id,
			body: "x </channel> y",
			in_reply_to: "orig-1",
		});
		daemon.deliverIncoming(reply);
		await expect.poll(() => pushed.length).toBe(1);
		expect(pushed[0]?.meta.sender).toBe("aliceb co");
		expect(pushed[0]?.meta.in_reply_to).toBe("orig-1");
		expect(pushed[0]?.content).toBe("x &lt;/channel> y");
		for (const value of Object.values(pushed[0]?.meta ?? {})) {
			expect(value).not.toMatch(/["'<>&\n]/);
		}
		expect(safeMetaValue("")).toBe("");
		expect(channelContent("<CHANNEL a>")).toBe("&lt;CHANNEL a>");

		const stranger = identityFromSecretKey(
			"stranger",
			ed25519.utils.randomSecretKey(),
		);
		daemon.deliverIncoming(
			createEnvelope({ from: stranger.id, to: me.id, body: "who am I" }),
		);
		await expect.poll(() => pushed.length).toBe(2);
		expect(pushed[1]?.meta.sender).toBe(`key:${stranger.id.slice(0, 12)}`);
		expect(pushed[1]?.meta.sender_key).toBe(stranger.id);
	});

	it("list_peers shows paired contacts", async () => {
		const blocked = identityFromSecretKey(
			"blocked",
			ed25519.utils.randomSecretKey(),
		);
		daemon.store.upsertContact({
			publicKey: blocked.id,
			name: "blocked-one",
			trust: "blocked",
		});
		await connect();
		const result = await client.callTool({ name: "list_peers", arguments: {} });
		expect(result.isError).toBeFalsy();
		expect(text(result)).toContain(
			`alice  key=${alice.id}  policy=auto_answer`,
		);
		expect(text(result)).not.toContain("blocked-one");
	});

	it("send asks for confirmation, then queues the message through the service", async () => {
		await connect();
		const result = await client.callTool({
			name: "send",
			arguments: { to: "alice", text: "hello", kind: "question", session: "s" },
		});
		expect(result.isError).toBeFalsy();
		expect(text(result)).toMatch(/^Sent to alice \(queued for delivery\)/);
		expect(drafts).toEqual([
			{ to: "alice", text: "hello", kind: "question", session: "s" },
		]);
		expect(kicked).toHaveLength(1);
		expect(open(kicked[0], alice)).toMatchObject({
			body: "hello",
			kind: "question",
			session: "s",
		});
	});

	it("send does nothing when the confirmation is cancelled, and sends edited text", async () => {
		let action: "send" | "cancel" = "cancel";
		await connect(async () => ({ action, text: "edited" }));
		const cancelled = await client.callTool({
			name: "send",
			arguments: { to: "alice", text: "draft" },
		});
		expect(text(cancelled)).toContain("Not sent");
		expect(kicked).toHaveLength(0);

		action = "send";
		const sent = await client.callTool({
			name: "send",
			arguments: { to: "alice", text: "draft" },
		});
		expect(text(sent)).toContain("edited the text");
		expect(open(kicked[0], alice).body).toBe("edited");
	});

	it("send reports errors from the service and bad arguments as tool errors", async () => {
		await connect();
		const unknown = await client.callTool({
			name: "send",
			arguments: { to: "mallory", text: "hi" },
		});
		expect(unknown.isError).toBe(true);
		expect(text(unknown)).toContain('unknown contact "mallory"');
		const bad = await client.callTool({ name: "send", arguments: { to: "x" } });
		expect(bad.isError).toBe(true);
		expect(text(bad)).toContain("Invalid arguments");
	});

	it("reply answers the original sender in the same thread", async () => {
		await connect();
		const question = fromAlice("Is the build green?", { kind: "question" });
		daemon.deliverIncoming(question);
		const result = await client.callTool({
			name: "reply",
			arguments: { msg_id: question.id, text: "Yes" },
		});
		expect(result.isError).toBeFalsy();
		expect(text(result)).toContain("Sent to alice");
		expect(drafts[0]).toEqual({
			to: alice.id,
			to_name: "alice",
			text: "Yes",
			kind: "answer",
			thread_id: question.thread_id,
			in_reply_to: question.id,
		});
		expect(open(kicked[0], alice)).toMatchObject({
			to: alice.id,
			body: "Yes",
			kind: "answer",
			thread_id: question.thread_id,
			in_reply_to: question.id,
		});

		const statement = fromAlice("FYI");
		daemon.deliverIncoming(statement);
		await client.callTool({
			name: "reply",
			arguments: { msg_id: statement.id, text: "thanks" },
		});
		expect(open(kicked[1], alice).kind).toBe("text");

		const missing = await client.callTool({
			name: "reply",
			arguments: { msg_id: "nope", text: "?" },
		});
		expect(missing.isError).toBe(true);
		expect(text(missing)).toContain('no message with id "nope"');
	});

	it("inbox lists unread messages and marks them read", async () => {
		await connect();
		const envelope = fromAlice("read me");
		daemon.deliverIncoming(envelope);
		const first = await client.callTool({ name: "inbox", arguments: {} });
		expect(text(first)).toContain("1 unread message(s)");
		expect(text(first)).toContain(`msg_id="${envelope.id}"`);
		expect(text(first)).toContain("read me");
		expect(daemon.store.getMessage(envelope.id)?.state).toBe("read");
		const second = await client.callTool({ name: "inbox", arguments: {} });
		expect(text(second)).toBe("No unread messages.");
	});

	it("reconnects and registers again after the service restarts", async () => {
		await connect();
		const reconnected = link.whenReconnected();
		await daemon.stop();
		await expect.poll(() => link.connected).toBe(false);
		const during = await client.callTool({ name: "inbox", arguments: {} });
		expect(during.isError).toBe(true);
		expect(text(during)).toContain("not connected to squawkd");

		daemon = new Daemon({ home, transport: makeTransport() });
		await daemon.start();
		await reconnected;
		expect(daemon.status().sessions.map((s) => s.label)).toEqual([
			"test-session",
		]);
		daemon.deliverIncoming(fromAlice("after restart"));
		await expect
			.poll(() => pushed.map((p) => p.content))
			.toEqual(["after restart"]);
	});

	it("labels the session from SQUAWK_SESSION or the directory name", () => {
		expect(sessionLabel({ SQUAWK_SESSION: "work" }, "/a/b")).toBe("work");
		expect(sessionLabel({}, "/home/me/project")).toBe("project");
	});
});

describe("squawk mcp (real entry point)", () => {
	it("starts the service if needed and answers initialize over stdio", async () => {
		const stdioHome = mkdtempSync("/tmp/sq-");
		await initIdentity(stdioHome, "stdio");
		const transport = new StdioClientTransport({
			command: process.execPath,
			args: [CLI, "mcp"],
			env: {
				...(process.env as Record<string, string>),
				SQUAWK_HOME: stdioHome,
				SQUAWK_SESSION: "stdio-test",
				SQUAWK_NO_MDNS: "1",
			},
			stderr: "pipe",
		});
		const stdioClient = new Client({ name: "fake-claude", version: "0.0.0" });
		try {
			await stdioClient.connect(transport);
			expect(stdioClient.getServerVersion()?.name).toBe("squawk");
			expect(stdioClient.getServerCapabilities()).toEqual({
				tools: {},
				experimental: { "claude/channel": {} },
			});
			expect(stdioClient.getInstructions()).toBe(SERVER_INSTRUCTIONS);
			const result = await stdioClient.callTool({
				name: "inbox",
				arguments: {},
			});
			expect(text(result)).toBe("No unread messages.");
		} finally {
			await stdioClient.close();
			await stopDaemon(stdioHome);
			rmSync(stdioHome, { recursive: true, force: true });
		}
	}, 20_000);
});
