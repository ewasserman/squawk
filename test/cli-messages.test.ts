import { type ChildProcess, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli.ts";
import {
	MESSAGE_NOTE,
	type MessagesIo,
	NOT_RUNNING_MESSAGE,
	type TailLine,
	tail,
} from "../src/cli-messages.ts";
import { Daemon } from "../src/daemon.ts";
import { initIdentity } from "../src/identity.ts";
import { type Address, NetworkTransport } from "../src/network.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

interface Node {
	home: string;
	daemon: Daemon;
}

const homes: string[] = [];
const running: Daemon[] = [];
const children: ChildProcess[] = [];
/** key id → address, shared by the nodes in a test (stands in for mDNS). */
let book: Map<string, Address>;

afterEach(async () => {
	for (const child of children.splice(0)) child.kill("SIGKILL");
	await Promise.all(running.splice(0).map((d) => d.stop().catch(() => {})));
	for (const h of homes.splice(0)) rmSync(h, { recursive: true, force: true });
});

async function makeHome(name: string): Promise<string> {
	const home = mkdtempSync("/tmp/sq-");
	homes.push(home);
	await initIdentity(home, name);
	return home;
}

async function startNode(name: string): Promise<Node> {
	const home = await makeHome(name);
	const transport = new NetworkTransport({
		host: "127.0.0.1",
		discovery: false,
		resolve: (key) => book.get(key),
		retryIntervalMs: 50,
		// Short timeouts so a stalled first attempt is retried within the test.
		ackTimeoutMs: 2000,
		handshakeTimeoutMs: 2000,
	});
	const daemon = new Daemon({ home, transport });
	await daemon.start();
	running.push(daemon);
	book.set(daemon.identity.id, { host: "127.0.0.1", port: transport.port });
	return { home, daemon };
}

async function pairedNodes(): Promise<{ alice: Node; bob: Node }> {
	book = new Map();
	const alice = await startNode("alice");
	const bob = await startNode("bob");
	alice.daemon.store.upsertContact({
		publicKey: bob.daemon.identity.id,
		name: "bob",
		trust: "paired",
	});
	bob.daemon.store.upsertContact({
		publicKey: alice.daemon.identity.id,
		name: "alice",
		trust: "paired",
	});
	return { alice, bob };
}

/** An in-process io that collects output. */
function capture(
	home: string,
	extra: Partial<MessagesIo> = {},
): MessagesIo & { out: string[]; err: string[] } {
	const out: string[] = [];
	const err: string[] = [];
	return {
		stdout: (text) => out.push(text),
		stderr: (text) => err.push(text),
		env: { SQUAWK_HOME: home },
		out,
		err,
		...extra,
	};
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

/** Sends with the CLI from `from`'s home and returns the new message id. */
async function cliSend(from: Node, ...args: string[]): Promise<string> {
	const io = capture(from.home);
	const code = await main(["send", ...args], io);
	expect(io.err.join("")).toBe("");
	expect(code).toBe(0);
	const match = /^(\S+) queued \(thread \S+\)\n$/.exec(io.out.join(""));
	expect(match).not.toBeNull();
	return match?.[1] as string;
}

function parseLines(chunks: string[]): TailLine[] {
	return chunks
		.join("")
		.split("\n")
		.filter((l) => l !== "")
		.map((l) => JSON.parse(l) as TailLine);
}

describe("squawk send and tail", () => {
	it("prints a message sent with the CLI as one JSON line in the other service's tail", async () => {
		const { alice, bob } = await pairedNodes();
		const controller = new AbortController();
		const out: string[] = [];
		let ready: () => void = () => {};
		const isReady = new Promise<void>((r) => {
			ready = r;
		});
		const tailing = tail(bob.home, {
			write: (t) => out.push(t),
			stderr: (t) => out.push(`ERR ${t}`),
			signal: controller.signal,
			onReady: ready,
		});
		await isReady;

		const id = await cliSend(
			alice,
			"bob",
			"hi bob",
			"--kind",
			"question",
			"--session",
			"review",
			"--thread",
			"t-1",
		);
		const [line] = await waitFor(() => out.length > 0 && parseLines(out));
		controller.abort();
		expect(await tailing).toBe(0);

		expect(out).toHaveLength(1);
		expect(out[0]?.endsWith("\n")).toBe(true);
		expect(line).toEqual({
			type: "squawk_message",
			note: MESSAGE_NOTE,
			msg_id: id,
			from: alice.daemon.identity.id,
			from_name: "alice",
			thread_id: "t-1",
			in_reply_to: null,
			kind: "question",
			policy: "show_first",
			session: "review",
			created_at: expect.any(String),
			body: "hi bob",
		});
	});

	it("prints only new messages by default, and leaves messages unread", async () => {
		const { alice, bob } = await pairedNodes();
		const old = await cliSend(alice, "bob", "old news");
		await waitFor(() => bob.daemon.store.getMessage(old));

		const controller = new AbortController();
		const io = capture(bob.home);
		let ready: () => void = () => {};
		const isReady = new Promise<void>((r) => {
			ready = r;
		});
		const tailing = tail(bob.home, {
			write: io.stdout,
			stderr: io.stderr,
			signal: controller.signal,
			onReady: ready,
		});
		await isReady;

		const fresh = await cliSend(alice, "bob", "new news", "--reply-to", old);
		const lines = await waitFor(() => io.out.length > 0 && parseLines(io.out));
		controller.abort();
		expect(await tailing).toBe(0);
		expect(lines.map((l) => l.msg_id)).toEqual([fresh]);
		expect(lines[0]?.in_reply_to).toBe(old);
		expect(bob.daemon.store.inbox().map((m) => m.id)).toEqual([old, fresh]);
	});

	it("--unread prints unread messages first, without marking them read", async () => {
		const { alice, bob } = await pairedNodes();
		const first = await cliSend(alice, "bob", "one");
		const second = await cliSend(alice, "bob", "two");
		await waitFor(() => bob.daemon.store.inbox().length === 2);

		const controller = new AbortController();
		const io = capture(bob.home, { signal: controller.signal });
		const tailing = main(["tail", "--unread"], io);
		const lines = await waitFor(
			() => parseLines(io.out).length === 2 && parseLines(io.out),
		);
		controller.abort();
		expect(await tailing).toBe(0);
		expect(lines.map((l) => [l.msg_id, l.body])).toEqual([
			[first, "one"],
			[second, "two"],
		]);
		expect(bob.daemon.store.inbox()).toHaveLength(2);
	});

	it("--reply-to joins the thread of the message being answered", async () => {
		const { alice, bob } = await pairedNodes();
		const question = await cliSend(alice, "bob", "staging green?");
		await waitFor(() => bob.daemon.store.getMessage(question));
		const reply = await cliSend(bob, "alice", "yes", "--reply-to", question);
		const stored = bob.daemon.store.getMessage(reply);
		expect(stored?.threadId).toBe(
			bob.daemon.store.getMessage(question)?.threadId,
		);
		expect(stored?.inReplyTo).toBe(question);
	});

	it("--pretty on its own also shows messages that were already waiting", async () => {
		const { alice, bob } = await pairedNodes();
		const id = await cliSend(alice, "bob", "sent before tail started");
		await waitFor(() => bob.daemon.store.getMessage(id));
		const controller = new AbortController();
		const io = capture(bob.home, { signal: controller.signal });
		const tailing = main(["tail", "--pretty"], io);
		await waitFor(() => io.out.length > 0);
		controller.abort();
		expect(await tailing).toBe(0);
		expect(io.out.join("")).toContain("\nsent before tail started\n");
	});

	it("--pretty prints a block for people", async () => {
		const { alice, bob } = await pairedNodes();
		const id = await cliSend(alice, "bob", "pretty please");
		await waitFor(() => bob.daemon.store.getMessage(id));
		const controller = new AbortController();
		const io = capture(bob.home, { signal: controller.signal });
		const tailing = main(["tail", "--unread", "--pretty"], io);
		await waitFor(() => io.out.length > 0);
		controller.abort();
		expect(await tailing).toBe(0);
		const text = io.out.join("");
		expect(text).toContain(`From:     alice (${alice.daemon.identity.id})`);
		expect(text).toContain(`Message:  ${id}`);
		expect(text).toContain("\npretty please\n");
	});

	it("exits with code 1 when the service connection closes", async () => {
		const { bob } = await pairedNodes();
		const io = capture(bob.home);
		let ready: () => void = () => {};
		const isReady = new Promise<void>((r) => {
			ready = r;
		});
		const tailing = tail(bob.home, {
			write: io.stdout,
			stderr: io.stderr,
			onReady: ready,
		});
		await isReady;
		await bob.daemon.stop();
		expect(await tailing).toBe(1);
		expect(io.err.join("")).toContain(
			"connection to the squawk service closed",
		);
	});

	it("runs as a real process: prints JSON lines to stdout and stops cleanly on SIGTERM", async () => {
		const { alice, bob } = await pairedNodes();
		const before = await cliSend(alice, "bob", "waiting for you");
		await waitFor(() => bob.daemon.store.getMessage(before));

		const child = spawn(process.execPath, [CLI, "tail", "--unread"], {
			env: { ...process.env, SQUAWK_HOME: bob.home },
			stdio: ["ignore", "pipe", "pipe"],
		});
		children.push(child);
		const out: string[] = [];
		let stderr = "";
		child.stdout.setEncoding("utf8").on("data", (t: string) => out.push(t));
		child.stderr.setEncoding("utf8").on("data", (t: string) => {
			stderr += t;
		});
		const exited = new Promise<number | null>((resolve) =>
			child.once("exit", (code) => resolve(code)),
		);

		// The unread message is printed only after the subscription is active,
		// so a message sent after it arrives as a live notification.
		await waitFor(() => parseLines(out).length === 1, 15_000);
		const live = await cliSend(alice, "bob", "are you there?");
		const lines = await waitFor(
			() => parseLines(out).length === 2 && parseLines(out),
		);
		expect(lines.map((l) => [l.msg_id, l.body])).toEqual([
			[before, "waiting for you"],
			[live, "are you there?"],
		]);
		expect(lines[1]?.type).toBe("squawk_message");

		child.kill("SIGTERM");
		expect(await exited).toBe(0);
		expect(stderr).toBe("");
	}, 20_000);
});

describe("squawk send input", () => {
	it("reads the message from stdin when no text is given, or when it is -", async () => {
		const { alice, bob } = await pairedNodes();
		const io = capture(alice.home, {
			stdin: Readable.from(["line one\n", "line two\n"]),
		});
		expect(await main(["send", "bob"], io)).toBe(0);
		const id = io.out.join("").split(" ")[0] as string;

		const dash = capture(alice.home, {
			stdin: Readable.from([Buffer.from("from a dash\n")]),
		});
		expect(await main(["send", "bob", "-"], dash)).toBe(0);
		const dashId = dash.out.join("").split(" ")[0] as string;

		expect((await waitFor(() => bob.daemon.store.getMessage(id))).body).toBe(
			"line one\nline two",
		);
		expect(
			(await waitFor(() => bob.daemon.store.getMessage(dashId))).body,
		).toBe("from a dash");
	});

	it("rejects an empty message, a bad kind and an unknown contact", async () => {
		const { alice } = await pairedNodes();
		const empty = capture(alice.home, { stdin: Readable.from(["\n"]) });
		expect(await main(["send", "bob"], empty)).toBe(2);
		expect(empty.err.join("")).toContain("empty");

		const kind = capture(alice.home);
		expect(await main(["send", "bob", "x", "--kind", "shout"], kind)).toBe(2);

		const unknown = capture(alice.home);
		expect(await main(["send", "carol", "hello"], unknown)).toBe(1);
		expect(unknown.err.join("")).toContain('unknown contact "carol"');
	});
});

describe("squawk peers and status", () => {
	it("prints the service status and peers as text and JSON", async () => {
		const { bob } = await pairedNodes();
		const json = capture(bob.home);
		expect(await main(["status", "--json"], json)).toBe(0);
		const status = JSON.parse(json.out.join(""));
		expect(status.name).toBe("bob");
		expect(status.port).toBe(book.get(bob.daemon.identity.id)?.port);

		const text = capture(bob.home);
		expect(await main(["status"], text)).toBe(0);
		expect(text.out.join("")).toContain(`Port:            ${status.port}`);

		const peers = capture(bob.home);
		expect(await main(["peers", "--json"], peers)).toBe(0);
		expect(JSON.parse(peers.out.join(""))).toEqual([]);
		const peersText = capture(bob.home);
		expect(await main(["peers"], peersText)).toBe(0);
		expect(peersText.out.join("")).toContain("No squawk services found");
	});

	it("says the service is not running, with exit code 1", async () => {
		const home = await makeHome("idle");
		for (const args of [
			["send", "bob", "hi"],
			["tail"],
			["peers"],
			["status", "--json"],
		]) {
			const io = capture(home);
			expect(await main(args, io)).toBe(1);
			expect(io.err.join("")).toBe(`squawk: ${NOT_RUNNING_MESSAGE}\n`);
		}
	});
});
