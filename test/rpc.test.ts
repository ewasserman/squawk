import { mkdtempSync, rmSync } from "node:fs";
import { createConnection } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	RpcClient,
	type RpcConnection,
	RpcError,
	RpcErrorCode,
	RpcServer,
} from "../src/rpc.ts";

let dir: string;
let path: string;
let server: RpcServer;
const clients: RpcClient[] = [];

beforeEach(async () => {
	// Unix socket paths are limited to about 104 bytes on macOS, so keep it short.
	dir = mkdtempSync("/tmp/sq-");
	path = join(dir, "s.sock");
	server = new RpcServer();
	await server.listen(path);
});

afterEach(async () => {
	for (const client of clients.splice(0)) await client.close();
	await server.close();
	rmSync(dir, { recursive: true, force: true });
});

async function connect(): Promise<RpcClient> {
	const client = await RpcClient.connect(path);
	clients.push(client);
	return client;
}

/** Sends raw text and resolves with the first line the server writes back. */
function rawExchange(text: string): Promise<unknown> {
	return new Promise((resolve, reject) => {
		const socket = createConnection(path);
		let buffer = "";
		socket.setEncoding("utf8");
		socket.on("error", reject);
		socket.on("data", (chunk: string) => {
			buffer += chunk;
			const newline = buffer.indexOf("\n");
			if (newline !== -1) {
				resolve(JSON.parse(buffer.slice(0, newline)));
				socket.destroy();
			}
		});
		socket.write(text);
	});
}

describe("RpcServer and RpcClient", () => {
	it("answers requests with results, including from async handlers", async () => {
		server.handle("add", (params) => {
			const { a, b } = params as { a: number; b: number };
			return a + b;
		});
		server.handle("later", async () => {
			await new Promise((r) => setTimeout(r, 10));
			return { done: true };
		});
		const client = await connect();
		const [sum, later] = await Promise.all([
			client.call<number>("add", { a: 2, b: 3 }),
			client.call("later"),
		]);
		expect(sum).toBe(5);
		expect(later).toEqual({ done: true });
	});

	it("returns errors thrown by handlers with their code and message", async () => {
		server.handle("fail", () => {
			throw new RpcError(RpcErrorCode.ApplicationError, "nope", { why: 1 });
		});
		server.handle("crash", () => {
			throw new Error("boom");
		});
		const client = await connect();
		await expect(client.call("fail")).rejects.toMatchObject({
			name: "RpcError",
			code: RpcErrorCode.ApplicationError,
			message: "nope",
			data: { why: 1 },
		});
		await expect(client.call("crash")).rejects.toMatchObject({
			code: RpcErrorCode.InternalError,
			message: "boom",
		});
		await expect(client.call("missing")).rejects.toMatchObject({
			code: RpcErrorCode.MethodNotFound,
		});
	});

	it("pushes notifications from the server to a client", async () => {
		let connection: RpcConnection | undefined;
		server.handle("hello", (_params, conn) => {
			connection = conn;
			return "hi";
		});
		const client = await connect();
		const received: unknown[] = [];
		client.onNotification("tick", (params) => received.push(params));
		await client.call("hello");
		connection?.notify("tick", { n: 1 });
		connection?.notify("tick", { n: 2 });
		await expect.poll(() => received).toEqual([{ n: 1 }, { n: 2 }]);
	});

	it("handles client notifications without replying", async () => {
		const seen: unknown[] = [];
		server.handle("note", (params) => {
			seen.push(params);
		});
		server.handle("ping", () => "pong");
		const client = await connect();
		client.notify("note", { x: 1 });
		expect(await client.call("ping")).toBe("pong");
		expect(seen).toEqual([{ x: 1 }]);
	});

	it("reports parse errors and invalid requests", async () => {
		expect(await rawExchange("not json\n")).toMatchObject({
			jsonrpc: "2.0",
			id: null,
			error: { code: RpcErrorCode.ParseError },
		});
		expect(await rawExchange('{"id":4,"method":"x"}\n')).toMatchObject({
			id: 4,
			error: { code: RpcErrorCode.InvalidRequest },
		});
	});

	it("handles a message split across writes and several in one write", async () => {
		server.handle("echo", (params) => params);
		const reply = await rawExchange(
			'{"jsonrpc":"2.0","id":1,"method":"echo","params":"a"}\n',
		);
		expect(reply).toEqual({ jsonrpc: "2.0", id: 1, result: "a" });

		const lines = await new Promise<string[]>((resolve) => {
			const socket = createConnection(path);
			let buffer = "";
			socket.setEncoding("utf8");
			socket.on("data", (chunk: string) => {
				buffer += chunk;
				const got = buffer.split("\n").filter((l) => l !== "");
				if (got.length === 2) {
					resolve(got);
					socket.destroy();
				}
			});
			socket.write('{"jsonrpc":"2.0","id":1,"me');
			setTimeout(() => {
				socket.write(
					'thod":"echo","params":1}\n{"jsonrpc":"2.0","id":2,"method":"echo","params":2}\n',
				);
			}, 10);
		});
		expect(lines.map((l) => JSON.parse(l).result).sort()).toEqual([1, 2]);
	});

	it("tells both sides when the connection closes and rejects pending calls", async () => {
		let serverSide: RpcConnection | undefined;
		server.handle("hang", (_params, conn) => {
			serverSide = conn;
			return new Promise(() => {});
		});
		const client = await connect();
		const pending = client.call("hang");
		await expect.poll(() => serverSide).toBeDefined();
		const serverClosed = new Promise<void>((resolve) =>
			serverSide?.onClose(resolve),
		);
		serverSide?.destroy();
		await expect(pending).rejects.toThrow(/closed/);
		await serverClosed;
		expect(client.closed).toBe(true);
		expect(serverSide?.notify("x")).toBe(false);
	});

	it("rejects connecting when nothing is listening", async () => {
		await expect(RpcClient.connect(join(dir, "none.sock"))).rejects.toThrow();
	});
});
