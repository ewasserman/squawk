/**
 * A small JSON-RPC 2.0 server and client over `node:net` (unix sockets in
 * practice). Each message is one line of JSON followed by "\n".
 *
 * Supported: requests (with an id, answered with a result or an error),
 * notifications in both directions (no id, never answered), and server code
 * pushing notifications to a connected client at any time. Batch requests
 * (a JSON array) are not supported and get an "invalid request" error.
 */
import {
	createConnection,
	createServer,
	type Server,
	type Socket,
} from "node:net";

/** Standard JSON-RPC 2.0 error codes, plus the one squawk uses for application errors. */
export const RpcErrorCode = {
	ParseError: -32700,
	InvalidRequest: -32600,
	MethodNotFound: -32601,
	InvalidParams: -32602,
	InternalError: -32603,
	/** A well-formed call the server refused, such as sending to an unknown contact. */
	ApplicationError: -32000,
} as const;

/** Longest line accepted, in bytes. A peer that sends more is disconnected. */
export const MAX_LINE_BYTES = 16 * 1024 * 1024;

/** An error carried in a JSON-RPC response. Thrown by handlers and by `RpcClient.call`. */
export class RpcError extends Error {
	readonly code: number;
	readonly data: unknown;
	constructor(code: number, message: string, data?: unknown) {
		super(message);
		this.name = "RpcError";
		this.code = code;
		this.data = data;
	}
}

type Id = string | number | null;

interface WireError {
	code: number;
	message: string;
	data?: unknown;
}

/**
 * Splits incoming data into lines and passes each parsed JSON value to
 * `onMessage`. Lines that are not JSON go to `onBadLine`.
 */
function readLines(
	socket: Socket,
	onMessage: (value: unknown) => void,
	onBadLine: () => void,
): void {
	let buffer = "";
	socket.setEncoding("utf8");
	socket.on("data", (chunk: string) => {
		buffer += chunk;
		if (buffer.length > MAX_LINE_BYTES && !buffer.includes("\n")) {
			socket.destroy(new Error("line too long"));
			return;
		}
		let newline = buffer.indexOf("\n");
		while (newline !== -1) {
			const line = buffer.slice(0, newline).trim();
			buffer = buffer.slice(newline + 1);
			if (line !== "") {
				let value: unknown;
				let parsed = true;
				try {
					value = JSON.parse(line);
				} catch {
					parsed = false;
				}
				if (parsed) onMessage(value);
				else onBadLine();
			}
			newline = buffer.indexOf("\n");
		}
	});
}

function writeLine(socket: Socket, value: unknown): boolean {
	if (socket.destroyed || !socket.writable) return false;
	socket.write(`${JSON.stringify(value)}\n`);
	return true;
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One client connected to an `RpcServer`. */
export class RpcConnection {
	/** A number unique among this server's connections. */
	readonly id: number;
	readonly socket: Socket;
	readonly #closeHandlers: Array<() => void> = [];
	#closed = false;

	constructor(id: number, socket: Socket) {
		this.id = id;
		this.socket = socket;
		socket.on("close", () => {
			this.#closed = true;
			for (const handler of this.#closeHandlers.splice(0)) handler();
		});
		socket.on("error", () => {
			// A "close" event always follows; nothing else to do here.
		});
	}

	get closed(): boolean {
		return this.#closed;
	}

	/** Sends a notification to this client. Returns false if the connection is closed. */
	notify(method: string, params?: unknown): boolean {
		if (this.#closed) return false;
		const message: Record<string, unknown> = { jsonrpc: "2.0", method };
		if (params !== undefined) message.params = params;
		return writeLine(this.socket, message);
	}

	/** Runs `handler` once when the connection closes (immediately if it already has). */
	onClose(handler: () => void): void {
		if (this.#closed) handler();
		else this.#closeHandlers.push(handler);
	}

	close(): void {
		this.socket.end();
	}

	destroy(): void {
		this.socket.destroy();
	}
}

/**
 * Handles one method. `params` is whatever the client sent (often undefined
 * or an object). Return the result, or throw an `RpcError` to send an error.
 * Any other thrown error becomes an "internal error" response with its message.
 */
export type RpcHandler = (
	params: unknown,
	connection: RpcConnection,
) => unknown | Promise<unknown>;

export interface RpcServerOptions {
	/** Called before each request or notification from a client is handled. */
	onCall?: (connection: RpcConnection, method: string) => void;
	/** Called for each new connection. */
	onConnection?: (connection: RpcConnection) => void;
}

/** A JSON-RPC 2.0 server listening on a unix socket (or any `net` path). */
export class RpcServer {
	readonly connections = new Set<RpcConnection>();
	readonly #handlers = new Map<string, RpcHandler>();
	readonly #options: RpcServerOptions;
	readonly #server: Server;
	#nextId = 1;

	constructor(options: RpcServerOptions = {}) {
		this.#options = options;
		this.#server = createServer((socket) => this.#accept(socket));
	}

	/** Registers the handler for `method`, replacing any earlier one. */
	handle(method: string, handler: RpcHandler): this {
		this.#handlers.set(method, handler);
		return this;
	}

	/** Starts listening on `path`. Rejects if the path is in use. */
	listen(path: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const onError = (err: Error) => reject(err);
			this.#server.once("error", onError);
			this.#server.listen(path, () => {
				this.#server.off("error", onError);
				resolve();
			});
		});
	}

	/** Stops accepting connections and drops every open connection. */
	close(): Promise<void> {
		return new Promise((resolve) => {
			for (const connection of this.connections) connection.destroy();
			if (!this.#server.listening) {
				resolve();
				return;
			}
			this.#server.close(() => resolve());
		});
	}

	#accept(socket: Socket): void {
		const connection = new RpcConnection(this.#nextId++, socket);
		this.connections.add(connection);
		connection.onClose(() => this.connections.delete(connection));
		this.#options.onConnection?.(connection);
		readLines(
			socket,
			(value) => {
				void this.#dispatch(connection, value);
			},
			() => {
				writeLine(socket, {
					jsonrpc: "2.0",
					id: null,
					error: { code: RpcErrorCode.ParseError, message: "parse error" },
				});
			},
		);
	}

	async #dispatch(connection: RpcConnection, message: unknown): Promise<void> {
		const reply = (id: Id, body: { result: unknown } | { error: WireError }) =>
			writeLine(connection.socket, { jsonrpc: "2.0", id, ...body });

		if (
			!isObject(message) ||
			message.jsonrpc !== "2.0" ||
			typeof message.method !== "string"
		) {
			const id =
				isObject(message) &&
				(typeof message.id === "string" || typeof message.id === "number")
					? message.id
					: null;
			reply(id, {
				error: {
					code: RpcErrorCode.InvalidRequest,
					message: "invalid request",
				},
			});
			return;
		}
		const hasId = "id" in message;
		const id = (message.id ?? null) as Id;
		const method = message.method;
		const handler = this.#handlers.get(method);
		if (handler === undefined) {
			if (hasId) {
				reply(id, {
					error: {
						code: RpcErrorCode.MethodNotFound,
						message: `unknown method "${method}"`,
					},
				});
			}
			return;
		}
		try {
			this.#options.onCall?.(connection, method);
			const result = await handler(message.params, connection);
			if (hasId) reply(id, { result: result ?? null });
		} catch (err) {
			if (!hasId) return;
			const error: WireError =
				err instanceof RpcError
					? { code: err.code, message: err.message }
					: {
							code: RpcErrorCode.InternalError,
							message: err instanceof Error ? err.message : String(err),
						};
			if (err instanceof RpcError && err.data !== undefined) {
				error.data = err.data;
			}
			reply(id, { error });
		}
	}
}

/** Handles a notification sent by the server. */
export type NotificationHandler = (params: unknown) => void;

/** A JSON-RPC 2.0 client for an `RpcServer`. */
export class RpcClient {
	readonly socket: Socket;
	readonly #pending = new Map<
		number,
		{ resolve: (value: unknown) => void; reject: (err: Error) => void }
	>();
	readonly #notificationHandlers = new Map<string, Set<NotificationHandler>>();
	readonly #closeHandlers: Array<() => void> = [];
	#nextId = 1;
	#closed = false;

	private constructor(socket: Socket) {
		this.socket = socket;
		readLines(
			socket,
			(value) => this.#receive(value),
			() => {
				// Ignore lines that are not JSON; the server never sends them.
			},
		);
		socket.on("error", () => {
			// A "close" event always follows.
		});
		socket.on("close", () => {
			this.#closed = true;
			const error = new Error("connection to the server closed");
			for (const { reject } of this.#pending.values()) reject(error);
			this.#pending.clear();
			for (const handler of this.#closeHandlers.splice(0)) handler();
		});
	}

	/** Connects to the server listening on `path`. Rejects if nothing is listening. */
	static connect(path: string): Promise<RpcClient> {
		return new Promise((resolve, reject) => {
			const socket = createConnection(path);
			const onError = (err: Error) => reject(err);
			socket.once("error", onError);
			socket.once("connect", () => {
				socket.off("error", onError);
				resolve(new RpcClient(socket));
			});
		});
	}

	get closed(): boolean {
		return this.#closed;
	}

	/** Calls `method` and resolves with its result, or rejects with an `RpcError`. */
	call<T = unknown>(method: string, params?: unknown): Promise<T> {
		if (this.#closed) {
			return Promise.reject(new Error("connection to the server closed"));
		}
		const id = this.#nextId++;
		const message: Record<string, unknown> = { jsonrpc: "2.0", id, method };
		if (params !== undefined) message.params = params;
		return new Promise<T>((resolve, reject) => {
			this.#pending.set(id, {
				resolve: resolve as (value: unknown) => void,
				reject,
			});
			writeLine(this.socket, message);
		});
	}

	/** Sends a notification (no response expected). */
	notify(method: string, params?: unknown): void {
		const message: Record<string, unknown> = { jsonrpc: "2.0", method };
		if (params !== undefined) message.params = params;
		writeLine(this.socket, message);
	}

	/** Runs `handler` for each server notification named `method`. Returns a function that stops it. */
	onNotification(method: string, handler: NotificationHandler): () => void {
		let handlers = this.#notificationHandlers.get(method);
		if (handlers === undefined) {
			handlers = new Set();
			this.#notificationHandlers.set(method, handlers);
		}
		handlers.add(handler);
		return () => handlers.delete(handler);
	}

	/** Runs `handler` once when the connection closes (immediately if it already has). */
	onClose(handler: () => void): void {
		if (this.#closed) handler();
		else this.#closeHandlers.push(handler);
	}

	/** Closes the connection and waits until it is closed. */
	close(): Promise<void> {
		return new Promise((resolve) => {
			this.onClose(resolve);
			this.socket.end();
		});
	}

	#receive(message: unknown): void {
		if (!isObject(message)) return;
		if (typeof message.method === "string" && !("id" in message)) {
			for (const handler of this.#notificationHandlers.get(message.method) ??
				[]) {
				handler(message.params);
			}
			return;
		}
		if (typeof message.id !== "number") return;
		const pending = this.#pending.get(message.id);
		if (pending === undefined) return;
		this.#pending.delete(message.id);
		if (isObject(message.error)) {
			const { code, message: text, data } = message.error;
			pending.reject(
				new RpcError(
					typeof code === "number" ? code : RpcErrorCode.InternalError,
					typeof text === "string" ? text : "unknown error",
					data,
				),
			);
		} else {
			pending.resolve(message.result);
		}
	}
}
