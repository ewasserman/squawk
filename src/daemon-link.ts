/**
 * A session's connection to the local background service (squawkd).
 *
 * `DaemonLink` connects to the service's socket, registers a session with a
 * label, and passes on the `message` notifications the service pushes to
 * that session. If the connection drops (for example because the service
 * was restarted), it reconnects with exponential backoff and registers the
 * session again. While it is disconnected, `call` fails with
 * `DaemonUnavailableError`.
 */
import type { MessageNotification } from "./daemon.ts";
import { connectToDaemon } from "./daemon-control.ts";
import type { RpcClient } from "./rpc.ts";

/** What the session server needs from the service. Tests can supply their own. */
export interface DaemonApi {
	/** Calls a service method and resolves with its result. */
	call<T = unknown>(method: string, params?: unknown): Promise<T>;
	/** Runs `handler` for each incoming message the service pushes to this session. */
	onMessage(handler: (message: MessageNotification) => void): void;
}

/** Thrown by `DaemonLink.call` while there is no connection to the service. */
export class DaemonUnavailableError extends Error {
	constructor() {
		super(
			"not connected to squawkd (the squawk background service); retrying. If it keeps failing, run `squawk daemon start`.",
		);
		this.name = "DaemonUnavailableError";
	}
}

export interface DaemonLinkOptions {
	/** The squawk home directory. */
	home: string;
	/** The session label passed to `register_session`. */
	label: string;
	/** First reconnect delay in milliseconds (default 250). Doubles each failure. */
	minBackoffMs?: number;
	/** Longest reconnect delay in milliseconds (default 10 000). */
	maxBackoffMs?: number;
	/** Where to report connection problems (default: standard error). */
	log?: (text: string) => void;
	/** Opens a connection; defaults to `connectToDaemon(home)`. */
	connect?: () => Promise<RpcClient | undefined>;
}

export class DaemonLink implements DaemonApi {
	readonly home: string;
	readonly label: string;
	readonly #minBackoffMs: number;
	readonly #maxBackoffMs: number;
	readonly #log: (text: string) => void;
	readonly #connect: () => Promise<RpcClient | undefined>;
	readonly #handlers = new Set<(message: MessageNotification) => void>();
	readonly #early: MessageNotification[] = [];
	#client: RpcClient | undefined;
	#closed = false;
	#retryTimer: NodeJS.Timeout | undefined;
	#backoffMs: number;
	#resolveReconnected: Array<() => void> = [];

	constructor(options: DaemonLinkOptions) {
		this.home = options.home;
		this.label = options.label;
		this.#minBackoffMs = options.minBackoffMs ?? 250;
		this.#maxBackoffMs = options.maxBackoffMs ?? 10_000;
		this.#backoffMs = this.#minBackoffMs;
		this.#log =
			options.log ?? ((text) => process.stderr.write(`squawk mcp: ${text}\n`));
		this.#connect = options.connect ?? (() => connectToDaemon(this.home));
	}

	/** True while connected and registered. */
	get connected(): boolean {
		return this.#client !== undefined && !this.#client.closed;
	}

	/**
	 * Connects and registers the session. Resolves false (without retrying)
	 * if the service is not answering, so the caller can start it and try again.
	 */
	async open(): Promise<boolean> {
		return this.#attempt();
	}

	call<T = unknown>(method: string, params?: unknown): Promise<T> {
		const client = this.#client;
		if (client === undefined || client.closed) {
			return Promise.reject(new DaemonUnavailableError());
		}
		return client.call<T>(method, params);
	}

	/**
	 * Messages that arrive before any handler is added (the service pushes
	 * queued messages right after registration) are kept and passed to the
	 * first handler.
	 */
	onMessage(handler: (message: MessageNotification) => void): void {
		this.#handlers.add(handler);
		for (const message of this.#early.splice(0)) handler(message);
	}

	/** Resolves the next time the link connects and registers again. */
	whenReconnected(): Promise<void> {
		return new Promise((resolve) => this.#resolveReconnected.push(resolve));
	}

	/** Closes the connection and stops reconnecting. */
	async close(): Promise<void> {
		this.#closed = true;
		clearTimeout(this.#retryTimer);
		const client = this.#client;
		this.#client = undefined;
		if (client !== undefined && !client.closed) await client.close();
	}

	async #attempt(): Promise<boolean> {
		const client = await this.#connect();
		if (client === undefined) return false;
		if (this.#closed) {
			await client.close();
			return false;
		}
		client.onNotification("message", (params) => {
			const message = params as MessageNotification;
			if (this.#handlers.size === 0) this.#early.push(message);
			for (const handler of this.#handlers) handler(message);
		});
		try {
			await client.call("register_session", { label: this.label });
		} catch (err) {
			this.#log(
				`could not register session: ${err instanceof Error ? err.message : String(err)}`,
			);
			if (!client.closed) await client.close();
			return false;
		}
		this.#client = client;
		this.#backoffMs = this.#minBackoffMs;
		client.onClose(() => {
			if (this.#client === client) this.#client = undefined;
			if (this.#closed) return;
			this.#log("lost the connection to squawkd; reconnecting");
			this.#scheduleRetry();
		});
		return true;
	}

	#scheduleRetry(): void {
		if (this.#closed) return;
		const delay = this.#backoffMs;
		this.#backoffMs = Math.min(this.#backoffMs * 2, this.#maxBackoffMs);
		this.#retryTimer = setTimeout(() => {
			this.#attempt().then(
				(ok) => {
					if (ok) {
						this.#log("reconnected to squawkd");
						for (const resolve of this.#resolveReconnected.splice(0)) resolve();
					} else {
						this.#scheduleRetry();
					}
				},
				() => this.#scheduleRetry(),
			);
		}, delay);
		this.#retryTimer.unref();
	}
}
