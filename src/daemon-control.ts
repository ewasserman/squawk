/**
 * Starting, stopping and querying the background service from the CLI.
 */
import { spawn } from "node:child_process";
import { closeSync, mkdirSync, openSync, readFileSync, rmSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { logPath, pidPath, runDir, socketPath } from "./config.ts";
import type { StatusResult } from "./daemon.ts";
import { runDaemon } from "./daemon-main.ts";
import { RpcClient } from "./rpc.ts";

/** Thrown when the service could not be started or stopped. */
export class DaemonControlError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "DaemonControlError";
	}
}

// In development Node runs the .ts sources directly; an installed copy runs the
// compiled .js files. Use whichever extension this file has.
const OWN_EXTENSION = import.meta.url.endsWith(".ts") ? ".ts" : ".js";
const DAEMON_MAIN = fileURLToPath(
	new URL(`./daemon-main${OWN_EXTENSION}`, import.meta.url),
);

/** Connects to the running service, or resolves undefined if none answers. */
export async function connectToDaemon(
	home: string,
): Promise<RpcClient | undefined> {
	try {
		return await RpcClient.connect(socketPath(home));
	} catch {
		return undefined;
	}
}

/** The running service's status, or undefined if it is not running. */
export async function daemonStatus(
	home: string,
): Promise<StatusResult | undefined> {
	const client = await connectToDaemon(home);
	if (client === undefined) return undefined;
	try {
		return await client.call<StatusResult>("status");
	} catch {
		return undefined;
	} finally {
		await client.close();
	}
}

/**
 * Starts the service as a detached process (output to run/squawkd.log) and
 * waits until it answers `status`. Does nothing if it is already running.
 */
export async function startDaemon(
	home: string,
	env: NodeJS.ProcessEnv = process.env,
	timeoutMs = 5_000,
): Promise<{ pid: number; alreadyRunning: boolean }> {
	const existing = await daemonStatus(home);
	if (existing !== undefined) {
		return { pid: existing.pid, alreadyRunning: true };
	}
	const run = runDir(home);
	mkdirSync(run, { recursive: true, mode: 0o700 });
	const log = openSync(logPath(home), "a", 0o600);
	let exited: string | undefined;
	try {
		const child = spawn(process.execPath, [DAEMON_MAIN], {
			detached: true,
			stdio: ["ignore", log, log],
			env: { ...env, SQUAWK_HOME: home },
		});
		child.once("exit", (code, signal) => {
			exited = signal ?? `exit code ${code}`;
		});
		child.unref();
	} finally {
		closeSync(log);
	}
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const status = await daemonStatus(home);
		if (status !== undefined) return { pid: status.pid, alreadyRunning: false };
		if (exited !== undefined) {
			throw new DaemonControlError(
				`squawkd exited during startup (${exited}); see ${logPath(home)}`,
			);
		}
		await delay(100);
	}
	throw new DaemonControlError(
		`squawkd did not answer within ${timeoutMs / 1000}s; see ${logPath(home)}`,
	);
}

function readPid(home: string): number | undefined {
	try {
		const pid = Number.parseInt(readFileSync(pidPath(home), "utf8"), 10);
		return Number.isInteger(pid) && pid > 0 ? pid : undefined;
	} catch {
		return undefined;
	}
}

function isAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

/**
 * Asks the service to stop over the socket. If it answers on the socket but
 * the stop call fails, sends SIGTERM to the pid in the pid file. Waits up to
 * `timeoutMs` for it to exit. Resolves false if it was not running (and then
 * removes any pid file left behind, without signalling that pid).
 */
export async function stopDaemon(
	home: string,
	timeoutMs = 5_000,
): Promise<boolean> {
	const pid = readPid(home);
	const client = await connectToDaemon(home);
	let asked = false;
	if (client !== undefined) {
		try {
			await client.call("stop");
			asked = true;
		} catch {
			// Fall back to the signal below.
		} finally {
			await client.close();
		}
	}
	if (client === undefined) {
		// No service answers on the socket, so a pid file is left over from
		// one that died. Its pid may now belong to an unrelated process, so
		// remove the file rather than send a signal.
		rmSync(pidPath(home), { force: true });
		return false;
	}
	if (pid === undefined || !isAlive(pid)) {
		return asked;
	}
	if (!asked) process.kill(pid, "SIGTERM");
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (!isAlive(pid)) return true;
		await delay(50);
	}
	throw new DaemonControlError(
		`squawkd (pid ${pid}) did not exit within ${timeoutMs / 1000}s`,
	);
}

/** Runs the service in this process (for debugging) until it stops. */
export function runDaemonForeground(home: string): Promise<void> {
	return runDaemon(home);
}
