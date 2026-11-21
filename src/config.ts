import { homedir } from "node:os";
import { join } from "node:path";

/**
 * The directory that holds squawk's identity, database and runtime files.
 * Uses the SQUAWK_HOME environment variable when it is set, otherwise
 * `~/.config/squawk`.
 */
export function squawkHome(env: NodeJS.ProcessEnv = process.env): string {
	const fromEnv = env.SQUAWK_HOME;
	if (fromEnv !== undefined && fromEnv !== "") {
		return fromEnv;
	}
	return join(homedir(), ".config", "squawk");
}

/** Path of the file holding this machine's key pair and display name. */
export function identityPath(home: string): string {
	return join(home, "identity.json");
}

/** Path of the SQLite database file. */
export function dbPath(home: string): string {
	return join(home, "squawk.db");
}

/** Directory for runtime files such as the background service's socket and pid file. */
export function runDir(home: string): string {
	return join(home, "run");
}

/** Path of the background service's unix socket. */
export function socketPath(home: string): string {
	return join(runDir(home), "squawkd.sock");
}

/** Path of the file holding the background service's process id. */
export function pidPath(home: string): string {
	return join(runDir(home), "squawkd.pid");
}

/** Path of the background service's log file (its stdout and stderr). */
export function logPath(home: string): string {
	return join(runDir(home), "squawkd.log");
}
