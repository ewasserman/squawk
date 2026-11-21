#!/usr/bin/env node
/**
 * Entry point for the background service: runs a `Daemon` for the squawk
 * home directory until it receives SIGTERM or SIGINT, or a client calls `stop`.
 */
import { squawkHome } from "./config.ts";
import { Daemon } from "./daemon.ts";

/** Runs the service in this process until it stops. */
export async function runDaemon(home: string = squawkHome()): Promise<void> {
	const daemon = new Daemon({ home });
	await daemon.start();
	const shutdown = () => void daemon.stop();
	process.once("SIGTERM", shutdown);
	process.once("SIGINT", shutdown);
	console.log(
		`${new Date().toISOString()} squawkd ${process.pid} listening on ${daemon.socketPath}`,
	);
	await daemon.whenStopped();
	process.off("SIGTERM", shutdown);
	process.off("SIGINT", shutdown);
	console.log(`${new Date().toISOString()} squawkd ${process.pid} stopped`);
}

if (import.meta.main) {
	try {
		await runDaemon();
	} catch (err) {
		console.error(
			`squawkd: ${err instanceof Error ? err.message : String(err)}`,
		);
		process.exitCode = 1;
	}
}
