#!/usr/bin/env node
import { parseArgs } from "node:util";
import { contactCommands } from "./cli-contacts.ts";
import { squawkHome } from "./config.ts";
import { DaemonRunningError, type StatusResult } from "./daemon.ts";
import {
	DaemonControlError,
	daemonStatus,
	runDaemonForeground,
	startDaemon,
	stopDaemon,
} from "./daemon-control.ts";
import {
	fingerprint,
	IdentityExistsError,
	initIdentity,
	loadIdentity,
	NoIdentityError,
} from "./identity.ts";
import { VERSION } from "./version.ts";

/** Where a command writes its output and which environment it reads. */
export interface CliIo {
	stdout: (text: string) => void;
	stderr: (text: string) => void;
	env: NodeJS.ProcessEnv;
}

/** A subcommand. Receives the arguments after its name; returns an exit code. */
interface Command {
	summary: string;
	run: (args: string[], io: CliIo) => Promise<number>;
}

/**
 * The subcommands. To add one (send, tail, daemon, pair, ...), add an entry
 * here; `main` finds it by name and `help` lists it.
 */
const commands: Record<string, Command> = {
	...contactCommands,
	init: {
		summary: "create this machine's key pair (--name <display name>)",
		async run(args, io) {
			const { values } = parseArgs({
				args,
				options: { name: { type: "string", short: "n" } },
				strict: true,
			});
			const home = squawkHome(io.env);
			const identity = await initIdentity(home, values.name);
			io.stdout(`Created identity "${identity.name}" in ${home}\n`);
			io.stdout(`Fingerprint: ${fingerprint(identity.publicKey)}\n`);
			return 0;
		},
	},
	whoami: {
		summary: "print this machine's display name, key and fingerprint",
		async run(args, io) {
			parseArgs({ args, options: {}, strict: true });
			const identity = await loadIdentity(squawkHome(io.env));
			io.stdout(`Name:        ${identity.name}\n`);
			io.stdout(`Key:         ${identity.id}\n`);
			io.stdout(`Fingerprint: ${fingerprint(identity.publicKey)}\n`);
			return 0;
		},
	},
	daemon: {
		summary: "control the background service (start | stop | status | run)",
		async run(args, io) {
			const { positionals } = parseArgs({
				args,
				options: {},
				allowPositionals: true,
				strict: true,
			});
			const [action, ...extra] = positionals;
			const home = squawkHome(io.env);
			if (extra.length > 0) {
				io.stderr(`squawk daemon: unexpected argument "${extra[0]}"\n`);
				return 2;
			}
			switch (action) {
				case "start": {
					await loadIdentity(home);
					const result = await startDaemon(home, io.env);
					io.stdout(
						result.alreadyRunning
							? `squawkd is already running (pid ${result.pid})\n`
							: `squawkd started (pid ${result.pid})\n`,
					);
					return 0;
				}
				case "stop": {
					const stopped = await stopDaemon(home);
					io.stdout(stopped ? "squawkd stopped\n" : "squawkd is not running\n");
					return stopped ? 0 : 1;
				}
				case "status": {
					const status = await daemonStatus(home);
					if (status === undefined) {
						io.stdout("squawkd is not running\n");
						return 1;
					}
					io.stdout(formatStatus(status));
					return 0;
				}
				case "run":
					await loadIdentity(home);
					await runDaemonForeground(home);
					return 0;
				default:
					io.stderr("Usage: squawk daemon start | stop | status | run\n");
					return 2;
			}
		},
	},
};

function formatStatus(status: StatusResult): string {
	const lines = [
		`squawkd is running (pid ${status.pid})`,
		`Name:            ${status.name}`,
		`Key:             ${status.key_id}`,
		`Fingerprint:     ${status.fingerprint}`,
		`Queued inbound:  ${status.queued_inbound}`,
		`Queued outbound: ${status.queued_outbound}`,
		`Sessions:        ${status.sessions.length === 0 ? "none" : ""}`,
		...status.sessions.map(
			(s) => `  ${s.label} (last active ${s.last_active})`,
		),
	];
	return `${lines.join("\n")}\n`;
}

function usage(): string {
	const width = Math.max(...Object.keys(commands).map((name) => name.length));
	const lines = Object.entries(commands).map(
		([name, cmd]) => `  ${name.padEnd(width)}  ${cmd.summary}`,
	);
	return `Usage: squawk <command> [options]\n\nCommands:\n${lines.join("\n")}\n`;
}

/** Runs the command line `argv` (without the node and script paths). Returns the exit code. */
export async function main(
	argv: string[],
	io: CliIo = {
		stdout: (text) => process.stdout.write(text),
		stderr: (text) => process.stderr.write(text),
		env: process.env,
	},
): Promise<number> {
	const [name, ...rest] = argv;
	if (name === undefined || name === "help" || name === "--help") {
		io.stdout(usage());
		return 0;
	}
	if (name === "--version") {
		io.stdout(`${VERSION}\n`);
		return 0;
	}
	const command = commands[name];
	if (command === undefined) {
		io.stderr(`squawk: unknown command "${name}"\n\n${usage()}`);
		return 2;
	}
	try {
		return await command.run(rest, io);
	} catch (err) {
		if (
			err instanceof IdentityExistsError ||
			err instanceof NoIdentityError ||
			err instanceof DaemonRunningError ||
			err instanceof DaemonControlError
		) {
			io.stderr(`squawk: ${err.message}\n`);
			return 1;
		}
		if (
			err instanceof Error &&
			"code" in err &&
			typeof err.code === "string" &&
			err.code.startsWith("ERR_PARSE_ARGS")
		) {
			io.stderr(`squawk ${name}: ${err.message}\n`);
			return 2;
		}
		throw err;
	}
}

if (import.meta.main) {
	process.exitCode = await main(process.argv.slice(2));
}
