#!/usr/bin/env node
import { parseArgs } from "node:util";
import { squawkHome } from "./config.ts";
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
};

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
		if (err instanceof IdentityExistsError || err instanceof NoIdentityError) {
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
