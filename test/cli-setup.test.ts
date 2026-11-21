import {
	chmodSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../src/cli.ts";
import { LAUNCH_COMMAND } from "../src/cli-setup.ts";
import { daemonStatus, stopDaemon } from "../src/daemon-control.ts";
import { loadIdentity } from "../src/identity.ts";

const dirs: string[] = [];
afterEach(async () => {
	for (const d of dirs.splice(0)) {
		await stopDaemon(join(d, "home")).catch(() => {});
		rmSync(d, { recursive: true, force: true });
	}
});

/** A temp dir with an empty squawk home and a fake `claude` that logs its arguments. */
function sandbox(claudeExit = 0) {
	const dir = mkdtempSync("/tmp/sq-");
	dirs.push(dir);
	const log = join(dir, "claude-calls.txt");
	const fake = join(dir, "fake-claude");
	writeFileSync(
		fake,
		`#!/bin/sh\necho "$@" >> ${log}\nexit $( [ "$2" = "add" ] && echo ${claudeExit} || echo 0 )\n`,
	);
	chmodSync(fake, 0o755);
	const env = {
		...process.env,
		SQUAWK_HOME: join(dir, "home"),
		SQUAWK_CLAUDE_BIN: fake,
		SQUAWK_NO_MDNS: "1",
	};
	return { dir, log, env };
}

async function run(env: NodeJS.ProcessEnv, ...args: string[]) {
	let out = "";
	let err = "";
	const code = await main(args, {
		stdout: (t) => {
			out += t;
		},
		stderr: (t) => {
			err += t;
		},
		env,
	});
	return { code, out, err };
}

describe("squawk setup", () => {
	it("on a clean home creates the identity, starts the service, registers squawk mcp and prints the launch command", async () => {
		const { log, env } = sandbox();
		const result = await run(env, "setup", "--name", "alice");
		expect(result.code).toBe(0);
		expect(result.out).toContain('Created your identity "alice"');
		expect(result.out).toContain(LAUNCH_COMMAND);
		expect(result.out).toContain("squawk tail");
		expect((await loadIdentity(env.SQUAWK_HOME as string)).name).toBe("alice");
		expect(await daemonStatus(env.SQUAWK_HOME as string)).toBeDefined();

		const calls = readFileSync(log, "utf8").trim().split("\n");
		expect(calls[0]).toBe("mcp remove --scope user squawk");
		expect(calls[1]).toMatch(
			new RegExp(
				`^mcp add --scope user --env SQUAWK_HOME=${env.SQUAWK_HOME} squawk -- \\S*node\\S* \\S+/cli\\.(ts|js) mcp$`,
			),
		);
	});

	it("can run again, keeping the existing identity", async () => {
		const { env } = sandbox();
		expect((await run(env, "setup", "--name", "alice")).code).toBe(0);
		const again = await run(env, "setup");
		expect(again.code).toBe(0);
		expect(again.out).toContain('Using your existing identity "alice"');
		expect(again.out).toContain("already running");
	});

	it("prints the registration command when claude fails, and skips it with --no-claude", async () => {
		const failing = sandbox(1);
		const r = await run(failing.env, "setup", "--name", "bob");
		expect(r.code).toBe(1);
		expect(r.err).toContain("mcp add --scope user");

		const skipped = sandbox();
		const s = await run(skipped.env, "setup", "--name", "carol", "--no-claude");
		expect(s.code).toBe(0);
		expect(s.out).toContain("Skipped registering");
	});
});
