import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

let home: string;

function squawk(
	...args: string[]
): Promise<{ code: number; stdout: string; stderr: string }> {
	return new Promise((resolve) => {
		execFile(
			process.execPath,
			[CLI, ...args],
			{ env: { ...process.env, SQUAWK_HOME: home }, timeout: 15_000 },
			(error, stdout, stderr) => {
				const code =
					error === null ? 0 : typeof error.code === "number" ? error.code : 1;
				resolve({ code, stdout, stderr });
			},
		);
	});
}

beforeAll(() => {
	home = mkdtempSync("/tmp/sq-");
});

afterAll(async () => {
	await squawk("daemon", "stop");
	rmSync(home, { recursive: true, force: true });
});

describe("squawk daemon (end to end)", () => {
	it("starts, reports status and stops the background service", async () => {
		expect((await squawk("init", "--name", "cli-test")).code).toBe(0);

		const before = await squawk("daemon", "status");
		expect(before.code).toBe(1);
		expect(before.stdout).toContain("not running");

		const start = await squawk("daemon", "start");
		expect(start.stderr).toBe("");
		expect(start.code).toBe(0);
		const pid = Number(/pid (\d+)/.exec(start.stdout)?.[1]);
		expect(pid).toBeGreaterThan(0);

		const again = await squawk("daemon", "start");
		expect(again.stdout).toContain("already running");

		const status = await squawk("daemon", "status");
		expect(status.code).toBe(0);
		expect(status.stdout).toContain(`pid ${pid}`);
		expect(status.stdout).toContain("cli-test");

		const stop = await squawk("daemon", "stop");
		expect(stop.code).toBe(0);
		expect(stop.stdout).toContain("stopped");
		expect(() => process.kill(pid, 0)).toThrow();

		const after = await squawk("daemon", "status");
		expect(after.code).toBe(1);
	});

	it("rejects an unknown action", async () => {
		const result = await squawk("daemon", "bogus");
		expect(result.code).toBe(2);
	});
});
