import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../src/cli.ts";
import { dbPath, identityPath, runDir, squawkHome } from "../src/config.ts";
import {
	fingerprint,
	IdentityExistsError,
	initIdentity,
	loadIdentity,
	NoIdentityError,
} from "../src/identity.ts";

let base: string;
let home: string;

beforeEach(async () => {
	base = await mkdtemp(join(tmpdir(), "squawk-test-"));
	home = join(base, "home");
});

afterEach(async () => {
	await rm(base, { recursive: true, force: true });
});

describe("config", () => {
	it("uses SQUAWK_HOME when set", () => {
		expect(squawkHome({ SQUAWK_HOME: "/x/y" })).toBe("/x/y");
	});

	it("falls back to ~/.config/squawk", () => {
		expect(squawkHome({})).toBe(join(homedir(), ".config", "squawk"));
	});

	it("builds paths under the home directory", () => {
		expect(identityPath("/h")).toBe("/h/identity.json");
		expect(dbPath("/h")).toBe("/h/squawk.db");
		expect(runDir("/h")).toBe("/h/run");
	});
});

describe("identity", () => {
	it("creates a key pair that can sign and verify", async () => {
		const id = await initIdentity(home, "alice");
		expect(id.name).toBe("alice");
		expect(id.publicKey).toHaveLength(32);
		const msg = new TextEncoder().encode("hello");
		const sig = ed25519.sign(msg, id.secretKey);
		expect(ed25519.verify(sig, msg, id.publicKey)).toBe(true);
	});

	it("derives x25519 keys that agree on a shared secret", async () => {
		const a = await initIdentity(join(base, "a"), "a");
		const b = await initIdentity(join(base, "b"), "b");
		const ab = x25519.getSharedSecret(a.x25519SecretKey, b.x25519PublicKey);
		const ba = x25519.getSharedSecret(b.x25519SecretKey, a.x25519PublicKey);
		expect(ab).toEqual(ba);
	});

	it("reloads the same identity", async () => {
		const created = await initIdentity(home, "alice");
		const loaded = await loadIdentity(home);
		expect(loaded.name).toBe("alice");
		expect(loaded.id).toBe(created.id);
		expect(loaded.secretKey).toEqual(created.secretKey);
		expect(loaded.x25519PublicKey).toEqual(created.x25519PublicKey);
	});

	it("refuses to overwrite an existing identity", async () => {
		const first = await initIdentity(home, "alice");
		await expect(initIdentity(home, "mallory")).rejects.toBeInstanceOf(
			IdentityExistsError,
		);
		const loaded = await loadIdentity(home);
		expect(loaded.id).toBe(first.id);
		expect(loaded.name).toBe("alice");
	});

	it("writes the key file as 0600 and the directory as 0700", async () => {
		await initIdentity(home, "alice");
		expect((await stat(identityPath(home))).mode & 0o777).toBe(0o600);
		expect((await stat(home)).mode & 0o777).toBe(0o700);
	});

	it("reports a missing identity", async () => {
		await expect(loadIdentity(home)).rejects.toBeInstanceOf(NoIdentityError);
	});

	it("uses a default display name when none is given", async () => {
		const id = await initIdentity(home);
		expect(id.name.length).toBeGreaterThan(0);
	});

	it("formats the fingerprint as eight groups of four hex characters", async () => {
		const id = await initIdentity(home, "alice");
		expect(fingerprint(id.publicKey)).toMatch(/^([0-9a-f]{4}-){7}[0-9a-f]{4}$/);
	});
});

describe("cli", () => {
	function capture() {
		const out: string[] = [];
		const err: string[] = [];
		return {
			out,
			err,
			io: {
				stdout: (t: string) => out.push(t),
				stderr: (t: string) => err.push(t),
				env: { SQUAWK_HOME: home },
			},
		};
	}

	it("init then whoami prints the name and fingerprint", async () => {
		const init = capture();
		expect(await main(["init", "--name", "alice"], init.io)).toBe(0);
		const raw = JSON.parse(await readFile(identityPath(home), "utf8"));
		expect(raw.name).toBe("alice");

		const who = capture();
		expect(await main(["whoami"], who.io)).toBe(0);
		const text = who.out.join("");
		const id = await loadIdentity(home);
		expect(text).toContain("alice");
		expect(text).toContain(fingerprint(id.publicKey));
	});

	it("init a second time fails with exit code 1", async () => {
		await main(["init", "--name", "alice"], capture().io);
		const again = capture();
		expect(await main(["init", "--name", "bob"], again.io)).toBe(1);
		expect(again.err.join("")).toContain("refusing to overwrite");
	});

	it("whoami without an identity fails with exit code 1", async () => {
		const who = capture();
		expect(await main(["whoami"], who.io)).toBe(1);
		expect(who.err.join("")).toContain("squawk init");
	});

	it("rejects unknown commands and options", async () => {
		expect(await main(["frobnicate"], capture().io)).toBe(2);
		expect(await main(["init", "--bogus"], capture().io)).toBe(2);
	});
});
