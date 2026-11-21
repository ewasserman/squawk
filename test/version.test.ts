import { describe, expect, it } from "vitest";
import { VERSION } from "../src/version.ts";

describe("version", () => {
	it("is a semantic version string", () => {
		expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
	});
});
