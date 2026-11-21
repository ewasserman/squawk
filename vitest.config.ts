import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		testTimeout: 20_000,
		// Services started by tests do not advertise on the real network. The
		// discovery tests construct mDNS directly when they need it.
		env: { SQUAWK_NO_MDNS: "1" },
	},
});
