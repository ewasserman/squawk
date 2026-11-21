/**
 * The `squawk mcp` command. Kept in its own file so `cli.ts` only has to
 * spread `mcpCommands` into its command table.
 */
import { parseArgs } from "node:util";
import type { Command } from "./cli.ts";
import { squawkHome } from "./config.ts";
import { runMcpServer, sessionLabel } from "./mcp.ts";

export const mcpCommands: Record<string, Command> = {
	mcp: {
		summary:
			"run the MCP server for a Claude Code session over stdio (label: $SQUAWK_SESSION or the directory name)",
		async run(args, io) {
			parseArgs({ args, options: {}, strict: true });
			// Standard output carries the MCP protocol, so only io.stderr is used here.
			await runMcpServer({
				home: squawkHome(io.env),
				label: sessionLabel(io.env, process.cwd()),
				env: io.env,
				log: (text) => io.stderr(`squawk mcp: ${text}\n`),
			});
			return 0;
		},
	},
};
