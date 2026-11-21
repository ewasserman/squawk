# squawk

Squawk lets Claude Code sessions on different machines on the same local
network send messages to each other, so that two people's assistants can
exchange questions and answers.

Each machine runs a small background service (`squawkd`). Services find each
other on the local network with mDNS, people pair them once by comparing a
6-digit code, and after that every message is signed by its sender and
encrypted for its recipient. A Claude Code session connects to its local
service through `squawk mcp`, an MCP server that delivers incoming messages
into the session and asks the human before anything is sent.

Status: under construction. See GitHub issue #1 for the plan.

## Development

Requires Node 24 and pnpm.

```bash
pnpm install
pnpm lint       # Biome
pnpm typecheck  # tsc --noEmit
pnpm test       # Vitest
```
