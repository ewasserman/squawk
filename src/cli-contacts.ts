/**
 * Commands for pairing and managing contacts: `squawk pair`, `squawk
 * contacts`, `squawk block` and `squawk unblock`. They talk to the running
 * service over its local socket.
 */
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { squawkHome } from "./config.ts";
import { connectToDaemon } from "./daemon-control.ts";
import type { PairingOffer } from "./pairing.ts";
import type { RpcClient } from "./rpc.ts";

/** The same shape as cli.ts's CliIo, plus an optional way to ask the person a question. */
export interface ContactsIo {
	stdout: (text: string) => void;
	stderr: (text: string) => void;
	env: NodeJS.ProcessEnv;
	/** Shows `prompt` and resolves with the line the person typed. Defaults to stdin. */
	ask?: (prompt: string) => Promise<string>;
}

interface ContactsCommand {
	summary: string;
	run: (args: string[], io: ContactsIo) => Promise<number>;
}

const NOT_RUNNING =
	"squawk service is not running; start it with `squawk daemon start`\n";

function askOnStdin(prompt: string, io: ContactsIo): Promise<string> {
	io.stdout(prompt);
	return new Promise((resolve) => {
		const rl = createInterface({ input: process.stdin });
		let answered = false;
		rl.once("line", (line) => {
			answered = true;
			rl.close();
			resolve(line);
		});
		rl.once("close", () => {
			if (!answered) resolve("");
		});
	});
}

async function withService(
	io: ContactsIo,
	work: (rpc: RpcClient) => Promise<number>,
): Promise<number> {
	const rpc = await connectToDaemon(squawkHome(io.env));
	if (!rpc) {
		io.stderr(NOT_RUNNING);
		return 1;
	}
	try {
		return await work(rpc);
	} catch (err) {
		io.stderr(`squawk: ${err instanceof Error ? err.message : String(err)}\n`);
		return 1;
	} finally {
		await rpc.close();
	}
}

/** "123456" → "123 456", easier to read aloud. */
export function formatCode(code: string): string {
	return `${code.slice(0, 3)} ${code.slice(3)}`;
}

export const contactCommands: Record<string, ContactsCommand> = {
	pair: {
		summary:
			"pair with someone: `pair <peer>` (name from `squawk peers`, or host:port), or `pair --accept` to wait",
		async run(args, io) {
			const { values, positionals } = parseArgs({
				args,
				options: { accept: { type: "boolean" } },
				allowPositionals: true,
				strict: true,
			});
			const peer = positionals[0];
			if ((values.accept && peer) || (!values.accept && !peer)) {
				io.stderr("Usage: squawk pair <peer> | squawk pair --accept\n");
				return 2;
			}
			return withService(io, async (rpc) => {
				let offer: PairingOffer;
				if (values.accept) {
					io.stdout(
						"Waiting for someone to pair with you (up to 2 minutes). Ask them to run `squawk pair <your name>`.\n",
					);
					offer = await rpc.call<PairingOffer>("pair_accept");
				} else {
					io.stdout(`Contacting ${peer}...\n`);
					offer = await rpc.call<PairingOffer>("pair_start", { peer });
				}
				io.stdout(
					[
						"",
						`Pairing with "${offer.peer_name}"`,
						`Their key fingerprint: ${offer.peer_fingerprint}`,
						"",
						`    Code: ${formatCode(offer.code)}`,
						"",
						"Compare this code with the one on the other person's screen,",
						"in person or on a call. If they differ, someone may be",
						"interfering: answer no.",
						"",
					].join("\n"),
				);
				const answer = await (io.ask ?? ((p) => askOnStdin(p, io)))(
					"Do the codes match? [y/N] ",
				);
				const match = /^\s*y(es)?\s*$/i.test(answer);
				if (!match) {
					await rpc
						.call("pair_confirm", {
							pairing_id: offer.pairing_id,
							match: false,
						})
						.catch(() => {});
					io.stdout("Pairing cancelled. Nothing was saved.\n");
					return 1;
				}
				io.stdout("Waiting for the other person to confirm...\n");
				const result = await rpc.call<{ contact: { name: string } }>(
					"pair_confirm",
					{ pairing_id: offer.pairing_id, match: true },
				);
				io.stdout(`Paired with "${result.contact.name}".\n`);
				return 0;
			});
		},
	},
	contacts: {
		summary: "list paired and blocked contacts (--json)",
		async run(args, io) {
			const { values } = parseArgs({
				args,
				options: { json: { type: "boolean" } },
				strict: true,
			});
			return withService(io, async (rpc) => {
				const { contacts } = await rpc.call<{
					contacts: Array<{
						name: string;
						key_id: string;
						fingerprint: string;
						trust: string;
						auto_send: boolean;
						inbound_policy: string | null;
					}>;
				}>("contacts");
				if (values.json) {
					io.stdout(`${JSON.stringify(contacts)}\n`);
					return 0;
				}
				if (contacts.length === 0) {
					io.stdout(
						"No contacts yet. Pair with someone using `squawk pair`.\n",
					);
					return 0;
				}
				for (const c of contacts) {
					io.stdout(
						`${c.name}  ${c.trust}  ${c.fingerprint}  policy=${c.inbound_policy ?? "default"}  auto_send=${c.auto_send ? "on" : "off"}\n`,
					);
				}
				return 0;
			});
		},
	},
	"auto-send": {
		summary:
			"let Claude send to a contact without asking you first: `auto-send <contact> on|off` (off by default)",
		async run(args, io) {
			const { positionals } = parseArgs({
				args,
				options: {},
				allowPositionals: true,
				strict: true,
			});
			const [contact, setting] = positionals;
			if (
				!contact ||
				(setting !== "on" && setting !== "off") ||
				positionals.length > 2
			) {
				io.stderr("Usage: squawk auto-send <contact> on|off\n");
				return 2;
			}
			return withService(io, async (rpc) => {
				const { contact: c } = await rpc.call<{ contact: { name: string } }>(
					"update_contact",
					{ contact, auto_send: setting === "on" },
				);
				io.stdout(
					setting === "on"
						? `Claude will now send messages to "${c.name}" without asking you first.\n`
						: `Claude will ask you before sending each message to "${c.name}".\n`,
				);
				return 0;
			});
		},
	},
	block: {
		summary: "refuse all connections and messages from a contact",
		async run(args, io) {
			return setTrust("block", args, io);
		},
	},
	unblock: {
		summary: "accept a blocked contact again",
		async run(args, io) {
			return setTrust("unblock", args, io);
		},
	},
};

async function setTrust(
	method: "block" | "unblock",
	args: string[],
	io: ContactsIo,
): Promise<number> {
	const { positionals } = parseArgs({
		args,
		options: {},
		allowPositionals: true,
		strict: true,
	});
	const contact = positionals[0];
	if (!contact || positionals.length > 1) {
		io.stderr(`Usage: squawk ${method} <contact>\n`);
		return 2;
	}
	return withService(io, async (rpc) => {
		const result = await rpc.call<{ name: string }>(method, { contact });
		io.stdout(
			method === "block"
				? `Blocked "${result.name}".\n`
				: `Unblocked "${result.name}".\n`,
		);
		return 0;
	});
}
