// Runs the Node version of squawk for tests/test_node_compat.py, which checks
// that the Python and Node versions read each other's messages and files.
// Reads one JSON request on stdin and writes one JSON reply on stdout.
import { fromBase64Url } from "../../src/encoding.ts";
import { EnvelopeError, open, ReplayGuard, seal } from "../../src/envelope.ts";
import { identityFromSecretKey } from "../../src/identity.ts";
import { Store } from "../../src/store.ts";

const hex = (bytes) => Buffer.from(bytes).toString("hex");

function identity(seed) {
	return identityFromSecretKey("node", fromBase64Url(seed));
}

const handlers = {
	identity({ seed }) {
		const id = identity(seed);
		return {
			id: id.id,
			x25519PublicKey: hex(id.x25519PublicKey),
			x25519SecretKey: hex(id.x25519SecretKey),
		};
	},
	seal({ seed, envelope }) {
		return seal(envelope, identity(seed));
	},
	open({ seed, sealed, now }) {
		try {
			const guard = now === undefined ? undefined : new ReplayGuard({ now: () => now });
			return { envelope: open(sealed, identity(seed), guard) };
		} catch (err) {
			if (err instanceof EnvelopeError) return { error: err.code };
			throw err;
		}
	},
	writeStore({ path, now, contact, incoming, outgoing, seenId }) {
		const store = Store.open(path, { now: () => now });
		store.upsertContact(contact);
		store.saveIncoming(incoming);
		store.queueOutgoing(outgoing);
		store.recordAttempt(outgoing.id, { error: "ECONNREFUSED" });
		store.seenIds().add(seenId, now);
		store.setSetting("default_inbound_policy", "auto_answer");
		store.close();
		return {};
	},
	readStore({ path, now }) {
		const store = Store.open(path, { now: () => now });
		const result = {
			schemaVersion: store.schemaVersion(),
			contacts: store.listContacts(),
			inbox: store.inbox(),
			threads: store.listThreads(),
			outbound: store.dueOutbound(Number.MAX_SAFE_INTEGER),
			acked: store.ackedAt("acked-id") ?? null,
			setting: store.getSetting("default_inbound_policy") ?? null,
		};
		store.close();
		return result;
	},
};

let input = "";
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
process.stdout.write(JSON.stringify(handlers[request.op](request)));
