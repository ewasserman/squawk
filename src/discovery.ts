/**
 * Finding other squawk services on the local network with mDNS.
 *
 * Each service advertises `_squawk._tcp` with a TXT record holding its display
 * name, key id, key fingerprint and WebSocket port, and browses for the same
 * service type. Everything learned this way is a hint: a discovered peer is
 * only a candidate until pairing has confirmed its key, and anyone on the
 * network can advertise any name or key. See docs/plan/security.md, threat 4.
 *
 * On macOS the work is done by the system's mDNSResponder through the
 * `dns-sd` command. A Node process sending multicast packets itself is often
 * refused there (EHOSTUNREACH) by the Local Network privacy setting, while
 * mDNSResponder is always allowed. Elsewhere bonjour-service is used.
 */
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { createInterface } from "node:readline";
import { Bonjour, type Service } from "bonjour-service";
import { isKeyId } from "./encoding.ts";

/** The DNS-SD service type, without the leading underscore or protocol. */
export const SERVICE_TYPE = "squawk";

/** What we advertise about ourselves. */
export interface Advertisement {
	name: string;
	keyId: string;
	fingerprint: string;
	port: number;
}

/** A squawk service seen on the network. Not trusted until paired. */
export interface DiscoveredPeer {
	name: string;
	keyId: string;
	fingerprint: string;
	/** Host name from the SRV record, e.g. `alices-mac.local`. */
	host: string;
	/** IP addresses from A/AAAA records, IPv4 first. */
	addresses: string[];
	port: number;
	/** Milliseconds since the epoch when this peer was last announced. */
	lastSeen: number;
}

/** A found or lost service, as reported by an mDNS backend. */
export interface RawService {
	name: string;
	host: string;
	port: number;
	addresses?: string[];
	txt?: Record<string, unknown>;
}

/**
 * The small part of an mDNS library that discovery needs. The default
 * implementation uses bonjour-service; tests pass a fake.
 */
export interface MdnsBackend {
	publish(
		instanceName: string,
		port: number,
		txt: Record<string, string>,
	): void;
	browse(
		onUp: (service: RawService) => void,
		onDown: (service: RawService) => void,
	): void;
	/** Asks the network again for services (used by `refresh`). */
	query(): void;
	/** Withdraws our advertisement and stops browsing. */
	destroy(): Promise<void>;
}

/** The real backend: multicast DNS on the local network via bonjour-service. */
export class BonjourBackend implements MdnsBackend {
	private bonjour = new Bonjour();
	private browser: ReturnType<Bonjour["find"]> | undefined;

	publish(
		instanceName: string,
		port: number,
		txt: Record<string, string>,
	): void {
		this.bonjour.publish({ name: instanceName, type: SERVICE_TYPE, port, txt });
	}

	browse(
		onUp: (service: RawService) => void,
		onDown: (service: RawService) => void,
	): void {
		const toRaw = (s: Service): RawService => ({
			name: s.name,
			host: s.host,
			port: s.port,
			addresses: s.addresses ?? [],
			txt: (s.txt ?? {}) as Record<string, unknown>,
		});
		this.browser = this.bonjour.find({ type: SERVICE_TYPE });
		this.browser.on("up", (s) => onUp(toRaw(s)));
		this.browser.on("down", (s) => onDown(toRaw(s)));
	}

	query(): void {
		this.browser?.update();
	}

	destroy(): Promise<void> {
		this.browser?.stop();
		return new Promise((resolve) => {
			this.bonjour.unpublishAll(() => {
				this.bonjour.destroy(() => resolve());
			});
		});
	}
}

/**
 * Splits the TXT line printed by `dns-sd -L` (` key=value key2=a\\ b`) into
 * key/value pairs. Spaces inside values are escaped with a backslash.
 */
export function parseDnsSdTxt(line: string): Record<string, string> {
	const out: Record<string, string> = {};
	let current = "";
	const items: string[] = [];
	const text = line.trim();
	for (let i = 0; i < text.length; i++) {
		const ch = text[i];
		if (ch === "\\" && i + 1 < text.length) {
			current += text[++i];
		} else if (ch === " ") {
			if (current) items.push(current);
			current = "";
		} else {
			current += ch;
		}
	}
	if (current) items.push(current);
	for (const item of items) {
		const eq = item.indexOf("=");
		if (eq > 0) out[item.slice(0, eq)] = item.slice(eq + 1);
	}
	return out;
}

/** The macOS backend: drives the system mDNSResponder through the `dns-sd` command. */
export class DnsSdBackend implements MdnsBackend {
	private readonly children = new Set<ChildProcess>();
	/** Instance name → number of interfaces it is currently seen on. */
	private readonly seenOn = new Map<string, number>();
	private readonly resolved = new Map<string, RawService>();

	private run(args: string[]): ChildProcess {
		const child = spawn("dns-sd", args, {
			stdio: ["ignore", "pipe", "ignore"],
		});
		this.children.add(child);
		child.on("exit", () => this.children.delete(child));
		child.on("error", () => this.children.delete(child));
		return child;
	}

	publish(
		instanceName: string,
		port: number,
		txt: Record<string, string>,
	): void {
		this.run([
			"-R",
			instanceName,
			`_${SERVICE_TYPE}._tcp`,
			"local",
			String(port),
			...Object.entries(txt).map(([k, v]) => `${k}=${v}`),
		]);
	}

	browse(
		onUp: (service: RawService) => void,
		onDown: (service: RawService) => void,
	): void {
		const child = this.run(["-B", `_${SERVICE_TYPE}._tcp`, "local"]);
		const marker = `_${SERVICE_TYPE}._tcp.`;
		createInterface({ input: child.stdout as NodeJS.ReadableStream }).on(
			"line",
			(line) => {
				const m = /^\S+\s+(Add|Rmv)\s+\d+\s+\d+\s+\S+\s+(\S+)\s+(.+)$/.exec(
					line,
				);
				if (!m || m[2] !== marker) return;
				const name = (m[3] ?? "").trim();
				const count = this.seenOn.get(name) ?? 0;
				if (m[1] === "Add") {
					this.seenOn.set(name, count + 1);
					if (count === 0) this.resolve(name, onUp);
				} else {
					const left = Math.max(0, count - 1);
					if (left > 0) {
						this.seenOn.set(name, left);
						return;
					}
					this.seenOn.delete(name);
					const service = this.resolved.get(name) ?? {
						name,
						host: "",
						port: 0,
					};
					this.resolved.delete(name);
					onDown(service);
				}
			},
		);
	}

	/** Looks up one instance's host, port and TXT record, then stops the lookup. */
	private resolve(name: string, onUp: (service: RawService) => void): void {
		const child = this.run(["-L", name, `_${SERVICE_TYPE}._tcp`, "local"]);
		let pending: { host: string; port: number } | undefined;
		const timer = setTimeout(() => child.kill(), 5000);
		createInterface({ input: child.stdout as NodeJS.ReadableStream }).on(
			"line",
			(line) => {
				const reach = /can be reached at (\S+?)\.?:(\d+)/.exec(line);
				if (reach) {
					pending = { host: reach[1] ?? "", port: Number(reach[2]) };
					return;
				}
				if (pending && line.startsWith(" ")) {
					const service: RawService = {
						name,
						host: pending.host,
						port: pending.port,
						addresses: [],
						txt: parseDnsSdTxt(line),
					};
					clearTimeout(timer);
					child.kill();
					if (!this.seenOn.has(name)) return;
					this.resolved.set(name, service);
					onUp(service);
					pending = undefined;
				}
			},
		);
	}

	query(): void {
		// mDNSResponder keeps asking the network by itself.
	}

	async destroy(): Promise<void> {
		for (const child of this.children) child.kill();
		this.children.clear();
	}
}

/** Picks the mDNS backend for this machine. SQUAWK_MDNS=bonjour|dns-sd overrides. */
export function defaultBackend(env = process.env): MdnsBackend {
	const choice = env.SQUAWK_MDNS;
	if (choice === "bonjour") return new BonjourBackend();
	if (choice === "dns-sd") return new DnsSdBackend();
	if (process.platform === "darwin") {
		const probe = spawnSync("which", ["dns-sd"], { stdio: "ignore" });
		if (probe.status === 0) return new DnsSdBackend();
	}
	return new BonjourBackend();
}

/** Reads a peer from a service's TXT record, or returns null if it is not a valid squawk record. */
export function peerFromService(
	service: RawService,
	now: number,
): DiscoveredPeer | null {
	const txt = service.txt ?? {};
	const text = (key: string): string | undefined => {
		const value = txt[key];
		if (typeof value === "string") return value;
		if (value instanceof Uint8Array) return new TextDecoder().decode(value);
		return undefined;
	};
	const keyId = text("id");
	const name = text("name");
	const fingerprint = text("fp");
	const port = Number(text("port") ?? service.port);
	if (!keyId || !isKeyId(keyId) || !name || !fingerprint) return null;
	if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
	const addresses = [...(service.addresses ?? [])].sort(
		(a, b) => Number(a.includes(":")) - Number(b.includes(":")),
	);
	return {
		name: name.slice(0, 64),
		keyId,
		fingerprint: fingerprint.slice(0, 64),
		host: service.host,
		addresses,
		port,
		lastSeen: now,
	};
}

export interface DiscoveryOptions {
	self: Advertisement;
	backend?: MdnsBackend;
	now?: () => number;
}

/**
 * Advertises this service and keeps a list of other squawk services seen on
 * the network, keyed by key id. Emits `up` and `down` with a DiscoveredPeer.
 */
export class Discovery extends EventEmitter<{
	up: [DiscoveredPeer];
	down: [DiscoveredPeer];
}> {
	private readonly self: Advertisement;
	private readonly backend: MdnsBackend;
	private readonly now: () => number;
	private readonly byKey = new Map<string, DiscoveredPeer>();
	/** mDNS instance name → key id, so a "down" (which may lack TXT) can be matched. */
	private readonly keyByInstance = new Map<string, string>();
	private started = false;

	constructor(options: DiscoveryOptions) {
		super();
		this.self = options.self;
		this.backend = options.backend ?? defaultBackend();
		this.now = options.now ?? Date.now;
	}

	/** The mDNS instance name we advertise: display name plus a fingerprint prefix, so it is unique. */
	instanceName(): string {
		const short = this.self.fingerprint.replace(/[^0-9a-f]/gi, "").slice(0, 8);
		return `${this.self.name.slice(0, 40)} (${short})`;
	}

	start(): void {
		if (this.started) return;
		this.started = true;
		this.backend.publish(this.instanceName(), this.self.port, {
			name: this.self.name,
			id: this.self.keyId,
			fp: this.self.fingerprint,
			port: String(this.self.port),
		});
		this.backend.browse(
			(s) => this.handleUp(s),
			(s) => this.handleDown(s),
		);
	}

	async stop(): Promise<void> {
		if (!this.started) return;
		this.started = false;
		await this.backend.destroy();
	}

	/** Asks the network again; answers arrive as `up` events. */
	refresh(): void {
		this.backend.query();
	}

	/** Peers currently seen, excluding ourselves, most recently seen first. */
	peers(): DiscoveredPeer[] {
		return [...this.byKey.values()].sort((a, b) => b.lastSeen - a.lastSeen);
	}

	/** The peer advertising this key, if seen. */
	peer(keyId: string): DiscoveredPeer | undefined {
		return this.byKey.get(keyId);
	}

	private handleUp(service: RawService): void {
		const peer = peerFromService(service, this.now());
		if (!peer || peer.keyId === this.self.keyId) return;
		this.keyByInstance.set(service.name, peer.keyId);
		this.byKey.set(peer.keyId, peer);
		this.emit("up", peer);
	}

	private handleDown(service: RawService): void {
		const keyId =
			this.keyByInstance.get(service.name) ??
			peerFromService(service, this.now())?.keyId;
		if (!keyId) return;
		this.keyByInstance.delete(service.name);
		const peer = this.byKey.get(keyId);
		if (!peer) return;
		this.byKey.delete(keyId);
		this.emit("down", peer);
	}
}
