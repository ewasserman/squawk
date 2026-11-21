#!/usr/bin/env node
/**
 * Spike: stands in for `squawk tail`. Prints one JSON line per "incoming
 * message", SPIKE_MONITOR_COUNT lines, SPIKE_MONITOR_INTERVAL_MS apart, so it
 * can be started under Claude Code's Monitor tool to see whether new lines
 * wake an idle session.
 */
const COUNT = Number(process.env.SPIKE_MONITOR_COUNT ?? 2);
const INTERVAL_MS = Number(process.env.SPIKE_MONITOR_INTERVAL_MS ?? 20_000);

let n = 0;
const timer = setInterval(() => {
	n++;
	console.log(
		JSON.stringify({
			msg_id: `monitor-${n}`,
			sender: "spike-bob",
			thread: "thread-1",
			policy: "show_first",
			body: `Monitor test message ${n}`,
		}),
	);
	if (n >= COUNT) clearInterval(timer);
}, INTERVAL_MS);
