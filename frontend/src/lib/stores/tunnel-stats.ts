import { writable } from 'svelte/store';
import type { TunnelStatus } from '$lib/api';
import type { RateSnapshot } from './stats';

const MAX_HISTORY = 30; // ~5 minutes at 10s intervals

export const tunnelStats = writable<Map<string, TunnelStatus>>(new Map());
export const tunnelCurrentRates = writable<Map<string, { rx_rate: number; tx_rate: number }>>(
	new Map()
);
export const tunnelRateHistory = writable<Map<string, RateSnapshot[]>>(new Map());

let eventSource: EventSource | null = null;
let prevSnapshot: Map<string, TunnelStatus> | null = null;
let lastTickTime = 0;

export function startTunnelStatsStream() {
	if (eventSource) return;

	eventSource = new EventSource('/api/v1/tunnels/stats/stream');
	eventSource.onmessage = (event) => {
		try {
			const data: TunnelStatus[] = JSON.parse(event.data);
			const map = new Map<string, TunnelStatus>();
			for (const s of data) {
				map.set(s.tunnel_id, s);
			}
			tunnelStats.set(map);

			// Compute rates from deltas
			const now = Date.now();
			if (prevSnapshot && lastTickTime > 0) {
				const elapsed = (now - lastTickTime) / 1000;
				if (elapsed > 0) {
					const rates = new Map<string, { rx_rate: number; tx_rate: number }>();

					tunnelRateHistory.update((history) => {
						for (const [key, curr] of map) {
							const prev = prevSnapshot!.get(key);
							if (prev) {
								const rxDelta = curr.transfer_rx - prev.transfer_rx;
								const txDelta = curr.transfer_tx - prev.transfer_tx;
								const rx_rate = rxDelta > 0 ? rxDelta / elapsed : 0;
								const tx_rate = txDelta > 0 ? txDelta / elapsed : 0;

								rates.set(key, { rx_rate, tx_rate });

								const entry: RateSnapshot = { timestamp: now, rx_rate, tx_rate };
								const arr = history.get(key) ?? [];
								arr.push(entry);
								if (arr.length > MAX_HISTORY) arr.shift();
								history.set(key, arr);
							}
						}
						return new Map(history);
					});

					tunnelCurrentRates.set(rates);
				}
			}

			prevSnapshot = map;
			lastTickTime = now;
		} catch (err) {
			console.error('Failed to parse tunnel stats:', err);
		}
	};

	eventSource.onerror = () => {
		stopTunnelStatsStream();
		// Reconnect after 5 seconds
		setTimeout(startTunnelStatsStream, 5000);
	};
}

export function stopTunnelStatsStream() {
	if (eventSource) {
		eventSource.close();
		eventSource = null;
	}
}
