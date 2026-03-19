import { writable } from 'svelte/store';
import type { PeerStats } from '$lib/api';

export interface RateSnapshot {
	timestamp: number;
	rx_rate: number;
	tx_rate: number;
}

const MAX_HISTORY = 30; // ~5 minutes at 10s intervals

export const stats = writable<Map<string, PeerStats>>(new Map());
export const currentRates = writable<Map<string, { rx_rate: number; tx_rate: number }>>(new Map());
export const rateHistory = writable<Map<string, RateSnapshot[]>>(new Map());

let eventSource: EventSource | null = null;
let prevSnapshot: Map<string, PeerStats> | null = null;
let lastTickTime = 0;

export function startStatsStream() {
	if (eventSource) return;

	eventSource = new EventSource('/api/v1/stats/stream');
	eventSource.onmessage = (event) => {
		try {
			const data: PeerStats[] = JSON.parse(event.data);
			const map = new Map<string, PeerStats>();
			for (const s of data) {
				map.set(s.public_key, s);
			}
			stats.set(map);

			// Compute rates from deltas
			const now = Date.now();
			if (prevSnapshot && lastTickTime > 0) {
				const elapsed = (now - lastTickTime) / 1000;
				if (elapsed > 0) {
					const rates = new Map<string, { rx_rate: number; tx_rate: number }>();

					rateHistory.update((history) => {
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

					currentRates.set(rates);
				}
			}

			prevSnapshot = map;
			lastTickTime = now;
		} catch (err) {
			console.error('Failed to parse stats:', err);
		}
	};

	eventSource.onerror = () => {
		stopStatsStream();
		// Reconnect after 5 seconds
		setTimeout(startStatsStream, 5000);
	};
}

export function stopStatsStream() {
	if (eventSource) {
		eventSource.close();
		eventSource = null;
	}
}
