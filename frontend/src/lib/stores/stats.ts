import { writable } from 'svelte/store';
import type { PeerStats } from '$lib/api';

export const stats = writable<Map<string, PeerStats>>(new Map());

let eventSource: EventSource | null = null;

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
