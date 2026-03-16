import { writable } from 'svelte/store';
import { api, type Peer } from '$lib/api';

export const peers = writable<Peer[]>([]);
export const peersLoading = writable(false);

export async function loadPeers() {
	peersLoading.set(true);
	try {
		const data = await api.listPeers();
		peers.set(data);
	} catch (err) {
		console.error('Failed to load peers:', err);
	} finally {
		peersLoading.set(false);
	}
}

export async function createPeer(name: string, email?: string) {
	const peer = await api.createPeer({ name, email });
	peers.update((p) => [peer, ...p]);
	return peer;
}

export async function deletePeer(id: string) {
	await api.deletePeer(id);
	peers.update((p) => p.filter((peer) => peer.id !== id));
}

export async function togglePeer(id: string) {
	const updated = await api.togglePeer(id);
	peers.update((p) => p.map((peer) => (peer.id === updated.id ? updated : peer)));
}
