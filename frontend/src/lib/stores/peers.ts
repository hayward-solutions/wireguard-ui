import { writable } from 'svelte/store';
import { api, type Peer, type CreatePeerResponse } from '$lib/api';

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

export async function createPeer(name: string, allowed_ips?: string, dns?: string, public_key?: string): Promise<CreatePeerResponse> {
	const response = await api.createPeer({ name, allowed_ips, dns, public_key });
	peers.update((p) => [response, ...p]);
	return response;
}

export async function deletePeer(id: string) {
	await api.deletePeer(id);
	peers.update((p) => p.filter((peer) => peer.id !== id));
}

export async function togglePeer(id: string) {
	const updated = await api.togglePeer(id);
	peers.update((p) => p.map((peer) => (peer.id === updated.id ? updated : peer)));
}

export async function regeneratePeer(id: string, publicKey: string): Promise<CreatePeerResponse> {
	const response = await api.regeneratePeer(id, publicKey);
	peers.update((p) => p.map((peer) => (peer.id === response.id ? response : peer)));
	return response;
}
