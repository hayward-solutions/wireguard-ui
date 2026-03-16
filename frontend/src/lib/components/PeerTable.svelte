<script lang="ts">
	import type { Peer, PeerStats } from '$lib/api';
	import { api } from '$lib/api';
	import { togglePeer, deletePeer } from '$lib/stores/peers';
	import { user } from '$lib/stores/auth';
	import { formatBytes, formatTimeAgo } from '$lib/format';
	import { Download, QrCode, Power, Trash2 } from 'lucide-svelte';

	let {
		peers,
		statsMap
	}: { peers: Peer[]; statsMap: Map<string, PeerStats> } = $props();

	let qrPeerId = $state<string | null>(null);
	let deleting = $state<string | null>(null);

	async function handleDelete(peer: Peer) {
		if (!confirm(`Delete peer "${peer.name}"?`)) return;
		deleting = peer.id;
		try {
			await deletePeer(peer.id);
		} finally {
			deleting = null;
		}
	}

	function getStats(peer: Peer): PeerStats | undefined {
		return statsMap.get(peer.public_key);
	}
</script>

<div class="overflow-hidden rounded-xl border border-zinc-200 bg-white">
	<table class="w-full text-left text-sm">
		<thead>
			<tr class="border-b border-zinc-100 bg-zinc-50 text-xs font-medium uppercase tracking-wider text-zinc-500">
				<th class="px-4 py-3">Status</th>
				<th class="px-4 py-3">Name</th>
				{#if $user?.role === 'admin'}
					<th class="px-4 py-3">Owner</th>
				{/if}
				<th class="px-4 py-3">Address</th>
				<th class="px-4 py-3">Last Handshake</th>
				<th class="px-4 py-3">Transfer</th>
				<th class="px-4 py-3 text-right">Actions</th>
			</tr>
		</thead>
		<tbody class="divide-y divide-zinc-100">
			{#each peers as peer (peer.id)}
				{@const stats = getStats(peer)}
				{@const connected = stats?.connected ?? false}
				<tr class="transition-colors hover:bg-zinc-50">
					<td class="px-4 py-3">
						<div
							class="mx-auto h-2.5 w-2.5 rounded-full {connected
								? 'bg-emerald-500'
								: 'bg-zinc-300'}"
							title={connected ? 'Connected' : 'Disconnected'}
						></div>
					</td>
					<td class="px-4 py-3">
						<span class="font-medium text-zinc-900">{peer.name}</span>
					</td>
					{#if $user?.role === 'admin'}
						<td class="px-4 py-3 text-zinc-500">{peer.created_by_name ?? '—'}</td>
					{/if}
					<td class="px-4 py-3 font-mono text-zinc-600">{peer.address}</td>
					<td class="px-4 py-3 text-zinc-500">
						{stats ? formatTimeAgo(stats.last_handshake) : '—'}
					</td>
					<td class="px-4 py-3 text-zinc-500">
						{#if stats}
							<span class="text-zinc-400">↓</span> {formatBytes(stats.transfer_rx)}
							<span class="mx-1 text-zinc-300">/</span>
							<span class="text-zinc-400">↑</span> {formatBytes(stats.transfer_tx)}
						{:else}
							—
						{/if}
					</td>
					<td class="px-4 py-3">
						<div class="flex items-center justify-end gap-1">
							<button
								onclick={() => togglePeer(peer.id)}
								class="rounded-lg p-1.5 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700"
								title={peer.enabled ? 'Disable' : 'Enable'}
							>
								<Power size={15} class={peer.enabled ? 'text-emerald-500' : ''} />
							</button>
							<a
								href={api.getConfigURL(peer.id)}
								class="rounded-lg p-1.5 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700"
								title="Download config"
								download
							>
								<Download size={15} />
							</a>
							<button
								onclick={() => (qrPeerId = qrPeerId === peer.id ? null : peer.id)}
								class="rounded-lg p-1.5 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700"
								title="Show QR code"
							>
								<QrCode size={15} />
							</button>
							<button
								onclick={() => handleDelete(peer)}
								disabled={deleting === peer.id}
								class="rounded-lg p-1.5 text-zinc-400 transition-colors hover:bg-red-50 hover:text-red-600"
								title="Delete peer"
							>
								<Trash2 size={15} />
							</button>
						</div>
					</td>
				</tr>
				{#if qrPeerId === peer.id}
					<tr>
						<td colspan={$user?.role === 'admin' ? 7 : 6} class="bg-zinc-50 px-4 py-4">
							<div class="flex justify-center">
								<img
									src={api.getQRCodeURL(peer.id)}
									alt="QR Code for {peer.name}"
									class="h-48 w-48"
								/>
							</div>
						</td>
					</tr>
				{/if}
			{:else}
				<tr>
					<td colspan={$user?.role === 'admin' ? 7 : 6} class="py-12 text-center text-zinc-400">
						No peers found
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
