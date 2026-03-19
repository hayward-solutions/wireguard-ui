<script lang="ts">
	import type { Peer, PeerStats } from '$lib/api';
	import { togglePeer, deletePeer } from '$lib/stores/peers';
	import { user } from '$lib/stores/auth';
	import { formatBytes, formatTimeAgo } from '$lib/format';
	import { Power, RefreshCw, Trash2 } from 'lucide-svelte';

	let {
		peers,
		statsMap,
		onregenerate
	}: { peers: Peer[]; statsMap: Map<string, PeerStats>; onregenerate: (peer: Peer) => void } = $props();

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

<div class="overflow-hidden rounded-xl border border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
	<div class="overflow-x-auto">
	<table class="w-full text-left text-sm">
		<thead>
			<tr class="border-b border-zinc-100 bg-zinc-50 text-xs font-medium uppercase tracking-wider text-zinc-500 dark:border-zinc-800 dark:bg-zinc-800 dark:text-zinc-400">
				<th class="px-4 py-3">Status</th>
				<th class="px-4 py-3">Name</th>
				{#if $user?.role === 'admin'}
					<th class="px-4 py-3">Owner</th>
				{/if}
				<th class="px-4 py-3">Address</th>
				<th class="hidden px-4 py-3 md:table-cell">Last Handshake</th>
				<th class="hidden px-4 py-3 md:table-cell">Transfer</th>
				<th class="px-4 py-3 text-right">Actions</th>
			</tr>
		</thead>
		<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
			{#each peers as peer (peer.id)}
				{@const stats = getStats(peer)}
				{@const connected = stats?.connected ?? false}
				<tr class="transition-colors hover:bg-zinc-50 dark:hover:bg-zinc-800">
					<td class="px-4 py-3">
						<div
							class="mx-auto h-2.5 w-2.5 rounded-full {connected
								? 'bg-emerald-500'
								: 'bg-zinc-300 dark:bg-zinc-600'}"
							title={connected ? 'Connected' : 'Disconnected'}
						></div>
					</td>
					<td class="px-4 py-3">
						<a href="/peers/{peer.id}" class="font-medium text-zinc-900 hover:underline dark:text-zinc-100">{peer.name}</a>
					</td>
					{#if $user?.role === 'admin'}
						<td class="px-4 py-3 text-zinc-500 dark:text-zinc-400">{peer.created_by_name ?? '—'}</td>
					{/if}
					<td class="px-4 py-3 font-mono text-zinc-600 dark:text-zinc-400">{peer.address}</td>
					<td class="hidden px-4 py-3 text-zinc-500 md:table-cell dark:text-zinc-400">
						{stats ? formatTimeAgo(stats.last_handshake) : '—'}
					</td>
					<td class="hidden px-4 py-3 text-zinc-500 md:table-cell dark:text-zinc-400">
						{#if stats}
							<span class="text-zinc-400 dark:text-zinc-500">↓</span> {formatBytes(stats.transfer_rx)}
							<span class="mx-1 text-zinc-300 dark:text-zinc-600">/</span>
							<span class="text-zinc-400 dark:text-zinc-500">↑</span> {formatBytes(stats.transfer_tx)}
						{:else}
							—
						{/if}
					</td>
					<td class="px-4 py-3">
						<div class="flex items-center justify-end gap-1">
							<button
								onclick={() => togglePeer(peer.id)}
								class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
								title={peer.enabled ? 'Disable' : 'Enable'}
							>
								<Power size={15} class={peer.enabled ? 'text-emerald-500' : ''} />
							</button>
							<button
								onclick={() => onregenerate(peer)}
								class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
								title="Regenerate config"
							>
								<RefreshCw size={15} />
							</button>
							<button
								onclick={() => handleDelete(peer)}
								disabled={deleting === peer.id}
								class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400"
								title="Delete peer"
							>
								<Trash2 size={15} />
							</button>
						</div>
					</td>
				</tr>
			{:else}
				<tr>
					<td colspan={$user?.role === 'admin' ? 7 : 6} class="py-12 text-center text-zinc-400 dark:text-zinc-500">
						No peers found
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
	</div>
</div>
