<script lang="ts">
	import type { Peer, PeerStats } from '$lib/api';
	import { api } from '$lib/api';
	import { togglePeer, deletePeer } from '$lib/stores/peers';
	import { user } from '$lib/stores/auth';
	import { formatBytes, formatTimeAgo } from '$lib/format';
	import { Download, QrCode, Power, Trash2, ArrowUpDown } from 'lucide-svelte';

	let { peer, stats }: { peer: Peer; stats?: PeerStats } = $props();

	let showQR = $state(false);
	let deleting = $state(false);

	const connected = $derived(stats?.connected ?? false);

	async function handleDelete() {
		if (!confirm(`Delete peer "${peer.name}"?`)) return;
		deleting = true;
		try {
			await deletePeer(peer.id);
		} finally {
			deleting = false;
		}
	}
</script>

<div class="rounded-xl border border-zinc-200 bg-white p-5 transition-shadow hover:shadow-md dark:border-zinc-700 dark:bg-zinc-900">
	<div class="flex items-start justify-between">
		<div class="flex items-center gap-3">
			<div
				class="h-2.5 w-2.5 rounded-full {connected ? 'bg-emerald-500' : 'bg-zinc-300 dark:bg-zinc-600'}"
				title={connected ? 'Connected' : 'Disconnected'}
			></div>
			<div>
				<h3 class="font-semibold text-zinc-900 dark:text-zinc-100">{peer.name}</h3>
				{#if $user?.role === 'admin' && peer.created_by_name}
					<p class="text-xs text-zinc-400 dark:text-zinc-500">{peer.created_by_name}</p>
				{/if}
			</div>
		</div>
		<div class="flex items-center gap-1">
			<button
				onclick={() => togglePeer(peer.id)}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title={peer.enabled ? 'Disable' : 'Enable'}
			>
				<Power size={16} class={peer.enabled ? 'text-emerald-500' : ''} />
			</button>
			<a
				href={api.getConfigURL(peer.id)}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title="Download config"
				download
			>
				<Download size={16} />
			</a>
			<button
				onclick={() => (showQR = !showQR)}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title="Show QR code"
			>
				<QrCode size={16} />
			</button>
			<button
				onclick={handleDelete}
				disabled={deleting}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400"
				title="Delete peer"
			>
				<Trash2 size={16} />
			</button>
		</div>
	</div>

	<div class="mt-4 grid grid-cols-2 gap-3 text-sm">
		<div>
			<span class="text-zinc-400 dark:text-zinc-500">Address</span>
			<p class="font-mono text-zinc-700 dark:text-zinc-300">{peer.address}</p>
		</div>
		<div>
			<span class="text-zinc-400 dark:text-zinc-500">Allowed IPs</span>
			<p class="font-mono text-zinc-700 dark:text-zinc-300">{peer.allowed_ips}</p>
		</div>
		{#if stats}
			<div>
				<span class="text-zinc-400 dark:text-zinc-500">Last handshake</span>
				<p class="text-zinc-700 dark:text-zinc-300">{formatTimeAgo(stats.last_handshake)}</p>
			</div>
			<div class="flex items-center gap-1">
				<ArrowUpDown size={14} class="text-zinc-400 dark:text-zinc-500" />
				<span class="text-zinc-700 dark:text-zinc-300">{formatBytes(stats.transfer_rx)} / {formatBytes(stats.transfer_tx)}</span>
			</div>
		{/if}
	</div>

	{#if showQR}
		<div class="mt-4 flex justify-center rounded-lg border border-zinc-100 bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-800">
			<img src={api.getQRCodeURL(peer.id)} alt="QR Code for {peer.name}" class="h-48 w-48" />
		</div>
	{/if}
</div>
