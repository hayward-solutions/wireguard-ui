<script lang="ts">
	import { onMount } from 'svelte';
	import { peers, loadPeers } from '$lib/stores/peers';
	import { stats } from '$lib/stores/stats';
	import { formatBytes } from '$lib/format';
	import { Users, Wifi, ArrowDown, ArrowUp } from 'lucide-svelte';

	onMount(() => {
		loadPeers();
	});

	const totalPeers = $derived($peers.length);
	const activePeers = $derived(
		$peers.filter((p) => {
			const s = $stats.get(p.public_key);
			return s?.connected;
		}).length
	);
	const totalRx = $derived(
		Array.from($stats.values()).reduce((sum, s) => sum + s.transfer_rx, 0)
	);
	const totalTx = $derived(
		Array.from($stats.values()).reduce((sum, s) => sum + s.transfer_tx, 0)
	);
</script>

<div>
	<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Dashboard</h1>
	<p class="mt-1 text-zinc-500 dark:text-zinc-400">WireGuard VPN overview</p>

	<div class="mt-8 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
		<div class="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800">
					<Users size={20} class="text-zinc-600 dark:text-zinc-400" />
				</div>
				<div>
					<p class="text-sm text-zinc-500 dark:text-zinc-400">Total Peers</p>
					<p class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">{totalPeers}</p>
				</div>
			</div>
		</div>

		<div class="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-50 dark:bg-emerald-950">
					<Wifi size={20} class="text-emerald-600" />
				</div>
				<div>
					<p class="text-sm text-zinc-500 dark:text-zinc-400">Active Peers</p>
					<p class="text-2xl font-bold text-emerald-600">{activePeers}</p>
				</div>
			</div>
		</div>

		<div class="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-50 dark:bg-blue-950">
					<ArrowDown size={20} class="text-blue-600" />
				</div>
				<div>
					<p class="text-sm text-zinc-500 dark:text-zinc-400">Total Received</p>
					<p class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">{formatBytes(totalRx)}</p>
				</div>
			</div>
		</div>

		<div class="rounded-xl border border-zinc-200 bg-white p-5 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-50 dark:bg-purple-950">
					<ArrowUp size={20} class="text-purple-600" />
				</div>
				<div>
					<p class="text-sm text-zinc-500 dark:text-zinc-400">Total Sent</p>
					<p class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">{formatBytes(totalTx)}</p>
				</div>
			</div>
		</div>
	</div>
</div>
