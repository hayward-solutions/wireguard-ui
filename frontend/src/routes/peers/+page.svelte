<script lang="ts">
	import { onMount } from 'svelte';
	import { peers, loadPeers } from '$lib/stores/peers';
	import { stats } from '$lib/stores/stats';
	import PeerCard from '$lib/components/PeerCard.svelte';
	import PeerTable from '$lib/components/PeerTable.svelte';
	import CreatePeerModal from '$lib/components/CreatePeerModal.svelte';
	import { Plus, Search, LayoutGrid, List } from 'lucide-svelte';

	let showCreate = $state(false);
	let search = $state('');
	let view = $state<'table' | 'cards'>(
		(typeof localStorage !== 'undefined' && localStorage.getItem('peers-view') as 'table' | 'cards') || 'table'
	);

	function setView(v: 'table' | 'cards') {
		view = v;
		localStorage.setItem('peers-view', v);
	}

	const filteredPeers = $derived(
		$peers.filter(
			(p) =>
				p.name.toLowerCase().includes(search.toLowerCase()) ||
				p.address.includes(search) ||
				(p.created_by_name?.toLowerCase().includes(search.toLowerCase()) ?? false)
		)
	);

	onMount(() => {
		loadPeers();
	});
</script>

<div>
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900">Peers</h1>
			<p class="mt-1 text-zinc-500">{$peers.length} peer{$peers.length !== 1 ? 's' : ''} configured</p>
		</div>
		<button
			onclick={() => (showCreate = true)}
			class="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800"
		>
			<Plus size={16} />
			Add Peer
		</button>
	</div>

	<div class="mt-6 flex items-center gap-3">
		<div class="relative flex-1">
			<Search size={16} class="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
			<input
				type="text"
				bind:value={search}
				placeholder="Search peers..."
				class="w-full rounded-lg border border-zinc-200 bg-white py-2 pl-10 pr-4 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none"
			/>
		</div>
		<div class="flex items-center rounded-lg border border-zinc-200 bg-white p-0.5">
			<button
				onclick={() => setView('table')}
				class="rounded-md p-1.5 transition-colors {view === 'table'
					? 'bg-zinc-900 text-white'
					: 'text-zinc-400 hover:text-zinc-600'}"
				title="Table view"
			>
				<List size={16} />
			</button>
			<button
				onclick={() => setView('cards')}
				class="rounded-md p-1.5 transition-colors {view === 'cards'
					? 'bg-zinc-900 text-white'
					: 'text-zinc-400 hover:text-zinc-600'}"
				title="Card view"
			>
				<LayoutGrid size={16} />
			</button>
		</div>
	</div>

	<div class="mt-6">
		{#if view === 'table'}
			<PeerTable peers={filteredPeers} statsMap={$stats} />
		{:else}
			<div class="grid gap-4 sm:grid-cols-1 lg:grid-cols-2">
				{#each filteredPeers as peer (peer.id)}
					<PeerCard {peer} stats={$stats.get(peer.public_key)} />
				{:else}
					<div class="col-span-full py-12 text-center text-zinc-400">
						{search ? 'No peers match your search' : 'No peers yet. Click "Add Peer" to get started.'}
					</div>
				{/each}
			</div>
		{/if}
	</div>
</div>

<CreatePeerModal bind:open={showCreate} />
