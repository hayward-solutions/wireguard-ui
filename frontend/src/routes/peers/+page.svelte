<script lang="ts">
	import { onMount } from 'svelte';
	import { peers, loadPeers } from '$lib/stores/peers';
	import { stats } from '$lib/stores/stats';
	import PeerCard from '$lib/components/PeerCard.svelte';
	import CreatePeerModal from '$lib/components/CreatePeerModal.svelte';
	import { Plus, Search } from 'lucide-svelte';

	let showCreate = $state(false);
	let search = $state('');

	const filteredPeers = $derived(
		$peers.filter(
			(p) =>
				p.name.toLowerCase().includes(search.toLowerCase()) ||
				p.email.toLowerCase().includes(search.toLowerCase()) ||
				p.address.includes(search)
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

	<div class="relative mt-6">
		<Search size={16} class="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
		<input
			type="text"
			bind:value={search}
			placeholder="Search peers..."
			class="w-full rounded-lg border border-zinc-200 bg-white py-2 pl-10 pr-4 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none"
		/>
	</div>

	<div class="mt-6 grid gap-4 sm:grid-cols-1 lg:grid-cols-2">
		{#each filteredPeers as peer (peer.id)}
			<PeerCard {peer} stats={$stats.get(peer.public_key)} />
		{:else}
			<div class="col-span-full py-12 text-center text-zinc-400">
				{search ? 'No peers match your search' : 'No peers yet. Click "Add Peer" to get started.'}
			</div>
		{/each}
	</div>
</div>

<CreatePeerModal bind:open={showCreate} />
