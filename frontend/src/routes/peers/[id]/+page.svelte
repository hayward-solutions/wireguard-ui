<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, type Peer, type PeerStats } from '$lib/api';
	import { stats, currentRates, rateHistory } from '$lib/stores/stats';
	import { user } from '$lib/stores/auth';
	import { formatBytes, formatTimeAgo, formatRate } from '$lib/format';
	import TransferRateChart from '$lib/components/TransferRateChart.svelte';
	import RegeneratePeerModal from '$lib/components/RegeneratePeerModal.svelte';
	import {
		ArrowLeft,
		ArrowDown,
		ArrowUp,
		Power,
		RefreshCw,
		Trash2,
		Download,
		QrCode,
		Wifi,
		Clock,
		Pencil,
		X,
		Save,
		Globe
	} from 'lucide-svelte';

	let peer = $state<Peer | null>(null);
	let loading = $state(true);
	let error = $state('');
	let saving = $state(false);
	let deleting = $state(false);
	let regeneratePeer = $state<Peer | null>(null);

	// Edit form
	let editing = $state(false);
	let editForm = $state({
		name: '',
		allowed_ips: '',
		dns: '',
		persistent_keepalive: 25
	});

	const peerStats: PeerStats | undefined = $derived(
		peer ? $stats.get(peer.public_key) : undefined
	);
	const connected = $derived(peerStats?.connected ?? false);
	const peerRates = $derived(peer ? $currentRates.get(peer.public_key) : undefined);
	const peerHistory = $derived(peer ? $rateHistory.get(peer.public_key) ?? [] : []);

	async function loadPeer() {
		loading = true;
		error = '';
		try {
			peer = await api.getPeer(page.params.id as string);
		} catch (e: any) {
			error = e.message || 'Peer not found';
		} finally {
			loading = false;
		}
	}

	function startEdit() {
		if (!peer) return;
		editForm = {
			name: peer.name,
			allowed_ips: peer.allowed_ips,
			dns: peer.dns,
			persistent_keepalive: peer.persistent_keepalive
		};
		editing = true;
	}

	function cancelEdit() {
		editing = false;
	}

	async function saveEdit() {
		if (!peer) return;
		saving = true;
		try {
			const updated = await api.updatePeer(peer.id, editForm);
			peer = updated;
			editing = false;
		} catch (e: any) {
			error = e.message;
		} finally {
			saving = false;
		}
	}

	async function handleToggle() {
		if (!peer) return;
		try {
			peer = await api.togglePeer(peer.id);
		} catch (e: any) {
			error = e.message;
		}
	}

	async function handleDelete() {
		if (!peer || !confirm(`Delete peer "${peer.name}"?`)) return;
		deleting = true;
		try {
			await api.deletePeer(peer.id);
			goto('/peers');
		} catch (e: any) {
			error = e.message;
			deleting = false;
		}
	}

	onMount(loadPeer);
</script>

{#if loading}
	<div class="py-12 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
{:else if error && !peer}
	<div class="py-12 text-center">
		<p class="text-zinc-500 dark:text-zinc-400">{error}</p>
		<a href="/peers" class="mt-4 inline-flex items-center gap-1 text-sm text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-200">
			<ArrowLeft size={14} /> Back to Peers
		</a>
	</div>
{:else if peer}
	<!-- Breadcrumb -->
	<div class="mb-6">
		<a href="/peers" class="inline-flex items-center gap-1 text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">
			<ArrowLeft size={14} /> Peers
		</a>
	</div>

	{#if error}
		<div class="mb-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
			{error}
			<button onclick={() => (error = '')} class="ml-2 text-red-400 hover:text-red-600"><X size={14} /></button>
		</div>
	{/if}

	<!-- Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div class="flex items-center gap-3">
			<div
				class="h-3 w-3 rounded-full {connected ? 'bg-emerald-500' : 'bg-zinc-300 dark:bg-zinc-600'}"
				title={connected ? 'Connected' : 'Disconnected'}
			></div>
			<div>
				<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">{peer.name}</h1>
				<p class="text-sm text-zinc-500 dark:text-zinc-400">
					{peer.address}
					{#if !peer.enabled}
						<span class="ml-2 rounded bg-zinc-100 px-1.5 py-0.5 text-xs font-medium text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">Disabled</span>
					{/if}
				</p>
			</div>
		</div>
		<div class="flex items-center gap-1">
			<button
				onclick={handleToggle}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title={peer.enabled ? 'Disable' : 'Enable'}
			>
				<Power size={18} class={peer.enabled ? 'text-emerald-500' : ''} />
			</button>
			<a
				href={api.getConfigURL(peer.id)}
				download
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title="Download config"
			>
				<Download size={18} />
			</a>
			<a
				href={api.getQRCodeURL(peer.id)}
				target="_blank"
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title="QR Code"
			>
				<QrCode size={18} />
			</a>
			<button
				onclick={() => (regeneratePeer = peer)}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title="Regenerate config"
			>
				<RefreshCw size={18} />
			</button>
			<button
				onclick={handleDelete}
				disabled={deleting}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400"
				title="Delete peer"
			>
				<Trash2 size={18} />
			</button>
		</div>
	</div>

	<!-- Stats Cards -->
	<div class="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<div class="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-50 dark:bg-emerald-950">
					<Wifi size={18} class={connected ? 'text-emerald-600' : 'text-zinc-400'} />
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Status</p>
					<p class="text-lg font-semibold {connected ? 'text-emerald-600' : 'text-zinc-400'}">
						{connected ? 'Connected' : 'Disconnected'}
					</p>
				</div>
			</div>
		</div>

		<div class="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-9 w-9 items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800">
					<Clock size={18} class="text-zinc-500" />
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Last Handshake</p>
					<p class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
						{peerStats ? formatTimeAgo(peerStats.last_handshake) : '-'}
					</p>
				</div>
			</div>
		</div>

		<div class="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 dark:bg-blue-950">
					<ArrowDown size={18} class="text-blue-600" />
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Received</p>
					<p class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
						{peerStats ? formatBytes(peerStats.transfer_rx) : '-'}
					</p>
					{#if peerRates}
						<p class="text-xs text-blue-500">{formatRate(peerRates.rx_rate)}</p>
					{/if}
				</div>
			</div>
		</div>

		<div class="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="flex items-center gap-3">
				<div class="flex h-9 w-9 items-center justify-center rounded-lg bg-purple-50 dark:bg-purple-950">
					<ArrowUp size={18} class="text-purple-600" />
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Sent</p>
					<p class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
						{peerStats ? formatBytes(peerStats.transfer_tx) : '-'}
					</p>
					{#if peerRates}
						<p class="text-xs text-purple-500">{formatRate(peerRates.tx_rate)}</p>
					{/if}
				</div>
			</div>
		</div>
	</div>

	<!-- Transfer Rate Chart -->
	<div class="mt-6">
		<TransferRateChart history={peerHistory} />
	</div>

	<!-- Details / Edit -->
	<div class="mt-6 rounded-xl border border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
		<div class="flex items-center justify-between border-b border-zinc-200 px-5 py-3 dark:border-zinc-700">
			<h2 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Configuration</h2>
			{#if !editing}
				<button
					onclick={startEdit}
					class="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-200"
				>
					<Pencil size={14} /> Edit
				</button>
			{/if}
		</div>

		{#if editing}
			<form onsubmit={(e) => { e.preventDefault(); saveEdit(); }} class="space-y-4 p-5">
				<div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
					<div>
						<label for="edit-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name</label>
						<input
							id="edit-name"
							type="text"
							bind:value={editForm.name}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-aips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Allowed IPs</label>
						<input
							id="edit-aips"
							type="text"
							bind:value={editForm.allowed_ips}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS</label>
						<input
							id="edit-dns"
							type="text"
							bind:value={editForm.dns}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-ka" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Persistent Keepalive (s)</label>
						<input
							id="edit-ka"
							type="number"
							min="0"
							bind:value={editForm.persistent_keepalive}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
				</div>
				<div class="flex items-center justify-end gap-3">
					<button
						type="button"
						onclick={cancelEdit}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
					>
						Cancel
					</button>
					<button
						type="submit"
						disabled={saving}
						class="inline-flex items-center gap-1.5 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
					>
						<Save size={14} />
						{saving ? 'Saving...' : 'Save'}
					</button>
				</div>
			</form>
		{:else}
			<div class="grid grid-cols-1 gap-x-8 gap-y-4 p-5 sm:grid-cols-2">
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Address</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{peer.address}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Allowed IPs</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{peer.allowed_ips}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">DNS</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{peer.dns || '-'}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Persistent Keepalive</p>
					<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{peer.persistent_keepalive}s</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Public Key</p>
					<p class="mt-0.5 font-mono text-xs text-zinc-700 dark:text-zinc-300 break-all">{peer.public_key}</p>
				</div>
				{#if $user?.role === 'admin' && peerStats?.endpoint}
					<div>
						<p class="text-xs text-zinc-500 dark:text-zinc-400">Endpoint</p>
						<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{peerStats.endpoint}</p>
					</div>
				{/if}
				{#if $user?.role === 'admin' && peer.created_by_name}
					<div>
						<p class="text-xs text-zinc-500 dark:text-zinc-400">Created By</p>
						<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{peer.created_by_name}</p>
					</div>
				{/if}
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Created</p>
					<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{new Date(peer.created_at).toLocaleDateString()}</p>
				</div>
			</div>
		{/if}
	</div>
{/if}

<RegeneratePeerModal bind:peer={regeneratePeer} />
