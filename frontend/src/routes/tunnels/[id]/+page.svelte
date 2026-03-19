<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { api, type Tunnel, type TunnelStatus } from '$lib/api';
	import { tunnelStats, tunnelCurrentRates, tunnelRateHistory } from '$lib/stores/tunnel-stats';
	import { formatBytes, formatTimeAgo, formatRate } from '$lib/format';
	import TransferRateChart from '$lib/components/TransferRateChart.svelte';
	import {
		ArrowLeft,
		ArrowDown,
		ArrowUp,
		Power,
		Trash2,
		Download,
		Wifi,
		Clock,
		Pencil,
		X,
		Save
	} from 'lucide-svelte';

	let tunnel = $state<Tunnel | null>(null);
	let loading = $state(true);
	let error = $state('');
	let saving = $state(false);
	let deleting = $state(false);

	// Edit form
	let editing = $state(false);
	let editForm = $state({
		name: '',
		description: '',
		address: '',
		listen_port: 0,
		dns: '',
		mtu: 1420,
		peer_public_key: '',
		peer_endpoint: '',
		peer_allowed_ips: '',
		persistent_keepalive: 25
	});

	const tunnelStatus: TunnelStatus | undefined = $derived(
		tunnel ? $tunnelStats.get(tunnel.id) : undefined
	);
	const connected = $derived(tunnelStatus?.connected ?? false);
	const tunnelRates = $derived(tunnel ? $tunnelCurrentRates.get(tunnel.id) : undefined);
	const tunnelHistory = $derived(tunnel ? $tunnelRateHistory.get(tunnel.id) ?? [] : []);

	async function loadTunnel() {
		loading = true;
		error = '';
		try {
			tunnel = await api.getTunnel(page.params.id as string);
		} catch (e: any) {
			error = e.message || 'Tunnel not found';
		} finally {
			loading = false;
		}
	}

	function startEdit() {
		if (!tunnel) return;
		editForm = {
			name: tunnel.name,
			description: tunnel.description,
			address: tunnel.address,
			listen_port: tunnel.listen_port,
			dns: tunnel.dns,
			mtu: tunnel.mtu,
			peer_public_key: tunnel.peer_public_key,
			peer_endpoint: tunnel.peer_endpoint,
			peer_allowed_ips: tunnel.peer_allowed_ips,
			persistent_keepalive: tunnel.persistent_keepalive
		};
		editing = true;
	}

	function cancelEdit() {
		editing = false;
	}

	async function saveEdit() {
		if (!tunnel) return;
		saving = true;
		try {
			const updated = await api.updateTunnel(tunnel.id, editForm);
			tunnel = updated;
			editing = false;
		} catch (e: any) {
			error = e.message;
		} finally {
			saving = false;
		}
	}

	async function handleToggle() {
		if (!tunnel) return;
		try {
			tunnel = await api.toggleTunnel(tunnel.id);
		} catch (e: any) {
			error = e.message;
		}
	}

	async function handleDelete() {
		if (!tunnel || !confirm(`Delete tunnel "${tunnel.name}"?`)) return;
		deleting = true;
		try {
			await api.deleteTunnel(tunnel.id);
			goto('/tunnels');
		} catch (e: any) {
			error = e.message;
			deleting = false;
		}
	}

	onMount(loadTunnel);
</script>

{#if loading}
	<div class="py-12 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
{:else if error && !tunnel}
	<div class="py-12 text-center">
		<p class="text-zinc-500 dark:text-zinc-400">{error}</p>
		<a href="/tunnels" class="mt-4 inline-flex items-center gap-1 text-sm text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-200">
			<ArrowLeft size={14} /> Back to Tunnels
		</a>
	</div>
{:else if tunnel}
	<!-- Breadcrumb -->
	<div class="mb-6">
		<a href="/tunnels" class="inline-flex items-center gap-1 text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">
			<ArrowLeft size={14} /> Tunnels
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
				<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">{tunnel.name}</h1>
				<p class="text-sm text-zinc-500 dark:text-zinc-400">
					{tunnel.address}
					{#if tunnel.description}
						<span class="mx-1">&middot;</span> {tunnel.description}
					{/if}
					{#if !tunnel.enabled}
						<span class="ml-2 rounded bg-zinc-100 px-1.5 py-0.5 text-xs font-medium text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">Disabled</span>
					{/if}
				</p>
			</div>
		</div>
		<div class="flex items-center gap-1">
			<button
				onclick={handleToggle}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title={tunnel.enabled ? 'Disable' : 'Enable'}
			>
				<Power size={18} class={tunnel.enabled ? 'text-emerald-500' : ''} />
			</button>
			<a
				href={api.getTunnelRemoteConfigURL(tunnel.id)}
				download
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
				title="Download remote config"
			>
				<Download size={18} />
			</a>
			<button
				onclick={handleDelete}
				disabled={deleting}
				class="rounded-lg p-2 text-zinc-400 transition-colors hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400"
				title="Delete tunnel"
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
						{tunnelStatus?.last_handshake ? formatTimeAgo(tunnelStatus.last_handshake) : '-'}
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
						{tunnelStatus ? formatBytes(tunnelStatus.transfer_rx) : '-'}
					</p>
					{#if tunnelRates}
						<p class="text-xs text-blue-500">{formatRate(tunnelRates.rx_rate)}</p>
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
						{tunnelStatus ? formatBytes(tunnelStatus.transfer_tx) : '-'}
					</p>
					{#if tunnelRates}
						<p class="text-xs text-purple-500">{formatRate(tunnelRates.tx_rate)}</p>
					{/if}
				</div>
			</div>
		</div>
	</div>

	<!-- Transfer Rate Chart -->
	<div class="mt-6">
		<TransferRateChart history={tunnelHistory} />
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
						<label for="edit-desc" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Description</label>
						<input
							id="edit-desc"
							type="text"
							bind:value={editForm.description}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-addr" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Address</label>
						<input
							id="edit-addr"
							type="text"
							bind:value={editForm.address}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-port" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Listen Port</label>
						<input
							id="edit-port"
							type="number"
							min="0"
							max="65535"
							bind:value={editForm.listen_port}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
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
						<label for="edit-mtu" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">MTU</label>
						<input
							id="edit-mtu"
							type="number"
							min="1280"
							max="9000"
							bind:value={editForm.mtu}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-ppk" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Peer Public Key</label>
						<input
							id="edit-ppk"
							type="text"
							bind:value={editForm.peer_public_key}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-pep" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Peer Endpoint</label>
						<input
							id="edit-pep"
							type="text"
							bind:value={editForm.peer_endpoint}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
						/>
					</div>
					<div>
						<label for="edit-paips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Peer Allowed IPs</label>
						<input
							id="edit-paips"
							type="text"
							bind:value={editForm.peer_allowed_ips}
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
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{tunnel.address}</p>
				</div>
				{#if tunnel.description}
					<div>
						<p class="text-xs text-zinc-500 dark:text-zinc-400">Description</p>
						<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{tunnel.description}</p>
					</div>
				{/if}
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Listen Port</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{tunnel.listen_port || 'Auto'}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">DNS</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{tunnel.dns || '-'}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">MTU</p>
					<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{tunnel.mtu}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Peer Endpoint</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{tunnel.peer_endpoint || '-'}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Peer Allowed IPs</p>
					<p class="mt-0.5 font-mono text-sm text-zinc-900 dark:text-zinc-100">{tunnel.peer_allowed_ips || '-'}</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Persistent Keepalive</p>
					<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{tunnel.persistent_keepalive}s</p>
				</div>
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Public Key</p>
					<p class="mt-0.5 font-mono text-xs text-zinc-700 dark:text-zinc-300 break-all">{tunnel.public_key}</p>
				</div>
				{#if tunnel.peer_public_key}
					<div>
						<p class="text-xs text-zinc-500 dark:text-zinc-400">Peer Public Key</p>
						<p class="mt-0.5 font-mono text-xs text-zinc-700 dark:text-zinc-300 break-all">{tunnel.peer_public_key}</p>
					</div>
				{/if}
				<div>
					<p class="text-xs text-zinc-500 dark:text-zinc-400">Created</p>
					<p class="mt-0.5 text-sm text-zinc-900 dark:text-zinc-100">{new Date(tunnel.created_at).toLocaleDateString()}</p>
				</div>
			</div>
		{/if}
	</div>
{/if}
