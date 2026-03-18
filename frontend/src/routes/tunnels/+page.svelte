<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TunnelWithStatus } from '$lib/api';
	import { Plus, Trash2, Pencil, X, ToggleLeft, ToggleRight, Download } from 'lucide-svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';

	let tunnels = $state<TunnelWithStatus[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Create/Edit modal
	let showForm = $state(false);
	let editTunnel = $state<TunnelWithStatus | null>(null);
	let form = $state({
		name: '',
		description: '',
		address: '10.100.0.1/30',
		listen_port: 0,
		dns: '',
		mtu: 1420,
		peer_public_key: '',
		peer_endpoint: '',
		peer_allowed_ips: '',
		persistent_keepalive: 25
	});
	let formError = $state('');

	// Delete confirm
	let deleteTunnel = $state<TunnelWithStatus | null>(null);

	// Created tunnel (shown once)
	let createdPSK = $state('');
	let createdPublicKey = $state('');

	async function loadData() {
		try {
			tunnels = await api.listTunnels();
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		editTunnel = null;
		form = {
			name: '', description: '', address: '10.100.0.1/30', listen_port: 0,
			dns: '', mtu: 1420, peer_public_key: '', peer_endpoint: '',
			peer_allowed_ips: '', persistent_keepalive: 25
		};
		formError = '';
		showForm = true;
	}

	function openEdit(t: TunnelWithStatus) {
		editTunnel = t;
		form = {
			name: t.name,
			description: t.description,
			address: t.address,
			listen_port: t.listen_port,
			dns: t.dns,
			mtu: t.mtu,
			peer_public_key: t.peer_public_key,
			peer_endpoint: t.peer_endpoint,
			peer_allowed_ips: t.peer_allowed_ips,
			persistent_keepalive: t.persistent_keepalive
		};
		formError = '';
		showForm = true;
	}

	async function handleSubmit() {
		formError = '';
		try {
			if (editTunnel) {
				await api.updateTunnel(editTunnel.id, form);
			} else {
				const result = await api.createTunnel(form);
				if (result.public_key) {
					createdPublicKey = result.public_key;
				}
				if (result.preshared_key) {
					createdPSK = result.preshared_key;
				}
			}
			showForm = false;
			await loadData();
		} catch (e: any) {
			formError = e.message;
		}
	}

	async function handleToggle(t: TunnelWithStatus) {
		try {
			await api.toggleTunnel(t.id);
			await loadData();
		} catch (e: any) {
			error = e.message;
		}
	}

	async function handleDelete() {
		if (!deleteTunnel) return;
		try {
			await api.deleteTunnel(deleteTunnel.id);
			deleteTunnel = null;
			await loadData();
		} catch (e: any) {
			error = e.message;
		}
	}

	onMount(loadData);
</script>

<div>
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Tunnels</h1>
			<p class="mt-1 text-zinc-500 dark:text-zinc-400">{tunnels.length} tunnel{tunnels.length !== 1 ? 's' : ''} &middot; Each tunnel runs on a separate WireGuard interface</p>
		</div>
		<button
			onclick={openCreate}
			class="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
		>
			<Plus size={16} />
			Add Tunnel
		</button>
	</div>

	{#if error}
		<div class="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{error}</div>
	{/if}

	{#if createdPublicKey || createdPSK}
		<div class="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-800 dark:bg-amber-950">
			<div class="flex items-start justify-between">
				<div class="space-y-2">
					<p class="text-sm text-amber-800 dark:text-amber-200">Tunnel created. Download the remote config from the table below, or copy these keys to configure the other server manually.</p>
					{#if createdPublicKey}
						<div>
							<p class="text-xs font-medium text-amber-800 dark:text-amber-200">This tunnel's public key <span class="font-normal">&mdash; paste into the remote server's tunnel config</span></p>
							<p class="mt-0.5 font-mono text-xs text-amber-700 dark:text-amber-300 select-all">{createdPublicKey}</p>
						</div>
					{/if}
					{#if createdPSK}
						<div>
							<p class="text-xs font-medium text-amber-800 dark:text-amber-200">Pre-shared key <span class="font-normal">&mdash; both ends must use the same key (shown once)</span></p>
							<p class="mt-0.5 font-mono text-xs text-amber-700 dark:text-amber-300 select-all">{createdPSK}</p>
						</div>
					{/if}
				</div>
				<button onclick={() => { createdPSK = ''; createdPublicKey = ''; }} class="ml-4 text-amber-400 hover:text-amber-600 dark:text-amber-500 dark:hover:text-amber-300">
					<X size={16} />
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="mt-8 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
	{:else}
		<div class="mt-6 overflow-hidden rounded-lg border border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Status</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Address</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Remote Endpoint</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Remote Subnets</th>
						<th class="px-4 py-3 text-right font-medium text-zinc-600 dark:text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
					{#each tunnels as t (t.id)}
						<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800 {!t.enabled ? 'opacity-50' : ''}">
							<td class="px-4 py-3">
								{#if t.status?.connected}
									<span class="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
										<span class="h-2 w-2 rounded-full bg-emerald-500"></span>
										Connected
									</span>
								{:else if t.enabled}
									<span class="inline-flex items-center gap-1.5 text-xs font-medium text-amber-600 dark:text-amber-400">
										<span class="h-2 w-2 rounded-full bg-amber-500"></span>
										Waiting
									</span>
								{:else}
									<span class="inline-flex items-center gap-1.5 text-xs font-medium text-zinc-400 dark:text-zinc-500">
										<span class="h-2 w-2 rounded-full bg-zinc-300 dark:bg-zinc-600"></span>
										Disabled
									</span>
								{/if}
							</td>
							<td class="px-4 py-3 font-medium text-zinc-900 dark:text-zinc-100">
								{t.name}
								{#if t.description}
									<span class="block text-xs text-zinc-400 dark:text-zinc-500">{t.description}</span>
								{/if}
							</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">{t.address}</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">{t.peer_endpoint || '-'}</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">{t.peer_allowed_ips || '-'}</td>
							<td class="px-4 py-3">
								<div class="flex items-center justify-end gap-1">
									<a href={api.getTunnelRemoteConfigURL(t.id)} download title="Download remote config"
										class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<Download size={15} />
									</a>
									<button onclick={() => handleToggle(t)} title={t.enabled ? 'Disable' : 'Enable'} class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										{#if t.enabled}
											<ToggleRight size={15} />
										{:else}
											<ToggleLeft size={15} />
										{/if}
									</button>
									<button onclick={() => openEdit(t)} title="Edit" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<Pencil size={15} />
									</button>
									<button onclick={() => (deleteTunnel = t)} title="Delete" class="rounded p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400">
										<Trash2 size={15} />
									</button>
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="6" class="px-4 py-12 text-center text-zinc-400 dark:text-zinc-500">No tunnels configured. Create one to connect to another WireGuard server.</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

<!-- Create/Edit Tunnel Modal -->
{#if showForm}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showForm = false)}>
		<div class="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{editTunnel ? 'Edit' : 'Create'} Tunnel</h2>
				<button onclick={() => (showForm = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if formError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{formError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="mt-4 space-y-4">
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="t-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name <Tooltip text="A friendly name for this tunnel connection" /></label>
						<input id="t-name" type="text" required bind:value={form.name}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="t-addr" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">VPN Address <Tooltip text="Point-to-point address for this end of the tunnel. Use a /30 subnet — the remote end gets the other IP automatically (e.g., .1 here → .2 there)" /></label>
						<input id="t-addr" type="text" required placeholder="10.100.0.1/30" bind:value={form.address}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div>
					<label for="t-desc" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Description <Tooltip text="Optional note to help identify this tunnel's purpose" /></label>
					<input id="t-desc" type="text" bind:value={form.description}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>

				<div class="border-t border-zinc-100 pt-4 dark:border-zinc-800">
					<h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Remote Peer</h3>
				</div>
				{#if editTunnel}
					<div>
						<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">This Tunnel's Public Key <Tooltip text="Give this key to the remote server so it can authenticate this tunnel" /></label>
						<input type="text" readonly value={editTunnel.public_key}
							class="mt-1 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm font-mono text-zinc-500 select-all focus:outline-none dark:border-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-400" />
					</div>
				{/if}
				<div>
					<label for="t-peer-pk" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Public Key <Tooltip text="The WireGuard public key of the remote server. Get this from the remote server's tunnel config, or set up the remote end first using the downloaded config" /></label>
					<input id="t-peer-pk" type="text" placeholder="Remote server's public key" bind:value={form.peer_public_key}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="t-peer-ep" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Endpoint <Tooltip text="The remote server's address in host:port format (e.g., vpn.example.com:51820)" /></label>
						<input id="t-peer-ep" type="text" placeholder="host:port" bind:value={form.peer_endpoint}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="t-peer-ips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Allowed IPs (remote subnets) <Tooltip text="Comma-separated CIDR subnets routed through this tunnel (e.g., 10.1.0.0/24)" /></label>
						<input id="t-peer-ips" type="text" placeholder="10.1.0.0/24, 10.2.0.0/24" bind:value={form.peer_allowed_ips}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>

				<div class="border-t border-zinc-100 pt-4 dark:border-zinc-800">
					<h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Advanced</h3>
				</div>
				<div class="grid grid-cols-3 gap-4">
					<div>
						<label for="t-port" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Listen Port <Tooltip text="Local UDP port for WireGuard to bind to. Use 0 for an ephemeral port (recommended for outbound-only tunnels)" /></label>
						<input id="t-port" type="number" min="0" max="65535" bind:value={form.listen_port}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="t-mtu" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">MTU <Tooltip text="Maximum packet size in bytes. Default 1420 accounts for WireGuard overhead. Lower if you experience connectivity issues" /></label>
						<input id="t-mtu" type="number" min="1280" max="9000" bind:value={form.mtu}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="t-ka" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Keepalive (s) <Tooltip text="Seconds between keepalive packets. Keeps NAT mappings alive for peers behind firewalls. 25s is recommended; 0 disables" /></label>
						<input id="t-ka" type="number" min="0" bind:value={form.persistent_keepalive}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div>
					<label for="t-dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS <Tooltip text="DNS servers for resolving hostnames on the remote network. Leave blank unless the remote side has internal DNS you need to reach" /></label>
					<input id="t-dns" type="text" placeholder="Optional" bind:value={form.dns}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>

				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (showForm = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">{editTunnel ? 'Save' : 'Create'}</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Delete Confirm Modal -->
{#if deleteTunnel}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (deleteTunnel = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Delete Tunnel</h2>
			<p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Are you sure you want to delete <strong>{deleteTunnel.name}</strong>? This will stop the tunnel interface.</p>
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (deleteTunnel = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
				<button onclick={handleDelete}
					class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
			</div>
		</div>
	</div>
{/if}
