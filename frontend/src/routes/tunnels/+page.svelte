<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type TunnelWithStatus, type ServerConfig } from '$lib/api';
	import { Plus, Trash2, Pencil, X, ToggleLeft, ToggleRight, Download, Copy, Check, ChevronRight, ChevronLeft } from 'lucide-svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';
	import { generateKeyPair, generatePresharedKey } from '$lib/crypto/wireguard-keys';
	import { allocateTunnelAddress } from '$lib/tunnel-alloc';

	let tunnels = $state<TunnelWithStatus[]>([]);
	let serverConfig = $state<ServerConfig | null>(null);
	let loading = $state(true);
	let error = $state('');

	// Wizard state
	let showWizard = $state(false);
	let wizardStep = $state(1);
	let tunnelMode = $state<'create' | 'accept'>('create');
	let wizardError = $state('');

	// Generated keys (created at wizard init)
	let generatedKeys = $state<{ privateKey: string; publicKey: string }>({ privateKey: '', publicKey: '' });
	let generatedPSK = $state('');

	// Clipboard feedback
	let copiedField = $state('');

	// Wizard form fields
	let form = $state({
		name: '',
		description: '',
		peer_endpoint: '',
		peer_public_key: '',
		preshared_key: '',
		address: '',
		peer_allowed_ips: '',
		listen_port: 0,
		mtu: 1420,
		dns: '',
		persistent_keepalive: 25
	});
	let showAdvanced = $state(false);

	// Edit modal (separate from wizard)
	let showEditForm = $state(false);
	let editTunnel = $state<TunnelWithStatus | null>(null);
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
	let editError = $state('');

	// Delete confirm
	let deleteTunnel = $state<TunnelWithStatus | null>(null);

	// Post-creation banner
	let lastMode = $state<'create' | 'accept' | null>(null);
	let createdPublicKey = $state('');
	let createdPSK = $state('');

	async function loadData() {
		try {
			const [t, s] = await Promise.all([api.listTunnels(), api.getServer()]);
			tunnels = t;
			serverConfig = s;
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}

	function copyToClipboard(text: string, field: string) {
		navigator.clipboard.writeText(text);
		copiedField = field;
		setTimeout(() => (copiedField = ''), 2000);
	}

	function openWizard(mode: 'create' | 'accept') {
		tunnelMode = mode;
		wizardStep = 1;
		wizardError = '';
		showAdvanced = false;

		// Generate keys client-side
		generatedKeys = generateKeyPair();
		generatedPSK = mode === 'create' ? generatePresharedKey() : '';

		// Auto-allocate address
		const usedAddrs = tunnels.map((t) => t.address);
		const subnet = serverConfig?.tunnel_subnet || '10.100.0.0/16';
		const autoAddr = allocateTunnelAddress(subnet, usedAddrs, mode) || (mode === 'create' ? '10.100.0.1/30' : '10.100.0.2/30');

		// Auto-populate advertise CIDRs from server config
		const defaultAllowedIPs = serverConfig?.address || '';

		form = {
			name: '',
			description: '',
			peer_endpoint: '',
			peer_public_key: '',
			preshared_key: '',
			address: autoAddr,
			peer_allowed_ips: defaultAllowedIPs,
			listen_port: 0,
			mtu: 1420,
			dns: '',
			persistent_keepalive: 25
		};
		showWizard = true;
	}

	function nextStep() {
		wizardError = '';
		if (wizardStep === 1) {
			if (!form.name.trim()) { wizardError = 'Name is required'; return; }
		}
		if (wizardStep === 2 && tunnelMode === 'accept') {
			if (!form.peer_public_key.trim()) { wizardError = 'Remote public key is required'; return; }
			if (!form.preshared_key.trim()) { wizardError = 'Pre-shared key is required'; return; }
		}
		if (wizardStep < 4) wizardStep++;
	}

	function prevStep() {
		wizardError = '';
		if (wizardStep > 1) wizardStep--;
	}

	async function finishWizard() {
		wizardError = '';
		try {
			const payload: any = {
				name: form.name,
				description: form.description,
				private_key: generatedKeys.privateKey,
				public_key: generatedKeys.publicKey,
				address: form.address,
				listen_port: form.listen_port,
				mtu: form.mtu,
				dns: form.dns,
				peer_public_key: form.peer_public_key,
				peer_endpoint: form.peer_endpoint,
				peer_allowed_ips: form.peer_allowed_ips,
				persistent_keepalive: form.persistent_keepalive,
				preshared_key: tunnelMode === 'create' ? generatedPSK : form.preshared_key
			};

			await api.createTunnel(payload);
			lastMode = tunnelMode;
			createdPublicKey = generatedKeys.publicKey;
			createdPSK = tunnelMode === 'create' ? generatedPSK : '';
			showWizard = false;
			await loadData();
		} catch (e: any) {
			wizardError = e.message;
		}
	}

	function openEdit(t: TunnelWithStatus) {
		editTunnel = t;
		editForm = {
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
		editError = '';
		showEditForm = true;
	}

	async function handleEditSubmit() {
		editError = '';
		if (!editTunnel) return;
		try {
			await api.updateTunnel(editTunnel.id, editForm);
			showEditForm = false;
			await loadData();
		} catch (e: any) {
			editError = e.message;
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

	const stepLabels = ['Basics', 'Keys', 'Network', 'Advanced'];

	onMount(loadData);
</script>

<div>
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Tunnels</h1>
			<p class="mt-1 text-zinc-500 dark:text-zinc-400">{tunnels.length} tunnel{tunnels.length !== 1 ? 's' : ''} &middot; Each tunnel runs on a separate WireGuard interface</p>
		</div>
		<div class="flex flex-col gap-2 sm:flex-row sm:items-center">
			<button
				onclick={() => openWizard('create')}
				class="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
			>
				<Plus size={16} />
				Create Tunnel
			</button>
			<button
				onclick={() => openWizard('accept')}
				class="inline-flex items-center gap-2 rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
			>
				<Plus size={16} />
				Accept Tunnel
			</button>
		</div>
	</div>

	{#if error}
		<div class="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{error}</div>
	{/if}

	{#if createdPublicKey || createdPSK}
		<div class="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-800 dark:bg-amber-950">
			<div class="flex items-start justify-between">
				<div class="space-y-2">
					{#if lastMode === 'accept'}
						<p class="text-sm text-amber-800 dark:text-amber-200">Tunnel created. Copy this server's public key, then go back to the initiating server and paste it into the tunnel's Remote Public Key field.</p>
					{:else}
						<p class="text-sm text-amber-800 dark:text-amber-200">Tunnel created. On the remote server, click <strong>Accept Tunnel</strong> and paste the keys below.</p>
					{/if}
					{#if createdPublicKey}
						<div>
							<p class="text-xs font-medium text-amber-800 dark:text-amber-200">This tunnel's public key</p>
							<p class="mt-0.5 font-mono text-xs text-amber-700 dark:text-amber-300 select-all">{createdPublicKey}</p>
						</div>
					{/if}
					{#if createdPSK}
						<div>
							<p class="text-xs font-medium text-amber-800 dark:text-amber-200">Pre-shared key <span class="font-normal">&mdash; shown once</span></p>
							<p class="mt-0.5 font-mono text-xs text-amber-700 dark:text-amber-300 select-all">{createdPSK}</p>
						</div>
					{/if}
				</div>
				<button onclick={() => { createdPSK = ''; createdPublicKey = ''; lastMode = null; }} class="ml-4 text-amber-400 hover:text-amber-600 dark:text-amber-500 dark:hover:text-amber-300">
					<X size={16} />
				</button>
			</div>
		</div>
	{/if}

	{#if loading}
		<div class="mt-8 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
	{:else}
		<div class="mt-6 overflow-hidden rounded-lg border border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
			<div class="overflow-x-auto">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Status</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Address</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Remote Endpoint</th>
						<th class="hidden px-4 py-3 font-medium text-zinc-600 md:table-cell dark:text-zinc-400">Remote Subnets</th>
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
								<a href="/tunnels/{t.id}" class="hover:underline">{t.name}</a>
								{#if t.description}
									<span class="block text-xs text-zinc-400 dark:text-zinc-500">{t.description}</span>
								{/if}
							</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">{t.address}</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">{t.peer_endpoint || '-'}</td>
							<td class="hidden px-4 py-3 font-mono text-xs text-zinc-700 md:table-cell dark:text-zinc-300">{t.peer_allowed_ips || '-'}</td>
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
		</div>
	{/if}
</div>

<!-- Wizard Modal -->
{#if showWizard}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showWizard = false)}>
		<div class="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<!-- Header -->
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{tunnelMode === 'accept' ? 'Accept' : 'Create'} Tunnel</h2>
				<button onclick={() => (showWizard = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>

			<!-- Step indicator -->
			<div class="mt-4 flex items-center gap-1">
				{#each stepLabels as label, i}
					<div class="flex items-center gap-1 {i > 0 ? 'ml-1' : ''}">
						{#if i > 0}
							<div class="h-px w-4 {i < wizardStep ? 'bg-zinc-900 dark:bg-zinc-100' : 'bg-zinc-200 dark:bg-zinc-700'}"></div>
						{/if}
						<span class="text-xs font-medium {i + 1 === wizardStep ? 'text-zinc-900 dark:text-zinc-100' : i + 1 < wizardStep ? 'text-zinc-500 dark:text-zinc-400' : 'text-zinc-300 dark:text-zinc-600'}">{i + 1}. {label}</span>
					</div>
				{/each}
			</div>

			{#if wizardError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{wizardError}</div>
			{/if}

			<div class="mt-4 space-y-4">
				<!-- Step 1: Basics -->
				{#if wizardStep === 1}
					<div>
						<label for="w-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name <Tooltip text="A friendly name for this tunnel connection" /></label>
						<input id="w-name" type="text" bind:value={form.name} placeholder="e.g., office-to-datacenter"
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="w-desc" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Description <Tooltip text="Optional note to help identify this tunnel's purpose" /></label>
						<input id="w-desc" type="text" bind:value={form.description}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="w-ep" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Remote Endpoint <Tooltip text="The remote server's address in host:port format (e.g., vpn.example.com:51820). Can be added later." /></label>
						<input id="w-ep" type="text" placeholder="host:port" bind:value={form.peer_endpoint}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>

				<!-- Step 2: Key Exchange -->
				{:else if wizardStep === 2}
					{#if tunnelMode === 'create'}
						<div class="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-700 dark:bg-zinc-800/50">
							<p class="text-xs text-zinc-500 dark:text-zinc-400">Copy these keys and paste them into the <strong>Accept Tunnel</strong> wizard on the remote server.</p>
						</div>
						<div>
							<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">This Tunnel's Public Key</label>
							<div class="mt-1 flex items-center gap-2">
								<input type="text" readonly value={generatedKeys.publicKey}
									class="w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm font-mono text-zinc-600 select-all focus:outline-none dark:border-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-400" />
								<button type="button" onclick={() => copyToClipboard(generatedKeys.publicKey, 'pubkey')} class="rounded-lg p-2 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
									{#if copiedField === 'pubkey'}<Check size={16} class="text-emerald-500" />{:else}<Copy size={16} />{/if}
								</button>
							</div>
						</div>
						<div>
							<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Pre-Shared Key <span class="font-normal text-zinc-400">&mdash; both servers must use the same key</span></label>
							<div class="mt-1 flex items-center gap-2">
								<input type="text" readonly value={generatedPSK}
									class="w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm font-mono text-zinc-600 select-all focus:outline-none dark:border-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-400" />
								<button type="button" onclick={() => copyToClipboard(generatedPSK, 'psk')} class="rounded-lg p-2 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
									{#if copiedField === 'psk'}<Check size={16} class="text-emerald-500" />{:else}<Copy size={16} />{/if}
								</button>
							</div>
						</div>
						<div>
							<label for="w-rpk" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Remote Public Key <span class="text-zinc-400 font-normal">(optional &mdash; add after accept)</span></label>
							<input id="w-rpk" type="text" placeholder="Paste after running Accept Tunnel on the remote" bind:value={form.peer_public_key}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
					{:else}
						<!-- Accept mode -->
						<div class="rounded-lg border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-700 dark:bg-zinc-800/50">
							<p class="text-xs text-zinc-500 dark:text-zinc-400">Paste the public key and pre-shared key from the <strong>Create Tunnel</strong> wizard on the remote server.</p>
						</div>
						<div>
							<label for="w-rpk" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Remote Public Key <span class="text-red-500">*</span></label>
							<input id="w-rpk" type="text" placeholder="Paste the public key from the creating server" bind:value={form.peer_public_key}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
						<div>
							<label for="w-psk" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Pre-Shared Key <span class="text-red-500">*</span></label>
							<input id="w-psk" type="text" placeholder="Paste the PSK from the creating server" bind:value={form.preshared_key}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
						<div>
							<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">This Tunnel's Public Key <span class="font-normal text-zinc-400">&mdash; copy back to the creating server</span></label>
							<div class="mt-1 flex items-center gap-2">
								<input type="text" readonly value={generatedKeys.publicKey}
									class="w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm font-mono text-zinc-600 select-all focus:outline-none dark:border-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-400" />
								<button type="button" onclick={() => copyToClipboard(generatedKeys.publicKey, 'pubkey')} class="rounded-lg p-2 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
									{#if copiedField === 'pubkey'}<Check size={16} class="text-emerald-500" />{:else}<Copy size={16} />{/if}
								</button>
							</div>
						</div>
					{/if}

				<!-- Step 3: Network -->
				{:else if wizardStep === 3}
					<div>
						<label for="w-addr" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">VPN Address <Tooltip text="Point-to-point address for this end of the tunnel. Auto-allocated from the tunnel subnet range in server settings." /></label>
						<input id="w-addr" type="text" bind:value={form.address}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="w-aips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Advertise CIDRs <Tooltip text="Subnets on this server that should be reachable through the tunnel. Defaults to this server's VPN subnet." /></label>
						<input id="w-aips" type="text" placeholder="10.0.0.0/24" bind:value={form.peer_allowed_ips}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>

				<!-- Step 4: Advanced -->
				{:else if wizardStep === 4}
					<div class="grid grid-cols-2 gap-4">
						<div>
							<label for="w-port" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Listen Port <Tooltip text="Local UDP port. Use 0 for ephemeral (recommended for outbound-only)" /></label>
							<input id="w-port" type="number" min="0" max="65535" bind:value={form.listen_port}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
						<div>
							<label for="w-mtu" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">MTU <Tooltip text="Maximum packet size. Default 1420." /></label>
							<input id="w-mtu" type="number" min="1280" max="9000" bind:value={form.mtu}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
					</div>
					<div class="grid grid-cols-2 gap-4">
						<div>
							<label for="w-ka" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Keepalive (s) <Tooltip text="25s recommended. 0 disables." /></label>
							<input id="w-ka" type="number" min="0" bind:value={form.persistent_keepalive}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
						<div>
							<label for="w-dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS <Tooltip text="DNS for the remote network. Usually leave blank." /></label>
							<input id="w-dns" type="text" placeholder="Optional" bind:value={form.dns}
								class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
						</div>
					</div>
				{/if}
			</div>

			<!-- Navigation -->
			<div class="mt-6 flex items-center justify-between">
				<div>
					{#if wizardStep > 1}
						<button type="button" onclick={prevStep}
							class="inline-flex items-center gap-1 rounded-lg border border-zinc-200 px-3 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">
							<ChevronLeft size={16} /> Back
						</button>
					{/if}
				</div>
				<div class="flex items-center gap-3">
					<button type="button" onclick={() => (showWizard = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					{#if wizardStep < 4}
						<button type="button" onclick={nextStep}
							class="inline-flex items-center gap-1 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">
							Next <ChevronRight size={16} />
						</button>
					{:else}
						<button type="button" onclick={finishWizard}
							class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">
							{tunnelMode === 'accept' ? 'Accept' : 'Create'} Tunnel
						</button>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Edit Tunnel Modal -->
{#if showEditForm && editTunnel}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showEditForm = false)}>
		<div class="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Edit Tunnel</h2>
				<button onclick={() => (showEditForm = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if editError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{editError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleEditSubmit(); }} class="mt-4 space-y-4">
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="e-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name</label>
						<input id="e-name" type="text" required bind:value={editForm.name}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="e-addr" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">VPN Address</label>
						<input id="e-addr" type="text" required bind:value={editForm.address}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div>
					<label for="e-desc" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Description</label>
					<input id="e-desc" type="text" bind:value={editForm.description}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>
				<div class="border-t border-zinc-100 pt-4 dark:border-zinc-800">
					<h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Remote Peer</h3>
				</div>
				<div>
					<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">This Tunnel's Public Key</label>
					<input type="text" readonly value={editTunnel.public_key}
						class="mt-1 w-full rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm font-mono text-zinc-500 select-all focus:outline-none dark:border-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-400" />
				</div>
				<div>
					<label for="e-peer-pk" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Remote Public Key</label>
					<input id="e-peer-pk" type="text" bind:value={editForm.peer_public_key}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="e-peer-ep" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Endpoint</label>
						<input id="e-peer-ep" type="text" placeholder="host:port" bind:value={editForm.peer_endpoint}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="e-peer-ips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Allowed IPs</label>
						<input id="e-peer-ips" type="text" bind:value={editForm.peer_allowed_ips}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div class="border-t border-zinc-100 pt-4 dark:border-zinc-800">
					<h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Advanced</h3>
				</div>
				<div class="grid grid-cols-3 gap-4">
					<div>
						<label for="e-port" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Listen Port</label>
						<input id="e-port" type="number" min="0" max="65535" bind:value={editForm.listen_port}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="e-mtu" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">MTU</label>
						<input id="e-mtu" type="number" min="1280" max="9000" bind:value={editForm.mtu}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="e-ka" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Keepalive (s)</label>
						<input id="e-ka" type="number" min="0" bind:value={editForm.persistent_keepalive}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div>
					<label for="e-dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS</label>
					<input id="e-dns" type="text" placeholder="Optional" bind:value={editForm.dns}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (showEditForm = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Save</button>
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
