<script lang="ts">
	import { createPeer } from '$lib/stores/peers';
	import { api, type CreatePeerResponse, type ServerConfig } from '$lib/api';
	import { generateKeyPair } from '$lib/crypto/wireguard-keys';
	import { renderPeerConfig } from '$lib/crypto/render-config';
	import { generateQRCodeDataURL } from '$lib/crypto/qrcode';
	import { X, ChevronDown, ChevronUp, Download, QrCode, AlertTriangle } from 'lucide-svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();

	// Step 1: create form
	let name = $state('');
	let allowedIPs = $state('');
	let dns = $state('');
	let creating = $state(false);
	let error = $state('');
	let showAdvanced = $state(false);
	let defaultsLoaded = $state(false);

	// Step 2: one-time download
	let createdPeer = $state<CreatePeerResponse | null>(null);
	let clientPrivateKey = $state<string | null>(null);
	let serverConfig = $state<ServerConfig | null>(null);
	let qrDataURL = $state<string | null>(null);
	let showQR = $state(false);

	// Load server defaults when modal opens
	$effect(() => {
		if (open && !defaultsLoaded) {
			api.getServer().then((server) => {
				serverConfig = server;
				allowedIPs = server.default_allowed_ips || '0.0.0.0/0, ::/0';
				dns = server.default_dns || '';
				defaultsLoaded = true;
			}).catch(() => {
				allowedIPs = '0.0.0.0/0, ::/0';
				defaultsLoaded = true;
			});
		}
		if (!open) {
			resetState();
		}
	});

	function resetState() {
		name = '';
		allowedIPs = '';
		dns = '';
		showAdvanced = false;
		defaultsLoaded = false;
		createdPeer = null;
		clientPrivateKey = null;
		qrDataURL = null;
		showQR = false;
		error = '';
	}

	function getConfigString(): string | null {
		if (!createdPeer || !clientPrivateKey || !serverConfig) return null;
		return renderPeerConfig({
			privateKey: clientPrivateKey,
			presharedKey: createdPeer.preshared_key || '',
			peer: createdPeer,
			server: serverConfig
		});
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!name.trim()) return;

		creating = true;
		error = '';
		try {
			// Generate keys client-side
			const keyPair = generateKeyPair();
			clientPrivateKey = keyPair.privateKey;

			const response = await createPeer(
				name.trim(),
				allowedIPs.trim(),
				dns.trim(),
				keyPair.publicKey
			);
			createdPeer = response;

			// Pre-generate QR code data URL
			const conf = getConfigString();
			if (conf) {
				qrDataURL = await generateQRCodeDataURL(conf);
			}
		} catch (err) {
			clientPrivateKey = null;
			error = err instanceof Error ? err.message : 'Failed to create peer';
		} finally {
			creating = false;
		}
	}

	function downloadConfig() {
		const conf = getConfigString();
		if (!conf || !createdPeer) return;

		const blob = new Blob([conf], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `${createdPeer.name}.conf`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function handleDismiss() {
		// Discard the private key and close
		clientPrivateKey = null;
		createdPeer = null;
		qrDataURL = null;
		open = false;
	}
</script>

{#if open}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 dark:bg-black/60">
		<div class="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl dark:bg-zinc-900">
			{#if createdPeer && clientPrivateKey}
				<!-- Step 2: One-time config download -->
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Peer Created</h2>
				</div>

				<div class="mt-4 space-y-4">
					<div class="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950">
						<AlertTriangle size={20} class="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
						<p class="text-sm text-amber-800 dark:text-amber-200">
							Save your configuration now. The private key is generated in your browser and <strong>cannot be recovered</strong> after you close this dialog.
						</p>
					</div>

					<div class="rounded-lg border border-zinc-200 bg-zinc-50 p-4 dark:border-zinc-700 dark:bg-zinc-800">
						<dl class="space-y-2 text-sm">
							<div class="flex justify-between">
								<dt class="text-zinc-500 dark:text-zinc-400">Name</dt>
								<dd class="font-medium text-zinc-900 dark:text-zinc-100">{createdPeer.name}</dd>
							</div>
							<div class="flex justify-between">
								<dt class="text-zinc-500 dark:text-zinc-400">Address</dt>
								<dd class="font-mono text-zinc-900 dark:text-zinc-100">{createdPeer.address}</dd>
							</div>
						</dl>
					</div>

					<div class="flex gap-2">
						<button
							onclick={downloadConfig}
							class="flex flex-1 items-center justify-center gap-2 rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
						>
							<Download size={16} />
							Download Config
						</button>
						<button
							onclick={() => (showQR = !showQR)}
							class="flex items-center justify-center gap-2 rounded-lg border border-zinc-300 px-4 py-2.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-600 dark:text-zinc-300 dark:hover:bg-zinc-800"
						>
							<QrCode size={16} />
							QR Code
						</button>
					</div>

					{#if showQR && qrDataURL}
						<div class="flex justify-center rounded-lg border border-zinc-100 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-800">
							<img src={qrDataURL} alt="QR Code for {createdPeer.name}" class="h-48 w-48" />
						</div>
					{/if}

					<button
						onclick={handleDismiss}
						class="w-full rounded-lg px-4 py-2 text-sm text-zinc-500 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-300"
					>
						I've saved my configuration
					</button>
				</div>
			{:else}
				<!-- Step 1: Create peer form -->
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Add Peer</h2>
					<button
						onclick={() => (open = false)}
						class="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
					>
						<X size={20} />
					</button>
				</div>

				<form onsubmit={handleSubmit} class="mt-5 space-y-4">
					<div>
						<label for="name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name <Tooltip text="A friendly name to identify this peer device (e.g., &quot;Office laptop&quot;)" /></label>
						<input
							id="name"
							type="text"
							bind:value={name}
							placeholder="e.g. Office laptop"
							required
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>

					<button
						type="button"
						onclick={() => (showAdvanced = !showAdvanced)}
						class="flex items-center gap-1 text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-300"
					>
						{#if showAdvanced}
							<ChevronUp size={14} />
						{:else}
							<ChevronDown size={14} />
						{/if}
						Advanced options
					</button>

					{#if showAdvanced}
						<div class="space-y-4 rounded-lg border border-zinc-100 bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-800">
							<div>
								<label for="allowed_ips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Allowed IPs <Tooltip text="CIDR subnets this peer can access. Use 0.0.0.0/0, ::/0 for full tunnel" /></label>
								<input
									id="allowed_ips"
									type="text"
									bind:value={allowedIPs}
									placeholder="0.0.0.0/0, ::/0"
									class="mt-1 w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
								/>
							</div>
							<div>
								<label for="dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS <Tooltip text="DNS servers for this peer. Uses server DNS if left empty" /></label>
								<input
									id="dns"
									type="text"
									bind:value={dns}
									placeholder="Uses server DNS if empty"
									class="mt-1 w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
								/>
							</div>
						</div>
					{/if}

					{#if error}
						<p class="text-sm text-red-600 dark:text-red-400">{error}</p>
					{/if}

					<div class="flex justify-end gap-3 pt-2">
						<button
							type="button"
							onclick={() => (open = false)}
							class="rounded-lg px-4 py-2 text-sm font-medium text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
						>
							Cancel
						</button>
						<button
							type="submit"
							disabled={creating || !name.trim()}
							class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
						>
							{creating ? 'Creating...' : 'Create Peer'}
						</button>
					</div>
				</form>
			{/if}
		</div>
	</div>
{/if}
