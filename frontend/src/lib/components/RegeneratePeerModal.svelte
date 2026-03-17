<script lang="ts">
	import type { Peer, CreatePeerResponse, ServerConfig } from '$lib/api';
	import { api } from '$lib/api';
	import { regeneratePeer } from '$lib/stores/peers';
	import { generateKeyPair } from '$lib/crypto/wireguard-keys';
	import { renderPeerConfig } from '$lib/crypto/render-config';
	import { generateQRCodeDataURL } from '$lib/crypto/qrcode';
	import { X, Download, QrCode, AlertTriangle, RefreshCw } from 'lucide-svelte';

	let { peer = $bindable<Peer | null>(null) }: { peer: Peer | null } = $props();

	let regenerating = $state(false);
	let error = $state('');

	// Post-regeneration state
	let regeneratedPeer = $state<CreatePeerResponse | null>(null);
	let clientPrivateKey = $state<string | null>(null);
	let serverConfig = $state<ServerConfig | null>(null);
	let qrDataURL = $state<string | null>(null);
	let showQR = $state(false);

	function resetState() {
		regenerating = false;
		error = '';
		regeneratedPeer = null;
		clientPrivateKey = null;
		serverConfig = null;
		qrDataURL = null;
		showQR = false;
	}

	function getConfigString(): string | null {
		if (!regeneratedPeer || !clientPrivateKey || !serverConfig) return null;
		return renderPeerConfig({
			privateKey: clientPrivateKey,
			presharedKey: regeneratedPeer.preshared_key || '',
			peer: regeneratedPeer,
			server: serverConfig
		});
	}

	async function handleRegenerate() {
		if (!peer) return;

		regenerating = true;
		error = '';
		try {
			const server = await api.getServer();
			serverConfig = server;

			const keyPair = generateKeyPair();
			clientPrivateKey = keyPair.privateKey;

			const response = await regeneratePeer(peer.id, keyPair.publicKey);
			regeneratedPeer = response;

			const conf = getConfigString();
			if (conf) {
				qrDataURL = await generateQRCodeDataURL(conf);
			}
		} catch (err) {
			clientPrivateKey = null;
			error = err instanceof Error ? err.message : 'Failed to regenerate config';
		} finally {
			regenerating = false;
		}
	}

	function downloadConfig() {
		const conf = getConfigString();
		if (!conf || !regeneratedPeer) return;

		const blob = new Blob([conf], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `${regeneratedPeer.name}.conf`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function handleDismiss() {
		resetState();
		peer = null;
	}
</script>

{#if peer}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 dark:bg-black/60">
		<div class="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl dark:bg-zinc-900">
			{#if regeneratedPeer && clientPrivateKey}
				<!-- Post-regeneration: download/QR -->
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Config Regenerated</h2>
				</div>

				<div class="mt-4 space-y-4">
					<div class="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950">
						<AlertTriangle size={20} class="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
						<p class="text-sm text-amber-800 dark:text-amber-200">
							Save your new configuration now. The private key <strong>cannot be recovered</strong> after you close this dialog. The previous configuration is no longer valid.
						</p>
					</div>

					<div class="rounded-lg border border-zinc-200 bg-zinc-50 p-4 dark:border-zinc-700 dark:bg-zinc-800">
						<dl class="space-y-2 text-sm">
							<div class="flex justify-between">
								<dt class="text-zinc-500 dark:text-zinc-400">Name</dt>
								<dd class="font-medium text-zinc-900 dark:text-zinc-100">{regeneratedPeer.name}</dd>
							</div>
							<div class="flex justify-between">
								<dt class="text-zinc-500 dark:text-zinc-400">Address</dt>
								<dd class="font-mono text-zinc-900 dark:text-zinc-100">{regeneratedPeer.address}</dd>
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
							<img src={qrDataURL} alt="QR Code for {regeneratedPeer.name}" class="h-48 w-48" />
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
				<!-- Confirmation step -->
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Regenerate Config</h2>
					<button
						onclick={handleDismiss}
						class="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
					>
						<X size={20} />
					</button>
				</div>

				<div class="mt-4 space-y-4">
					<div class="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950">
						<AlertTriangle size={20} class="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
						<p class="text-sm text-amber-800 dark:text-amber-200">
							This will generate new keys for <strong>{peer.name}</strong>. The current configuration will stop working immediately.
						</p>
					</div>

					{#if error}
						<p class="text-sm text-red-600 dark:text-red-400">{error}</p>
					{/if}

					<div class="flex justify-end gap-3">
						<button
							onclick={handleDismiss}
							class="rounded-lg px-4 py-2 text-sm font-medium text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
						>
							Cancel
						</button>
						<button
							onclick={handleRegenerate}
							disabled={regenerating}
							class="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
						>
							<RefreshCw size={16} class={regenerating ? 'animate-spin' : ''} />
							{regenerating ? 'Regenerating...' : 'Regenerate'}
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}
