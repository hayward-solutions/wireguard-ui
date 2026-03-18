<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type ServerConfig } from '$lib/api';
	import { Copy, Check, RefreshCw } from 'lucide-svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';

	let config = $state<ServerConfig | null>(null);
	let saving = $state(false);
	let applying = $state(false);
	let error = $state('');
	let success = $state('');
	let copiedKey = $state(false);

	onMount(async () => {
		try {
			config = await api.getServer();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load config';
		}
	});

	async function handleSave(e: Event) {
		e.preventDefault();
		if (!config) return;
		saving = true;
		error = '';
		success = '';
		try {
			config = await api.updateServer(config);
			success = 'Configuration saved';
			setTimeout(() => (success = ''), 3000);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to save';
		} finally {
			saving = false;
		}
	}

	async function handleApply() {
		applying = true;
		error = '';
		try {
			await api.applyServer();
			success = 'Configuration applied to WireGuard interface';
			setTimeout(() => (success = ''), 3000);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to apply';
		} finally {
			applying = false;
		}
	}

	function copyPublicKey() {
		if (config?.public_key) {
			navigator.clipboard.writeText(config.public_key);
			copiedKey = true;
			setTimeout(() => (copiedKey = false), 2000);
		}
	}
</script>

<div>
	<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Server Configuration</h1>
	<p class="mt-1 text-zinc-500 dark:text-zinc-400">Manage your WireGuard server settings</p>

	{#if config}
		<div class="mt-8 rounded-xl border border-zinc-200 bg-white p-6 dark:border-zinc-700 dark:bg-zinc-900">
			<div class="mb-6">
				<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Public Key</label>
				<div class="mt-1 flex items-center gap-2">
					<code class="flex-1 rounded-lg bg-zinc-50 px-3 py-2 font-mono text-sm text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
						{config.public_key}
					</code>
					<button
						onclick={copyPublicKey}
						class="rounded-lg p-2 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300"
					>
						{#if copiedKey}
							<Check size={16} class="text-emerald-500" />
						{:else}
							<Copy size={16} />
						{/if}
					</button>
				</div>
			</div>

			<form onsubmit={handleSave} class="space-y-5">
				<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
					<div>
						<label for="endpoint" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Endpoint <Tooltip text="Public hostname or IP where peers connect, including port (e.g., vpn.example.com:51820)" /></label>
						<input
							id="endpoint"
							type="text"
							bind:value={config.endpoint}
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
					<div>
						<label for="listen_port" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Listen Port <Tooltip text="UDP port the WireGuard interface listens on. Default: 51820" /></label>
						<input
							id="listen_port"
							type="number"
							bind:value={config.listen_port}
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
					<div>
						<label for="address" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Address (CIDR) <Tooltip text="The server's VPN IP and subnet (e.g., 10.0.0.1/24). Peers are allocated IPs from this subnet" /></label>
						<input
							id="address"
							type="text"
							bind:value={config.address}
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
					<div>
						<label for="dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS <Tooltip text="Comma-separated DNS servers pushed to peers (e.g., 1.1.1.1, 8.8.8.8)" /></label>
						<input
							id="dns"
							type="text"
							bind:value={config.dns}
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
					<div>
						<label for="mtu" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">MTU <Tooltip text="Maximum packet size. Default 1420 accounts for WireGuard encapsulation overhead" /></label>
						<input
							id="mtu"
							type="number"
							bind:value={config.mtu}
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
				</div>

				<div class="col-span-full border-t border-zinc-100 pt-5 dark:border-zinc-800">
					<h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Peer Defaults</h3>
					<p class="mt-0.5 text-xs text-zinc-400 dark:text-zinc-500">Applied to new peers when not overridden</p>
				</div>

				<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
					<div>
						<label for="default_allowed_ips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Allowed IPs <Tooltip text="Default routes advertised to new peers. Use 0.0.0.0/0, ::/0 to route all traffic through the VPN" /></label>
						<input
							id="default_allowed_ips"
							type="text"
							bind:value={config.default_allowed_ips}
							placeholder="0.0.0.0/0, ::/0"
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
					<div>
						<label for="default_dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS <Tooltip text="Default DNS servers for new peers. Falls back to server DNS if empty" /></label>
						<input
							id="default_dns"
							type="text"
							bind:value={config.default_dns}
							placeholder="Falls back to server DNS if empty"
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
				</div>

				<div class="col-span-full border-t border-zinc-100 pt-5 dark:border-zinc-800">
					<h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Tunnels</h3>
					<p class="mt-0.5 text-xs text-zinc-400 dark:text-zinc-500">Settings for server-to-server tunnel connections</p>
				</div>

				<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
					<div>
						<label for="tunnel_subnet" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Tunnel Subnet <Tooltip text="CIDR range used to auto-allocate /30 point-to-point addresses for tunnels. Each tunnel gets a /30 block from this range." /></label>
						<input
							id="tunnel_subnet"
							type="text"
							bind:value={config.tunnel_subnet}
							placeholder="10.100.0.0/16"
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
						/>
					</div>
				</div>

				<div class="col-span-full border-t border-zinc-100 pt-5 dark:border-zinc-800">
					<h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Hooks</h3>
				</div>

				<div>
					<label for="post_up" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Post Up <Tooltip text="Shell command run after the WireGuard interface starts. Requires ALLOW_CUSTOM_SCRIPTS=true" /></label>
					<input
						id="post_up"
						type="text"
						bind:value={config.post_up}
						placeholder="iptables -A FORWARD ..."
						class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 font-mono text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
					/>
				</div>

				<div>
					<label for="post_down" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Post Down <Tooltip text="Shell command run after the WireGuard interface stops. Used to clean up Post Up changes" /></label>
					<input
						id="post_down"
						type="text"
						bind:value={config.post_down}
						placeholder="iptables -D FORWARD ..."
						class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 font-mono text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
					/>
				</div>

				{#if error}
					<p class="text-sm text-red-600 dark:text-red-400">{error}</p>
				{/if}
				{#if success}
					<p class="text-sm text-emerald-600">{success}</p>
				{/if}

				<div class="flex flex-col gap-3 sm:flex-row sm:justify-end">
					<button
						type="button"
						onclick={handleApply}
						disabled={applying}
						class="inline-flex items-center gap-2 rounded-lg border border-zinc-300 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-600 dark:text-zinc-300 dark:hover:bg-zinc-800"
					>
						<RefreshCw size={16} class={applying ? 'animate-spin' : ''} />
						{applying ? 'Applying...' : 'Apply to Interface'}
					</button>
					<button
						type="submit"
						disabled={saving}
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
					>
						{saving ? 'Saving...' : 'Save'}
					</button>
				</div>
			</form>
		</div>
	{:else if error}
		<div class="mt-8 rounded-xl border border-red-200 bg-red-50 p-6 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{error}</div>
	{:else}
		<div class="mt-8 flex justify-center py-12">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900 dark:border-zinc-600 dark:border-t-zinc-100"></div>
		</div>
	{/if}
</div>
