<script lang="ts">
	import { createPeer } from '$lib/stores/peers';
	import { api } from '$lib/api';
	import { X, ChevronDown, ChevronUp } from 'lucide-svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();

	let name = $state('');
	let allowedIPs = $state('');
	let dns = $state('');
	let creating = $state(false);
	let error = $state('');
	let showAdvanced = $state(false);
	let defaultsLoaded = $state(false);

	// Load server defaults when modal opens
	$effect(() => {
		if (open && !defaultsLoaded) {
			api.getServer().then((server) => {
				allowedIPs = server.default_allowed_ips || '0.0.0.0/0, ::/0';
				dns = server.default_dns || '';
				defaultsLoaded = true;
			}).catch(() => {
				allowedIPs = '0.0.0.0/0, ::/0';
				defaultsLoaded = true;
			});
		}
		if (!open) {
			defaultsLoaded = false;
		}
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!name.trim()) return;

		creating = true;
		error = '';
		try {
			await createPeer(name.trim(), allowedIPs.trim(), dns.trim());
			name = '';
			allowedIPs = '';
			dns = '';
			showAdvanced = false;
			defaultsLoaded = false;
			open = false;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to create peer';
		} finally {
			creating = false;
		}
	}
</script>

{#if open}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 dark:bg-black/60">
		<div class="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl dark:bg-zinc-900">
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
					<label for="name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name</label>
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
							<label for="allowed_ips" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Allowed IPs</label>
							<input
								id="allowed_ips"
								type="text"
								bind:value={allowedIPs}
								placeholder="0.0.0.0/0, ::/0"
								class="mt-1 w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-900 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
							/>
							<p class="mt-1 text-xs text-zinc-400 dark:text-zinc-500">Routes to advertise to this peer</p>
						</div>
						<div>
							<label for="dns" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">DNS</label>
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
		</div>
	</div>
{/if}
