<script lang="ts">
	import { onMount } from 'svelte';
	import { Shield } from 'lucide-svelte';
	import { api } from '$lib/api';
	import { checkAuth } from '$lib/stores/auth';
	import { goto } from '$app/navigation';

	let authInfo = $state<{ oidc_enabled: boolean; local_enabled: boolean } | null>(null);
	let username = $state('');
	let password = $state('');
	let error = $state('');
	let loading = $state(false);

	onMount(async () => {
		try {
			const res = await fetch('/auth/info');
			authInfo = await res.json().then((r) => r.data);
		} catch {
			// Default to showing local login
			authInfo = { oidc_enabled: false, local_enabled: true };
		}
	});

	async function handleLocalLogin(e: Event) {
		e.preventDefault();
		loading = true;
		error = '';
		try {
			const res = await fetch('/auth/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ username, password })
			});
			const json = await res.json();
			if (json.error) {
				error = json.error.message;
			} else {
				await checkAuth();
				goto('/');
			}
		} catch (err) {
			error = 'Login failed';
		} finally {
			loading = false;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-zinc-50">
	<div class="w-full max-w-sm">
		<div class="text-center">
			<div class="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-zinc-900">
				<Shield size={32} class="text-white" />
			</div>
			<h1 class="mt-6 text-2xl font-bold text-zinc-900">WireGuard UI</h1>
			<p class="mt-2 text-zinc-500">Sign in to manage your VPN</p>
		</div>

		{#if authInfo}
			{#if authInfo.local_enabled}
				<form onsubmit={handleLocalLogin} class="mt-8 space-y-4">
					<div>
						<label for="username" class="block text-sm font-medium text-zinc-700">Username</label>
						<input
							id="username"
							type="text"
							bind:value={username}
							required
							autocomplete="username"
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none"
						/>
					</div>
					<div>
						<label for="password" class="block text-sm font-medium text-zinc-700">Password</label>
						<input
							id="password"
							type="password"
							bind:value={password}
							required
							autocomplete="current-password"
							class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none"
						/>
					</div>

					{#if error}
						<p class="text-sm text-red-600">{error}</p>
					{/if}

					<button
						type="submit"
						disabled={loading}
						class="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:opacity-50"
					>
						{loading ? 'Signing in...' : 'Sign in'}
					</button>
				</form>
			{/if}

			{#if authInfo.oidc_enabled}
				{#if authInfo.local_enabled}
					<div class="my-6 flex items-center gap-3">
						<div class="flex-1 border-t border-zinc-200"></div>
						<span class="text-xs text-zinc-400">or</span>
						<div class="flex-1 border-t border-zinc-200"></div>
					</div>
				{/if}

				<a
					href="/auth/login"
					class="mt-{authInfo.local_enabled ? '0' : '8'} inline-flex w-full items-center justify-center rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50"
				>
					Sign in with SSO
				</a>
			{/if}
		{:else}
			<div class="mt-8 flex justify-center">
				<div class="h-6 w-6 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900"></div>
			</div>
		{/if}
	</div>
</div>
