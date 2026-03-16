<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import { checkAuth, user, loading } from '$lib/stores/auth';
	import { onMount } from 'svelte';
	import { startStatsStream, stopStatsStream } from '$lib/stores/stats';

	let { children } = $props();

	const isLoginPage = $derived(page.url.pathname === '/login');

	onMount(() => {
		checkAuth();
		return () => stopStatsStream();
	});

	// Start/stop stats stream based on auth state
	$effect(() => {
		if ($user) {
			startStatsStream();
		} else {
			stopStatsStream();
		}
	});

	// Redirect to login if not authenticated and not already on login page
	$effect(() => {
		if (!$loading && !$user && !isLoginPage) {
			goto('/login');
		}
	});
</script>

{#if $loading}
	<div class="flex h-screen items-center justify-center bg-zinc-50">
		<div class="h-8 w-8 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900"></div>
	</div>
{:else if isLoginPage || !$user}
	{@render children()}
{:else}
	<div class="flex h-screen bg-zinc-50">
		<Sidebar />
		<main class="flex-1 overflow-auto">
			<div class="mx-auto max-w-6xl p-8">
				{@render children()}
			</div>
		</main>
	</div>
{/if}
