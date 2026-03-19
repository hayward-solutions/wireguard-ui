<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import { checkAuth, user, loading } from '$lib/stores/auth';
	import { initTheme } from '$lib/stores/theme';
	import { sidebarOpen, closeSidebar, toggleSidebar } from '$lib/stores/sidebar';
	import { onMount } from 'svelte';
	import { startStatsStream, stopStatsStream } from '$lib/stores/stats';
	import { startTunnelStatsStream, stopTunnelStatsStream } from '$lib/stores/tunnel-stats';
	import { Menu } from 'lucide-svelte';

	let { children } = $props();

	const isLoginPage = $derived(page.url.pathname === '/login');

	// Swipe-to-close state
	let touchStartX = $state(0);

	onMount(() => {
		initTheme();
		checkAuth();
		return () => {
			stopStatsStream();
			stopTunnelStatsStream();
		};
	});

	// Start/stop stats stream based on auth state
	$effect(() => {
		if ($user) {
			startStatsStream();
			if ($user.role === 'admin') {
				startTunnelStatsStream();
			}
		} else {
			stopStatsStream();
			stopTunnelStatsStream();
		}
	});

	const isProfilePage = $derived(page.url.pathname === '/profile');

	// Redirect to login if not authenticated and not already on login page
	$effect(() => {
		if (!$loading && !$user && !isLoginPage) {
			goto('/login');
		}
	});

	// Enforce MFA setup: redirect to profile if MFA enrollment is required
	$effect(() => {
		if (!$loading && $user?.mfa_setup_required && !isProfilePage && !isLoginPage) {
			goto('/profile');
		}
	});

	// Auto-close sidebar on route change (mobile)
	$effect(() => {
		page.url.pathname;
		closeSidebar();
	});

	function handleTouchStart(e: TouchEvent) {
		touchStartX = e.touches[0].clientX;
	}

	function handleTouchEnd(e: TouchEvent) {
		const deltaX = e.changedTouches[0].clientX - touchStartX;
		if (deltaX < -50 && $sidebarOpen) {
			closeSidebar();
		}
	}
</script>

{#if $loading}
	<div class="flex h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
		<div class="h-8 w-8 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900 dark:border-zinc-600 dark:border-t-zinc-100"></div>
	</div>
{:else if isLoginPage || !$user}
	{@render children()}
{:else}
	<div class="flex h-screen flex-col bg-zinc-50 dark:bg-zinc-950">
		<!-- Mobile header -->
		<div class="flex h-14 shrink-0 items-center gap-3 border-b border-zinc-200 bg-white px-4 lg:hidden dark:border-zinc-700 dark:bg-zinc-900">
			<button
				onclick={() => toggleSidebar()}
				class="rounded-lg p-2 text-zinc-600 transition-colors hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
				aria-label="Toggle navigation"
			>
				<Menu size={20} />
			</button>
			<div class="flex h-7 w-7 items-center justify-center rounded-md bg-zinc-900 text-xs font-bold text-white dark:bg-zinc-100 dark:text-zinc-900">
				W
			</div>
			<span class="text-base font-semibold text-zinc-900 dark:text-zinc-100">WireGuard UI</span>
		</div>

		<!-- Content area -->
		<div class="flex flex-1 overflow-hidden">
			<!-- Backdrop (mobile only) -->
			{#if $sidebarOpen}
				<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
				<div
					class="fixed inset-0 z-30 bg-black/40 lg:hidden"
					onclick={() => closeSidebar()}
				></div>
			{/if}

			<!-- Sidebar wrapper -->
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="fixed inset-y-0 left-0 z-40 w-64 transform transition-transform duration-200 ease-in-out lg:relative lg:translate-x-0
					{$sidebarOpen ? 'translate-x-0' : '-translate-x-full'}"
				ontouchstart={handleTouchStart}
				ontouchend={handleTouchEnd}
			>
				<Sidebar />
			</div>

			<!-- Main content -->
			<main class="flex-1 overflow-auto">
				<div class="mx-auto max-w-6xl p-4 lg:p-8">
					{@render children()}
				</div>
			</main>
		</div>
	</div>
{/if}
