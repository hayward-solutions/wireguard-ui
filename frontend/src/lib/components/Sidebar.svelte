<script lang="ts">
	import { page } from '$app/state';
	import { LayoutDashboard, Users, Server, ShieldCheck, CircleUser, LogOut, Sun, Moon, Monitor, UsersRound, Shield, Cable } from 'lucide-svelte';
	import { logout, user } from '$lib/stores/auth';
	import { theme, cycleTheme } from '$lib/stores/theme';
	import { closeSidebar } from '$lib/stores/sidebar';
	import { get } from 'svelte/store';

	const baseLinks = [
		{ href: '/', label: 'Dashboard', icon: LayoutDashboard },
		{ href: '/peers', label: 'Peers', icon: Users },
		{ href: '/server', label: 'Server', icon: Server },
		{ href: '/profile', label: 'Profile', icon: CircleUser }
	];

	const adminLinks = [
		{ href: '/tunnels', label: 'Tunnels', icon: Cable },
		{ href: '/users', label: 'Users', icon: ShieldCheck },
		{ href: '/groups', label: 'Groups', icon: UsersRound },
		{ href: '/acls', label: 'ACL Rules', icon: Shield }
	];

	const links = $derived(
		get(user)?.role === 'admin'
			? [...baseLinks, ...adminLinks]
			: baseLinks
	);

	const themeIcon = $derived(
		$theme === 'light' ? Sun : $theme === 'dark' ? Moon : Monitor
	);

	const themeLabel = $derived(
		$theme === 'light' ? 'Light' : $theme === 'dark' ? 'Dark' : 'System'
	);
</script>

<aside class="flex h-full w-64 flex-col border-r border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
	<div class="flex h-16 items-center gap-3 border-b border-zinc-200 px-6 dark:border-zinc-700">
		<div class="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white dark:bg-zinc-100 dark:text-zinc-900">
			W
		</div>
		<span class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">WireGuard UI</span>
	</div>

	<nav class="flex-1 space-y-1 px-3 py-4">
		{#each links as link}
			{@const active = page.url.pathname === link.href || (link.href !== '/' && page.url.pathname.startsWith(link.href))}
			<a
				href={link.href}
				onclick={() => closeSidebar()}
				class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors
					{active ? 'bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-100' : 'text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100'}"
			>
				<link.icon size={18} />
				{link.label}
			</a>
		{/each}
	</nav>

	<div class="border-t border-zinc-200 p-3 dark:border-zinc-700">
		<button
			onclick={() => cycleTheme()}
			class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-zinc-600 transition-colors hover:bg-zinc-50 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
		>
			<svelte:component this={themeIcon} size={18} />
			{themeLabel}
		</button>
		<button
			onclick={() => logout()}
			class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-zinc-600 transition-colors hover:bg-zinc-50 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
		>
			<LogOut size={18} />
			Sign out
		</button>
	</div>
</aside>
