<script lang="ts">
	import { page } from '$app/state';
	import { LayoutDashboard, Users, Server, ShieldCheck, LogOut } from 'lucide-svelte';
	import { logout, user } from '$lib/stores/auth';
	import { get } from 'svelte/store';

	const baseLinks = [
		{ href: '/', label: 'Dashboard', icon: LayoutDashboard },
		{ href: '/peers', label: 'Peers', icon: Users },
		{ href: '/server', label: 'Server', icon: Server }
	];

	const links = $derived(
		get(user)?.role === 'admin'
			? [...baseLinks, { href: '/users', label: 'Users', icon: ShieldCheck }]
			: baseLinks
	);
</script>

<aside class="flex h-full w-64 flex-col border-r border-zinc-200 bg-white">
	<div class="flex h-16 items-center gap-3 border-b border-zinc-200 px-6">
		<div class="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white">
			W
		</div>
		<span class="text-lg font-semibold text-zinc-900">WireGuard UI</span>
	</div>

	<nav class="flex-1 space-y-1 px-3 py-4">
		{#each links as link}
			{@const active = page.url.pathname === link.href || (link.href !== '/' && page.url.pathname.startsWith(link.href))}
			<a
				href={link.href}
				class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors
					{active ? 'bg-zinc-100 text-zinc-900' : 'text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900'}"
			>
				<link.icon size={18} />
				{link.label}
			</a>
		{/each}
	</nav>

	<div class="border-t border-zinc-200 p-3">
		<button
			onclick={() => logout()}
			class="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-zinc-600 transition-colors hover:bg-zinc-50 hover:text-zinc-900"
		>
			<LogOut size={18} />
			Sign out
		</button>
	</div>
</aside>
