<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type Group, type User } from '$lib/api';
	import { Plus, Trash2, Pencil, X, Users } from 'lucide-svelte';

	let groups = $state<Group[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Create modal
	let showCreate = $state(false);
	let createName = $state('');
	let createError = $state('');

	// Edit modal
	let editGroup = $state<Group | null>(null);
	let editName = $state('');
	let editError = $state('');

	// Delete confirm
	let deleteGroup = $state<Group | null>(null);

	// Members modal
	let membersGroup = $state<Group | null>(null);
	let members = $state<User[]>([]);
	let membersLoading = $state(false);

	async function loadGroups() {
		try {
			groups = await api.listGroups();
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}

	async function handleCreate() {
		createError = '';
		try {
			await api.createGroup({ name: createName });
			showCreate = false;
			createName = '';
			await loadGroups();
		} catch (e: any) {
			createError = e.message;
		}
	}

	function openEdit(g: Group) {
		editGroup = g;
		editName = g.name;
		editError = '';
	}

	async function handleEdit() {
		if (!editGroup) return;
		editError = '';
		try {
			await api.updateGroup(editGroup.id, { name: editName });
			editGroup = null;
			await loadGroups();
		} catch (e: any) {
			editError = e.message;
		}
	}

	async function handleDelete() {
		if (!deleteGroup) return;
		try {
			await api.deleteGroup(deleteGroup.id);
			deleteGroup = null;
			await loadGroups();
		} catch (e: any) {
			error = e.message;
		}
	}

	async function openMembers(g: Group) {
		membersGroup = g;
		membersLoading = true;
		try {
			members = await api.getGroupMembers(g.id);
		} catch (e: any) {
			error = e.message;
		} finally {
			membersLoading = false;
		}
	}

	onMount(loadGroups);
</script>

<div>
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Groups</h1>
			<p class="mt-1 text-zinc-500 dark:text-zinc-400">{groups.length} group{groups.length !== 1 ? 's' : ''}</p>
		</div>
		<button
			onclick={() => (showCreate = true)}
			class="inline-flex items-center gap-2 self-start rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 sm:self-auto dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
		>
			<Plus size={16} />
			Add Group
		</button>
	</div>

	{#if error}
		<div class="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{error}</div>
	{/if}

	{#if loading}
		<div class="mt-8 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
	{:else}
		<div class="mt-6 overflow-hidden rounded-lg border border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
			<div class="overflow-x-auto">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Source</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Created</th>
						<th class="px-4 py-3 text-right font-medium text-zinc-600 dark:text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
					{#each groups as g (g.id)}
						<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800">
							<td class="px-4 py-3 font-medium text-zinc-900 dark:text-zinc-100">{g.name}</td>
							<td class="px-4 py-3">
								<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium
									{g.source === 'oidc' ? 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200' : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'}">
									{g.source}
								</span>
							</td>
							<td class="px-4 py-3 text-zinc-500 dark:text-zinc-400">{new Date(g.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-3">
								<div class="flex items-center justify-end gap-1">
									<button onclick={() => openMembers(g)} title="Members" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<Users size={15} />
									</button>
									<button onclick={() => openEdit(g)} title="Edit" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<Pencil size={15} />
									</button>
									<button onclick={() => (deleteGroup = g)} title="Delete" class="rounded p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400">
										<Trash2 size={15} />
									</button>
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="4" class="px-4 py-12 text-center text-zinc-400 dark:text-zinc-500">No groups found</td>
						</tr>
					{/each}
				</tbody>
			</table>
			</div>
		</div>
	{/if}
</div>

<!-- Create Group Modal -->
{#if showCreate}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showCreate = false)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Create Group</h2>
				<button onclick={() => (showCreate = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if createError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{createError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }} class="mt-4 space-y-4">
				<div>
					<label for="g-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name</label>
					<input id="g-name" type="text" required bind:value={createName}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (showCreate = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Create</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Edit Group Modal -->
{#if editGroup}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (editGroup = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Edit Group</h2>
				<button onclick={() => (editGroup = null)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if editError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{editError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleEdit(); }} class="mt-4 space-y-4">
				<div>
					<label for="eg-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name</label>
					<input id="eg-name" type="text" required bind:value={editName}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (editGroup = null)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Save</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Members Modal -->
{#if membersGroup}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (membersGroup = null)}>
		<div class="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Members of {membersGroup.name}</h2>
				<button onclick={() => (membersGroup = null)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if membersLoading}
				<div class="mt-4 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
			{:else if members.length === 0}
				<p class="mt-4 text-sm text-zinc-500 dark:text-zinc-400">No members in this group.</p>
			{:else}
				<div class="mt-4 max-h-64 overflow-y-auto">
					<table class="w-full text-left text-sm">
						<thead class="border-b border-zinc-200 dark:border-zinc-700">
							<tr>
								<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Username</th>
								<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
								<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Role</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
							{#each members as m (m.id)}
								<tr>
									<td class="px-3 py-2 text-zinc-900 dark:text-zinc-100">{m.username}</td>
									<td class="px-3 py-2 text-zinc-600 dark:text-zinc-400">{m.name}</td>
									<td class="px-3 py-2">
										<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium
											{m.role === 'admin' ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200' : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'}">
											{m.role}
										</span>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
			<div class="mt-4 flex justify-end">
				<button onclick={() => (membersGroup = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Close</button>
			</div>
		</div>
	</div>
{/if}

<!-- Delete Confirm Modal -->
{#if deleteGroup}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (deleteGroup = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Delete Group</h2>
			<p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Are you sure you want to delete <strong>{deleteGroup.name}</strong>? This will also remove all associated ACL rules and memberships.</p>
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (deleteGroup = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
				<button onclick={handleDelete}
					class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
			</div>
		</div>
	</div>
{/if}
