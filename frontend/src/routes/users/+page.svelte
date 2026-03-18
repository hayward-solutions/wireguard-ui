<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type User, type Group } from '$lib/api';
	import { user as currentUser } from '$lib/stores/auth';
	import { Plus, Trash2, KeyRound, Pencil, X, UsersRound } from 'lucide-svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';
	import { get } from 'svelte/store';

	let users = $state<User[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Create modal
	let showCreate = $state(false);
	let createForm = $state({ username: '', password: '', name: '', role: 'viewer' });
	let createError = $state('');

	// Edit modal
	let editUser = $state<User | null>(null);
	let editForm = $state({ username: '', name: '', role: '' });
	let editError = $state('');

	// Reset password modal
	let resetUser = $state<User | null>(null);
	let resetPassword = $state('');
	let resetError = $state('');

	// Delete confirm
	let deleteUser = $state<User | null>(null);

	// Group management modal
	let groupsUser = $state<User | null>(null);
	let allGroups = $state<Group[]>([]);
	let userGroupIds = $state<Set<string>>(new Set());
	let groupsLoading = $state(false);
	let groupsError = $state('');

	async function loadUsers() {
		try {
			users = await api.listUsers();
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}

	async function openGroups(u: User) {
		groupsUser = u;
		groupsLoading = true;
		groupsError = '';
		try {
			const [groups, userGroups] = await Promise.all([
				api.listGroups(),
				api.getUserGroups(u.id)
			]);
			allGroups = groups;
			userGroupIds = new Set(userGroups.map((g: Group) => g.id));
		} catch (e: any) {
			groupsError = e.message;
		} finally {
			groupsLoading = false;
		}
	}

	function toggleGroup(groupId: string) {
		const next = new Set(userGroupIds);
		if (next.has(groupId)) {
			next.delete(groupId);
		} else {
			next.add(groupId);
		}
		userGroupIds = next;
	}

	async function saveGroups() {
		if (!groupsUser) return;
		groupsError = '';
		try {
			await api.setUserGroups(groupsUser.id, [...userGroupIds]);
			groupsUser = null;
		} catch (e: any) {
			groupsError = e.message;
		}
	}

	async function handleCreate() {
		createError = '';
		try {
			await api.createUser(createForm);
			showCreate = false;
			createForm = { username: '', password: '', name: '', role: 'viewer' };
			await loadUsers();
		} catch (e: any) {
			createError = e.message;
		}
	}

	function openEdit(u: User) {
		editUser = u;
		editForm = { username: u.username, name: u.name, role: u.role };
		editError = '';
	}

	async function handleEdit() {
		if (!editUser) return;
		editError = '';
		try {
			await api.updateUser(editUser.id, editForm);
			editUser = null;
			await loadUsers();
		} catch (e: any) {
			editError = e.message;
		}
	}

	function openReset(u: User) {
		resetUser = u;
		resetPassword = '';
		resetError = '';
	}

	async function handleReset() {
		if (!resetUser) return;
		resetError = '';
		try {
			await api.resetPassword(resetUser.id, resetPassword);
			resetUser = null;
		} catch (e: any) {
			resetError = e.message;
		}
	}

	async function handleDelete() {
		if (!deleteUser) return;
		try {
			await api.deleteUser(deleteUser.id);
			deleteUser = null;
			await loadUsers();
		} catch (e: any) {
			error = e.message;
		}
	}

	onMount(loadUsers);
</script>

<div>
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Users</h1>
			<p class="mt-1 text-zinc-500 dark:text-zinc-400">{users.length} user{users.length !== 1 ? 's' : ''}</p>
		</div>
		<button
			onclick={() => (showCreate = true)}
			class="inline-flex items-center gap-2 self-start rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 sm:self-auto dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
		>
			<Plus size={16} />
			Add User
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
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Username</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Role</th>
						<th class="hidden px-4 py-3 font-medium text-zinc-600 md:table-cell dark:text-zinc-400">Created</th>
						<th class="px-4 py-3 text-right font-medium text-zinc-600 dark:text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
					{#each users as u (u.id)}
						<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800">
							<td class="px-4 py-3 font-medium text-zinc-900 dark:text-zinc-100">{u.username}</td>
							<td class="px-4 py-3 text-zinc-600 dark:text-zinc-400">{u.name}</td>
							<td class="px-4 py-3">
								<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium
									{u.role === 'admin' ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200' : u.role === 'editor' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'}">
									{u.role}
								</span>
							</td>
							<td class="hidden px-4 py-3 text-zinc-500 md:table-cell dark:text-zinc-400">{new Date(u.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-3">
								<div class="flex items-center justify-end gap-1">
									<button onclick={() => openGroups(u)} title="Manage groups" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<UsersRound size={15} />
									</button>
									<button onclick={() => openEdit(u)} title="Edit" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<Pencil size={15} />
									</button>
									<button onclick={() => openReset(u)} title="Reset password" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<KeyRound size={15} />
									</button>
									{#if u.id !== get(currentUser)?.id}
										<button onclick={() => (deleteUser = u)} title="Delete" class="rounded p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400">
											<Trash2 size={15} />
										</button>
									{/if}
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="5" class="px-4 py-12 text-center text-zinc-400 dark:text-zinc-500">No users found</td>
						</tr>
					{/each}
				</tbody>
			</table>
			</div>
		</div>
	{/if}
</div>

<!-- Create User Modal -->
{#if showCreate}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showCreate = false)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Create User</h2>
				<button onclick={() => (showCreate = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if createError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{createError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }} class="mt-4 space-y-4">
				<div>
					<label for="c-username" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Username <Tooltip text="Unique login identifier" /></label>
					<input id="c-username" type="text" required bind:value={createForm.username}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div>
					<label for="c-password" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Password <Tooltip text="Account password for authentication" /></label>
					<input id="c-password" type="password" required bind:value={createForm.password}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div>
					<label for="c-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Display Name <Tooltip text="Optional friendly name shown in the UI" /></label>
					<input id="c-name" type="text" bind:value={createForm.name}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div>
					<label for="c-role" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Role <Tooltip text="Permission level — Viewer (read-only), Editor (manage peers), Admin (full access)" /></label>
					<select id="c-role" bind:value={createForm.role}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500">
						<option value="viewer">Viewer</option>
						<option value="editor">Editor</option>
						<option value="admin">Admin</option>
					</select>
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

<!-- Edit User Modal -->
{#if editUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (editUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Edit User</h2>
				<button onclick={() => (editUser = null)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if editError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{editError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleEdit(); }} class="mt-4 space-y-4">
				<div>
					<label for="e-username" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Username <Tooltip text="Unique login identifier" /></label>
					<input id="e-username" type="text" bind:value={editForm.username}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div>
					<label for="e-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Display Name <Tooltip text="Optional friendly name shown in the UI" /></label>
					<input id="e-name" type="text" bind:value={editForm.name}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div>
					<label for="e-role" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Role <Tooltip text="Permission level — Viewer (read-only), Editor (manage peers), Admin (full access)" /></label>
					<select id="e-role" bind:value={editForm.role}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500">
						<option value="viewer">Viewer</option>
						<option value="editor">Editor</option>
						<option value="admin">Admin</option>
					</select>
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (editUser = null)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Save</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Reset Password Modal -->
{#if resetUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (resetUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Reset Password</h2>
				<button onclick={() => (resetUser = null)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			<p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Set a new password for <strong>{resetUser.username}</strong></p>
			{#if resetError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{resetError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleReset(); }} class="mt-4 space-y-4">
				<div>
					<label for="r-password" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">New Password</label>
					<input id="r-password" type="password" required bind:value={resetPassword}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (resetUser = null)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Reset Password</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Delete Confirm Modal -->
{#if deleteUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (deleteUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Delete User</h2>
			<p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Are you sure you want to delete <strong>{deleteUser.username}</strong>? This action cannot be undone.</p>
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (deleteUser = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
				<button onclick={handleDelete}
					class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
			</div>
		</div>
	</div>
{/if}

<!-- Groups Modal -->
{#if groupsUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (groupsUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Group Membership</h2>
				<button onclick={() => (groupsUser = null)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			<p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Manage groups for <strong>{groupsUser.username}</strong></p>
			{#if groupsError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{groupsError}</div>
			{/if}
			{#if groupsLoading}
				<div class="mt-6 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
			{:else if allGroups.length === 0}
				<div class="mt-6 text-center text-sm text-zinc-400 dark:text-zinc-500">No groups defined. Create groups first.</div>
			{:else}
				<div class="mt-4 max-h-64 space-y-1 overflow-y-auto">
					{#each allGroups as group (group.id)}
						<label class="flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 hover:bg-zinc-50 dark:hover:bg-zinc-800">
							<input type="checkbox" checked={userGroupIds.has(group.id)} onchange={() => toggleGroup(group.id)}
								class="h-4 w-4 rounded border-zinc-300 text-zinc-900 focus:ring-zinc-500 dark:border-zinc-600 dark:bg-zinc-800" />
							<span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">{group.name}</span>
							{#if group.source === 'oidc'}
								<span class="rounded-full bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-700 dark:bg-purple-900 dark:text-purple-300">OIDC</span>
							{/if}
						</label>
					{/each}
				</div>
			{/if}
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (groupsUser = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
				<button onclick={saveGroups} disabled={allGroups.length === 0}
					class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Save</button>
			</div>
		</div>
	</div>
{/if}
