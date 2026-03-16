<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type User } from '$lib/api';
	import { user as currentUser } from '$lib/stores/auth';
	import { Plus, Trash2, KeyRound, Pencil, X } from 'lucide-svelte';
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

	async function loadUsers() {
		try {
			users = await api.listUsers();
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
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
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900">Users</h1>
			<p class="mt-1 text-zinc-500">{users.length} user{users.length !== 1 ? 's' : ''}</p>
		</div>
		<button
			onclick={() => (showCreate = true)}
			class="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800"
		>
			<Plus size={16} />
			Add User
		</button>
	</div>

	{#if error}
		<div class="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
	{/if}

	{#if loading}
		<div class="mt-8 text-center text-zinc-400">Loading...</div>
	{:else}
		<div class="mt-6 overflow-hidden rounded-lg border border-zinc-200 bg-white">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-200 bg-zinc-50">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-600">Username</th>
						<th class="px-4 py-3 font-medium text-zinc-600">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-600">Role</th>
						<th class="px-4 py-3 font-medium text-zinc-600">Created</th>
						<th class="px-4 py-3 text-right font-medium text-zinc-600">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-100">
					{#each users as u (u.id)}
						<tr class="hover:bg-zinc-50">
							<td class="px-4 py-3 font-medium text-zinc-900">{u.username}</td>
							<td class="px-4 py-3 text-zinc-600">{u.name}</td>
							<td class="px-4 py-3">
								<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium
									{u.role === 'admin' ? 'bg-amber-100 text-amber-800' : u.role === 'editor' ? 'bg-blue-100 text-blue-800' : 'bg-zinc-100 text-zinc-600'}">
									{u.role}
								</span>
							</td>
							<td class="px-4 py-3 text-zinc-500">{new Date(u.created_at).toLocaleDateString()}</td>
							<td class="px-4 py-3">
								<div class="flex items-center justify-end gap-1">
									<button onclick={() => openEdit(u)} title="Edit" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700">
										<Pencil size={15} />
									</button>
									<button onclick={() => openReset(u)} title="Reset password" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700">
										<KeyRound size={15} />
									</button>
									{#if u.id !== get(currentUser)?.id}
										<button onclick={() => (deleteUser = u)} title="Delete" class="rounded p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600">
											<Trash2 size={15} />
										</button>
									{/if}
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="5" class="px-4 py-12 text-center text-zinc-400">No users found</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

<!-- Create User Modal -->
{#if showCreate}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onclick={() => (showCreate = false)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900">Create User</h2>
				<button onclick={() => (showCreate = false)} class="text-zinc-400 hover:text-zinc-600"><X size={20} /></button>
			</div>
			{#if createError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{createError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }} class="mt-4 space-y-4">
				<div>
					<label for="c-username" class="block text-sm font-medium text-zinc-700">Username</label>
					<input id="c-username" type="text" required bind:value={createForm.username}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none" />
				</div>
				<div>
					<label for="c-password" class="block text-sm font-medium text-zinc-700">Password</label>
					<input id="c-password" type="password" required bind:value={createForm.password}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none" />
				</div>
				<div>
					<label for="c-name" class="block text-sm font-medium text-zinc-700">Display Name</label>
					<input id="c-name" type="text" bind:value={createForm.name}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none" />
				</div>
				<div>
					<label for="c-role" class="block text-sm font-medium text-zinc-700">Role</label>
					<select id="c-role" bind:value={createForm.role}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none">
						<option value="viewer">Viewer</option>
						<option value="editor">Editor</option>
						<option value="admin">Admin</option>
					</select>
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (showCreate = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800">Create</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Edit User Modal -->
{#if editUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onclick={() => (editUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900">Edit User</h2>
				<button onclick={() => (editUser = null)} class="text-zinc-400 hover:text-zinc-600"><X size={20} /></button>
			</div>
			{#if editError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{editError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleEdit(); }} class="mt-4 space-y-4">
				<div>
					<label for="e-username" class="block text-sm font-medium text-zinc-700">Username</label>
					<input id="e-username" type="text" bind:value={editForm.username}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none" />
				</div>
				<div>
					<label for="e-name" class="block text-sm font-medium text-zinc-700">Display Name</label>
					<input id="e-name" type="text" bind:value={editForm.name}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none" />
				</div>
				<div>
					<label for="e-role" class="block text-sm font-medium text-zinc-700">Role</label>
					<select id="e-role" bind:value={editForm.role}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none">
						<option value="viewer">Viewer</option>
						<option value="editor">Editor</option>
						<option value="admin">Admin</option>
					</select>
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (editUser = null)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800">Save</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Reset Password Modal -->
{#if resetUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onclick={() => (resetUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900">Reset Password</h2>
				<button onclick={() => (resetUser = null)} class="text-zinc-400 hover:text-zinc-600"><X size={20} /></button>
			</div>
			<p class="mt-2 text-sm text-zinc-500">Set a new password for <strong>{resetUser.username}</strong></p>
			{#if resetError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{resetError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleReset(); }} class="mt-4 space-y-4">
				<div>
					<label for="r-password" class="block text-sm font-medium text-zinc-700">New Password</label>
					<input id="r-password" type="password" required bind:value={resetPassword}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none" />
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (resetUser = null)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800">Reset Password</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Delete Confirm Modal -->
{#if deleteUser}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onclick={() => (deleteUser = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl" onclick={(e) => e.stopPropagation()}>
			<h2 class="text-lg font-semibold text-zinc-900">Delete User</h2>
			<p class="mt-2 text-sm text-zinc-500">Are you sure you want to delete <strong>{deleteUser.username}</strong>? This action cannot be undone.</p>
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (deleteUser = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50">Cancel</button>
				<button onclick={handleDelete}
					class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
			</div>
		</div>
	</div>
{/if}
