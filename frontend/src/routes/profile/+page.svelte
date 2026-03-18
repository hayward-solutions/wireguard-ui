<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type APIToken, type APITokenCreateResponse } from '$lib/api';
	import { user } from '$lib/stores/auth';
	import { Plus, Trash2, Copy, Check, X, Eye, EyeOff } from 'lucide-svelte';
	import { get } from 'svelte/store';

	// User info
	let profile = $derived(get(user));

	// Password change
	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let passwordError = $state('');
	let passwordSuccess = $state('');
	let passwordLoading = $state(false);
	let showCurrentPassword = $state(false);
	let showNewPassword = $state(false);

	// API Tokens
	let tokens = $state<APIToken[]>([]);
	let tokensLoading = $state(true);
	let tokensError = $state('');

	// Create token modal
	let showCreateToken = $state(false);
	let tokenName = $state('');
	let createTokenError = $state('');

	// Newly created token (shown once)
	let newToken = $state<APITokenCreateResponse | null>(null);
	let copied = $state(false);

	// Delete confirm
	let deleteToken = $state<APIToken | null>(null);

	async function handleChangePassword() {
		passwordError = '';
		passwordSuccess = '';

		if (newPassword !== confirmPassword) {
			passwordError = 'New passwords do not match';
			return;
		}
		if (newPassword.length < 8) {
			passwordError = 'New password must be at least 8 characters';
			return;
		}

		passwordLoading = true;
		try {
			await api.changePassword(currentPassword, newPassword);
			passwordSuccess = 'Password changed successfully';
			currentPassword = '';
			newPassword = '';
			confirmPassword = '';
		} catch (e: any) {
			passwordError = e.message;
		} finally {
			passwordLoading = false;
		}
	}

	async function loadTokens() {
		try {
			tokens = await api.listTokens();
		} catch (e: any) {
			tokensError = e.message;
		} finally {
			tokensLoading = false;
		}
	}

	async function handleCreateToken() {
		createTokenError = '';
		try {
			const result = await api.createToken(tokenName);
			newToken = result;
			showCreateToken = false;
			tokenName = '';
			copied = false;
			await loadTokens();
		} catch (e: any) {
			createTokenError = e.message;
		}
	}

	async function handleDeleteToken() {
		if (!deleteToken) return;
		try {
			await api.deleteToken(deleteToken.id);
			deleteToken = null;
			await loadTokens();
		} catch (e: any) {
			tokensError = e.message;
		}
	}

	async function copyToken() {
		if (!newToken) return;
		await navigator.clipboard.writeText(newToken.token);
		copied = true;
		setTimeout(() => (copied = false), 2000);
	}

	onMount(loadTokens);
</script>

<div class="space-y-8">
	<!-- User Info -->
	<div>
		<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">Profile</h1>
		<p class="mt-1 text-zinc-500 dark:text-zinc-400">Manage your account settings</p>
	</div>

	<div class="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-700 dark:bg-zinc-900">
		<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Account Information</h2>
		<dl class="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
			<div>
				<dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Username</dt>
				<dd class="mt-1 text-sm text-zinc-900 dark:text-zinc-100">{profile?.username ?? ''}</dd>
			</div>
			<div>
				<dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Display Name</dt>
				<dd class="mt-1 text-sm text-zinc-900 dark:text-zinc-100">{profile?.name ?? ''}</dd>
			</div>
			<div>
				<dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Role</dt>
				<dd class="mt-1">
					<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium
						{profile?.role === 'admin' ? 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200' : profile?.role === 'editor' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'}">
						{profile?.role ?? ''}
					</span>
				</dd>
			</div>
		</dl>
	</div>

	<!-- Change Password -->
	<div class="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-700 dark:bg-zinc-900">
		<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Change Password</h2>
		<p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Update your account password</p>

		{#if passwordError}
			<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{passwordError}</div>
		{/if}
		{#if passwordSuccess}
			<div class="mt-3 rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">{passwordSuccess}</div>
		{/if}

		<form onsubmit={(e) => { e.preventDefault(); handleChangePassword(); }} class="mt-4 max-w-md space-y-4">
			<div>
				<label for="current-password" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Current Password</label>
				<div class="relative mt-1">
					<input id="current-password" type={showCurrentPassword ? 'text' : 'password'} required bind:value={currentPassword}
						class="w-full rounded-lg border border-zinc-200 px-3 py-2 pr-10 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
					<button type="button" onclick={() => (showCurrentPassword = !showCurrentPassword)}
						class="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300">
						{#if showCurrentPassword}<EyeOff size={16} />{:else}<Eye size={16} />{/if}
					</button>
				</div>
			</div>
			<div>
				<label for="new-password" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">New Password</label>
				<div class="relative mt-1">
					<input id="new-password" type={showNewPassword ? 'text' : 'password'} required bind:value={newPassword}
						class="w-full rounded-lg border border-zinc-200 px-3 py-2 pr-10 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
					<button type="button" onclick={() => (showNewPassword = !showNewPassword)}
						class="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300">
						{#if showNewPassword}<EyeOff size={16} />{:else}<Eye size={16} />{/if}
					</button>
				</div>
			</div>
			<div>
				<label for="confirm-password" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Confirm New Password</label>
				<input id="confirm-password" type="password" required bind:value={confirmPassword}
					class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
			</div>
			<div class="pt-2">
				<button type="submit" disabled={passwordLoading}
					class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">
					{passwordLoading ? 'Changing...' : 'Change Password'}
				</button>
			</div>
		</form>
	</div>

	<!-- API Tokens -->
	<div class="rounded-lg border border-zinc-200 bg-white p-6 dark:border-zinc-700 dark:bg-zinc-900">
		<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">API Tokens</h2>
				<p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Create tokens for programmatic API access</p>
			</div>
			<button onclick={() => { showCreateToken = true; tokenName = ''; createTokenError = ''; }}
				class="inline-flex items-center gap-2 self-start rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 sm:self-auto dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">
				<Plus size={16} />
				Create Token
			</button>
		</div>

		{#if tokensError}
			<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{tokensError}</div>
		{/if}

		{#if tokensLoading}
			<div class="mt-6 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
		{:else}
			<div class="mt-4 overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-700">
				<div class="overflow-x-auto">
				<table class="w-full text-left text-sm">
					<thead class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800">
						<tr>
							<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
							<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Token</th>
							<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Created</th>
							<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Last Used</th>
							<th class="px-4 py-3 text-right font-medium text-zinc-600 dark:text-zinc-400">Actions</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
						{#each tokens as token (token.id)}
							<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800">
								<td class="px-4 py-3 font-medium text-zinc-900 dark:text-zinc-100">{token.name}</td>
								<td class="px-4 py-3 font-mono text-zinc-500 dark:text-zinc-400">{token.token_prefix}...</td>
								<td class="px-4 py-3 text-zinc-500 dark:text-zinc-400">{new Date(token.created_at).toLocaleDateString()}</td>
								<td class="px-4 py-3 text-zinc-500 dark:text-zinc-400">{token.last_used ? new Date(token.last_used).toLocaleDateString() : 'Never'}</td>
								<td class="px-4 py-3">
									<div class="flex items-center justify-end">
										<button onclick={() => (deleteToken = token)} title="Delete" class="rounded p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400">
											<Trash2 size={15} />
										</button>
									</div>
								</td>
							</tr>
						{:else}
							<tr>
								<td colspan="5" class="px-4 py-12 text-center text-zinc-400 dark:text-zinc-500">No API tokens</td>
							</tr>
						{/each}
					</tbody>
				</table>
				</div>
			</div>
		{/if}
	</div>
</div>

<!-- New Token Display -->
{#if newToken}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60">
		<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
		<div class="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Token Created</h2>
				<button onclick={() => (newToken = null)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			<div class="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
				Copy this token now. You won't be able to see it again.
			</div>
			<div class="mt-4">
				<span class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">API Token</span>
				<div class="mt-1 flex items-center gap-2">
					<code class="flex-1 overflow-x-auto rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100">{newToken.token}</code>
					<button onclick={copyToken}
						class="shrink-0 rounded-lg border border-zinc-200 p-2 text-zinc-600 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-400 dark:hover:bg-zinc-800" title="Copy">
						{#if copied}<Check size={16} class="text-green-600 dark:text-green-400" />{:else}<Copy size={16} />{/if}
					</button>
				</div>
			</div>
			<div class="mt-6 flex justify-end">
				<button onclick={() => (newToken = null)}
					class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Done</button>
			</div>
		</div>
	</div>
{/if}

<!-- Create Token Modal -->
{#if showCreateToken}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showCreateToken = false)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Create API Token</h2>
				<button onclick={() => (showCreateToken = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if createTokenError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{createTokenError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleCreateToken(); }} class="mt-4 space-y-4">
				<div>
					<label for="token-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Token Name</label>
					<input id="token-name" type="text" required bind:value={tokenName} placeholder="e.g. CI/CD Pipeline"
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-500 dark:focus:ring-zinc-500" />
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (showCreateToken = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Create</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Delete Token Confirm Modal -->
{#if deleteToken}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (deleteToken = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Delete Token</h2>
			<p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Are you sure you want to delete the token <strong>{deleteToken.name}</strong>? Any applications using this token will lose access.</p>
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (deleteToken = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
				<button onclick={handleDeleteToken}
					class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
			</div>
		</div>
	</div>
{/if}
