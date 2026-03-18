<script lang="ts">
	import { onMount } from 'svelte';
	import { api, type ACLRule, type Group, type User } from '$lib/api';
	import { Plus, Trash2, Pencil, X, ToggleLeft, ToggleRight } from 'lucide-svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';

	let rules = $state<ACLRule[]>([]);
	let groups = $state<Group[]>([]);
	let users = $state<User[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Create/Edit modal
	let showForm = $state(false);
	let formRule = $state<ACLRule | null>(null); // null = create, non-null = edit
	let form = $state({
		name: '',
		description: '',
		priority: 100,
		protocol: 'any',
		dst_cidr: '',
		dst_ports: '',
		target_type: 'global' as 'global' | 'group' | 'user',
		group_id: '',
		user_id: '',
		enabled: true
	});
	let formError = $state('');

	// Delete confirm
	let deleteRule = $state<ACLRule | null>(null);

	// Effective rules preview
	let previewUserId = $state('');
	let previewRules = $state<ACLRule[] | null>(null);
	let previewLoading = $state(false);

	async function loadData() {
		try {
			[rules, groups, users] = await Promise.all([
				api.listACLRules(),
				api.listGroups(),
				api.listUsers()
			]);
		} catch (e: any) {
			error = e.message;
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		formRule = null;
		form = { name: '', description: '', priority: 100, protocol: 'any', dst_cidr: '', dst_ports: '', target_type: 'global', group_id: '', user_id: '', enabled: true };
		formError = '';
		showForm = true;
	}

	function openEdit(r: ACLRule) {
		formRule = r;
		form = {
			name: r.name,
			description: r.description,
			priority: r.priority,
			protocol: r.protocol,
			dst_cidr: r.dst_cidr,
			dst_ports: r.dst_ports,
			target_type: r.group_id ? 'group' : r.user_id ? 'user' : 'global',
			group_id: r.group_id || '',
			user_id: r.user_id || '',
			enabled: r.enabled
		};
		formError = '';
		showForm = true;
	}

	async function handleSubmit() {
		formError = '';
		const data: any = {
			name: form.name,
			description: form.description,
			priority: form.priority,
			protocol: form.protocol,
			dst_cidr: form.dst_cidr,
			dst_ports: form.dst_ports,
			enabled: form.enabled,
			group_id: form.target_type === 'group' ? form.group_id : null,
			user_id: form.target_type === 'user' ? form.user_id : null
		};

		try {
			if (formRule) {
				await api.updateACLRule(formRule.id, data);
			} else {
				await api.createACLRule(data);
			}
			showForm = false;
			await loadData();
		} catch (e: any) {
			formError = e.message;
		}
	}

	async function handleToggle(r: ACLRule) {
		try {
			await api.updateACLRule(r.id, { enabled: !r.enabled });
			await loadData();
		} catch (e: any) {
			error = e.message;
		}
	}

	async function handleDelete() {
		if (!deleteRule) return;
		try {
			await api.deleteACLRule(deleteRule.id);
			deleteRule = null;
			await loadData();
		} catch (e: any) {
			error = e.message;
		}
	}

	async function loadPreview() {
		if (!previewUserId) return;
		previewLoading = true;
		try {
			previewRules = await api.getEffectiveACLRules(previewUserId);
		} catch (e: any) {
			error = e.message;
		} finally {
			previewLoading = false;
		}
	}

	function getTargetLabel(r: ACLRule): string {
		if (r.group_id) {
			const g = groups.find(g => g.id === r.group_id);
			return `Group: ${g?.name || r.group_id}`;
		}
		if (r.user_id) {
			const u = users.find(u => u.id === r.user_id);
			return `User: ${u?.username || r.user_id}`;
		}
		return 'Global';
	}

	onMount(loadData);
</script>

<div>
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">ACL Rules</h1>
			<p class="mt-1 text-zinc-500 dark:text-zinc-400">{rules.length} rule{rules.length !== 1 ? 's' : ''} &middot; Default deny for non-admin peers</p>
		</div>
		<button
			onclick={openCreate}
			class="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
		>
			<Plus size={16} />
			Add Rule
		</button>
	</div>

	{#if error}
		<div class="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{error}</div>
	{/if}

	{#if loading}
		<div class="mt-8 text-center text-zinc-400 dark:text-zinc-500">Loading...</div>
	{:else}
		<div class="mt-6 overflow-hidden rounded-lg border border-zinc-200 bg-white dark:border-zinc-700 dark:bg-zinc-900">
			<table class="w-full text-left text-sm">
				<thead class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800">
					<tr>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Pri</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Destination</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Proto</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Ports</th>
						<th class="px-4 py-3 font-medium text-zinc-600 dark:text-zinc-400">Target</th>
						<th class="px-4 py-3 text-right font-medium text-zinc-600 dark:text-zinc-400">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
					{#each rules as r (r.id)}
						<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800 {!r.enabled ? 'opacity-50' : ''}">
							<td class="px-4 py-3 font-mono text-xs text-zinc-500 dark:text-zinc-400">{r.priority}</td>
							<td class="px-4 py-3 font-medium text-zinc-900 dark:text-zinc-100">
								{r.name}
								{#if r.description}
									<span class="block text-xs text-zinc-400 dark:text-zinc-500">{r.description}</span>
								{/if}
							</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">{r.dst_cidr}</td>
							<td class="px-4 py-3">
								<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium
									{r.protocol === 'tcp' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : r.protocol === 'udp' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'}">
									{r.protocol}
								</span>
							</td>
							<td class="px-4 py-3 font-mono text-xs text-zinc-500 dark:text-zinc-400">{r.dst_ports || '*'}</td>
							<td class="px-4 py-3 text-xs text-zinc-600 dark:text-zinc-400">{getTargetLabel(r)}</td>
							<td class="px-4 py-3">
								<div class="flex items-center justify-end gap-1">
									<button onclick={() => handleToggle(r)} title={r.enabled ? 'Disable' : 'Enable'} class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										{#if r.enabled}
											<ToggleRight size={15} />
										{:else}
											<ToggleLeft size={15} />
										{/if}
									</button>
									<button onclick={() => openEdit(r)} title="Edit" class="rounded p-1.5 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:text-zinc-500 dark:hover:bg-zinc-700 dark:hover:text-zinc-300">
										<Pencil size={15} />
									</button>
									<button onclick={() => (deleteRule = r)} title="Delete" class="rounded p-1.5 text-zinc-400 hover:bg-red-50 hover:text-red-600 dark:text-zinc-500 dark:hover:bg-red-950 dark:hover:text-red-400">
										<Trash2 size={15} />
									</button>
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="7" class="px-4 py-12 text-center text-zinc-400 dark:text-zinc-500">No ACL rules. All non-admin peer traffic is denied by default.</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>

		<!-- Effective Rules Preview -->
		<div class="mt-8">
			<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Preview Effective Rules</h2>
			<p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Select a user to see which rules apply to them.</p>
			<div class="mt-3 flex items-center gap-3">
				<select bind:value={previewUserId}
					class="rounded-lg border border-zinc-200 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100">
					<option value="">Select user...</option>
					{#each users as u (u.id)}
						<option value={u.id}>{u.username} ({u.role})</option>
					{/each}
				</select>
				<button onclick={loadPreview} disabled={!previewUserId}
					class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">Preview</button>
			</div>
			{#if previewLoading}
				<div class="mt-4 text-sm text-zinc-400">Loading...</div>
			{:else if previewRules !== null}
				{#if previewRules.length === 0}
					<div class="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
						No rules apply to this user. All traffic will be denied.
					</div>
				{:else}
					<div class="mt-4 overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-700">
						<table class="w-full text-left text-sm">
							<thead class="border-b border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800">
								<tr>
									<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Pri</th>
									<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Name</th>
									<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Destination</th>
									<th class="px-3 py-2 font-medium text-zinc-600 dark:text-zinc-400">Proto/Ports</th>
								</tr>
							</thead>
							<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
								{#each previewRules as r (r.id)}
									<tr>
										<td class="px-3 py-2 font-mono text-xs">{r.priority}</td>
										<td class="px-3 py-2 text-zinc-900 dark:text-zinc-100">{r.name}</td>
										<td class="px-3 py-2 font-mono text-xs">{r.dst_cidr}</td>
										<td class="px-3 py-2 text-xs">{r.protocol}{r.dst_ports ? `:${r.dst_ports}` : ''}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			{/if}
		</div>
	{/if}
</div>

<!-- Create/Edit Rule Modal -->
{#if showForm}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (showForm = false)}>
		<div class="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{formRule ? 'Edit' : 'Create'} ACL Rule</h2>
				<button onclick={() => (showForm = false)} class="text-zinc-400 hover:text-zinc-600 dark:text-zinc-500 dark:hover:text-zinc-300"><X size={20} /></button>
			</div>
			{#if formError}
				<div class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">{formError}</div>
			{/if}
			<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="mt-4 space-y-4">
				<div class="grid grid-cols-2 gap-4">
					<div>
						<label for="r-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name <Tooltip text="A descriptive name for this access control rule" /></label>
						<input id="r-name" type="text" required bind:value={form.name}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="r-pri" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Priority <Tooltip text="Rule evaluation order. Lower numbers are evaluated first (0 = highest priority)" /></label>
						<input id="r-pri" type="number" min="0" required bind:value={form.priority}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div>
					<label for="r-desc" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Description <Tooltip text="Optional note explaining the purpose of this rule" /></label>
					<input id="r-desc" type="text" bind:value={form.description}
						class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
				</div>
				<div class="grid grid-cols-3 gap-4">
					<div>
						<label for="r-cidr" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Destination CIDR <Tooltip text="The network range this rule applies to in CIDR notation (e.g., 10.0.0.0/24)" /></label>
						<input id="r-cidr" type="text" required placeholder="10.0.0.0/24" bind:value={form.dst_cidr}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
					<div>
						<label for="r-proto" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Protocol <Tooltip text="Network protocol to match. &quot;Any&quot; matches all protocols" /></label>
						<select id="r-proto" bind:value={form.protocol}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100">
							<option value="any">Any</option>
							<option value="tcp">TCP</option>
							<option value="udp">UDP</option>
						</select>
					</div>
					<div>
						<label for="r-ports" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Ports <Tooltip text="Comma-separated port numbers or ranges. Leave empty to match all ports" /></label>
						<input id="r-ports" type="text" placeholder="All" bind:value={form.dst_ports}
							class="mt-1 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm font-mono focus:border-zinc-400 focus:ring-1 focus:ring-zinc-400 focus:outline-none dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
					</div>
				</div>
				<div>
					<label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Applies To <Tooltip text="Scope of the rule — global (all peers), specific group, or specific user" /></label>
					<div class="mt-2 flex gap-4">
						<label class="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
							<input type="radio" value="global" bind:group={form.target_type} class="accent-zinc-900 dark:accent-zinc-100" /> Global
						</label>
						<label class="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
							<input type="radio" value="group" bind:group={form.target_type} class="accent-zinc-900 dark:accent-zinc-100" /> Group
						</label>
						<label class="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
							<input type="radio" value="user" bind:group={form.target_type} class="accent-zinc-900 dark:accent-zinc-100" /> User
						</label>
					</div>
					{#if form.target_type === 'group'}
						<select bind:value={form.group_id}
							class="mt-2 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100">
							<option value="">Select group...</option>
							{#each groups as g (g.id)}
								<option value={g.id}>{g.name}</option>
							{/each}
						</select>
					{:else if form.target_type === 'user'}
						<select bind:value={form.user_id}
							class="mt-2 w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100">
							<option value="">Select user...</option>
							{#each users as u (u.id)}
								<option value={u.id}>{u.username}</option>
							{/each}
						</select>
					{/if}
				</div>
				<div class="flex items-center gap-2">
					<input id="r-enabled" type="checkbox" bind:checked={form.enabled} class="accent-zinc-900 dark:accent-zinc-100" />
					<label for="r-enabled" class="text-sm text-zinc-700 dark:text-zinc-300">Enabled <Tooltip text="Whether this rule is currently active" /></label>
				</div>
				<div class="flex justify-end gap-3 pt-2">
					<button type="button" onclick={() => (showForm = false)}
						class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
					<button type="submit"
						class="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200">{formRule ? 'Save' : 'Create'}</button>
				</div>
			</form>
		</div>
	</div>
{/if}

<!-- Delete Confirm Modal -->
{#if deleteRule}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 dark:bg-black/60" onclick={() => (deleteRule = null)}>
		<div class="w-full max-w-md rounded-xl bg-white p-6 shadow-xl dark:bg-zinc-900" onclick={(e) => e.stopPropagation()}>
			<h2 class="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Delete Rule</h2>
			<p class="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Are you sure you want to delete <strong>{deleteRule.name}</strong>?</p>
			<div class="mt-6 flex justify-end gap-3">
				<button onclick={() => (deleteRule = null)}
					class="rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
				<button onclick={handleDelete}
					class="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
			</div>
		</div>
	</div>
{/if}
