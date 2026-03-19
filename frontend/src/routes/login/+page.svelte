<script lang="ts">
	import { onMount } from 'svelte';
	import { Shield, KeyRound, ArrowLeft } from 'lucide-svelte';
	import { api } from '$lib/api';
	import { checkAuth } from '$lib/stores/auth';
	import { goto } from '$app/navigation';
	import { startAuthentication } from '@simplewebauthn/browser';

	let authInfo = $state<{ oidc_enabled: boolean; local_enabled: boolean; webauthn_enabled: boolean; passwordless_login_enabled: boolean } | null>(null);
	let username = $state('');
	let password = $state('');
	let error = $state('');
	let loading = $state(false);

	// MFA challenge state
	let mfaRequired = $state(false);
	let mfaToken = $state('');
	let mfaMethods = $state<string[]>([]);
	let totpCode = $state('');
	let mfaLoading = $state(false);

	onMount(async () => {
		try {
			const res = await fetch('/auth/info');
			authInfo = await res.json().then((r) => r.data);
		} catch {
			authInfo = { oidc_enabled: false, local_enabled: true, webauthn_enabled: false };
		}
	});

	function getCSRFToken(): string | undefined {
		const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
		return match ? decodeURIComponent(match[1]) : undefined;
	}

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
			} else if (json.data?.mfa_required) {
				mfaRequired = true;
				mfaToken = json.data.mfa_token;
				mfaMethods = json.data.mfa_methods || [];
			} else {
				await checkAuth();
				goto(json.data?.mfa_setup_required ? '/profile' : '/');
			}
		} catch (err) {
			error = 'Login failed';
		} finally {
			loading = false;
		}
	}

	async function handleTOTPVerify(e: Event) {
		e.preventDefault();
		mfaLoading = true;
		error = '';
		try {
			const headers: Record<string, string> = { 'Content-Type': 'application/json' };
			const csrf = getCSRFToken();
			if (csrf) headers['X-CSRF-Token'] = csrf;

			const res = await fetch('/auth/mfa/challenge', {
				method: 'POST',
				headers,
				credentials: 'include',
				body: JSON.stringify({ mfa_token: mfaToken, code: totpCode })
			});
			const json = await res.json();
			if (json.error) {
				error = json.error.message;
			} else {
				await checkAuth();
				goto('/');
			}
		} catch (err) {
			error = 'Verification failed';
		} finally {
			mfaLoading = false;
		}
	}

	async function handleWebAuthnMFA() {
		mfaLoading = true;
		error = '';
		try {
			const headers: Record<string, string> = { 'Content-Type': 'application/json' };
			const csrf = getCSRFToken();
			if (csrf) headers['X-CSRF-Token'] = csrf;

			// Begin WebAuthn assertion
			const beginRes = await fetch('/auth/mfa/webauthn/begin', {
				method: 'POST',
				headers,
				credentials: 'include',
				body: JSON.stringify({ mfa_token: mfaToken })
			});
			const beginJson = await beginRes.json();
			if (beginJson.error) {
				error = beginJson.error.message;
				return;
			}

			// Trigger browser authenticator
			const assertion = await startAuthentication({ optionsJSON: beginJson.data.options });

			// Finish WebAuthn assertion
			const finishRes = await fetch('/auth/mfa/webauthn/finish', {
				method: 'POST',
				headers,
				credentials: 'include',
				body: JSON.stringify({ mfa_token: mfaToken, response: assertion })
			});
			const finishJson = await finishRes.json();
			if (finishJson.error) {
				error = finishJson.error.message;
			} else {
				await checkAuth();
				goto('/');
			}
		} catch (err: any) {
			if (err.name === 'NotAllowedError') {
				error = 'Authentication was cancelled or timed out';
			} else {
				error = err.message || 'WebAuthn authentication failed';
			}
		} finally {
			mfaLoading = false;
		}
	}

	async function handlePasskeyLogin() {
		loading = true;
		error = '';
		try {
			const headers: Record<string, string> = { 'Content-Type': 'application/json' };
			const csrf = getCSRFToken();
			if (csrf) headers['X-CSRF-Token'] = csrf;

			// Begin discoverable login
			const beginRes = await fetch('/auth/passkey/begin', {
				method: 'POST',
				headers,
				credentials: 'include'
			});
			const beginJson = await beginRes.json();
			if (beginJson.error) {
				error = beginJson.error.message;
				return;
			}

			// Trigger browser authenticator
			const assertion = await startAuthentication({ optionsJSON: beginJson.data.options });

			// Finish discoverable login
			const finishRes = await fetch('/auth/passkey/finish', {
				method: 'POST',
				headers,
				credentials: 'include',
				body: JSON.stringify({ challenge_id: beginJson.data.challenge_id, response: assertion })
			});
			const finishJson = await finishRes.json();
			if (finishJson.error) {
				error = finishJson.error.message;
			} else {
				await checkAuth();
				goto('/');
			}
		} catch (err: any) {
			if (err.name === 'NotAllowedError') {
				error = 'Authentication was cancelled or timed out';
			} else {
				error = err.message || 'Passkey authentication failed';
			}
		} finally {
			loading = false;
		}
	}

	function backToLogin() {
		mfaRequired = false;
		mfaToken = '';
		mfaMethods = [];
		totpCode = '';
		error = '';
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-zinc-950">
	<div class="w-full max-w-sm">
		<div class="text-center">
			<div class="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-zinc-900 dark:bg-zinc-100">
				<Shield size={32} class="text-white dark:text-zinc-900" />
			</div>
			<h1 class="mt-6 text-2xl font-bold text-zinc-900 dark:text-zinc-100">WireGuard UI</h1>
			<p class="mt-2 text-zinc-500 dark:text-zinc-400">
				{mfaRequired ? 'Verify your identity' : 'Sign in to manage your VPN'}
			</p>
		</div>

		{#if authInfo}
			{#if mfaRequired}
				<!-- MFA Challenge Step -->
				<div class="mt-8 space-y-4">
					{#if mfaMethods.includes('totp')}
						<form onsubmit={handleTOTPVerify} class="space-y-4">
							<div>
								<label for="totp-code" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Authenticator Code</label>
								<input
									id="totp-code"
									type="text"
									inputmode="numeric"
									pattern="[0-9]*"
									maxlength="6"
									autocomplete="one-time-code"
									bind:value={totpCode}
									required
									placeholder="000000"
									class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-center text-lg tracking-widest focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
								/>
							</div>

							{#if error}
								<p class="text-sm text-red-600 dark:text-red-400">{error}</p>
							{/if}

							<button
								type="submit"
								disabled={mfaLoading}
								class="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
							>
								{mfaLoading ? 'Verifying...' : 'Verify'}
							</button>
						</form>
					{/if}

					{#if mfaMethods.includes('webauthn')}
						{#if mfaMethods.includes('totp')}
							<div class="flex items-center gap-3">
								<div class="flex-1 border-t border-zinc-200 dark:border-zinc-700"></div>
								<span class="text-xs text-zinc-400 dark:text-zinc-500">or</span>
								<div class="flex-1 border-t border-zinc-200 dark:border-zinc-700"></div>
							</div>
						{/if}

						<button
							onclick={handleWebAuthnMFA}
							disabled={mfaLoading}
							class="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 disabled:opacity-50 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
						>
							<KeyRound size={16} />
							Use security key
						</button>
					{/if}

					<button
						onclick={backToLogin}
						class="inline-flex w-full items-center justify-center gap-1 text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-300"
					>
						<ArrowLeft size={14} />
						Back to login
					</button>
				</div>
			{:else}
				<!-- Normal Login -->
				{#if authInfo.local_enabled}
					<form onsubmit={handleLocalLogin} class="mt-8 space-y-4">
						<div>
							<label for="username" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Username</label>
							<input
								id="username"
								type="text"
								bind:value={username}
								required
								autocomplete="username"
								class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
							/>
						</div>
						<div>
							<label for="password" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Password</label>
							<input
								id="password"
								type="password"
								bind:value={password}
								required
								autocomplete="current-password"
								class="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 focus:outline-none dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100 dark:focus:border-zinc-400 dark:focus:ring-zinc-400"
							/>
						</div>

						{#if error}
							<p class="text-sm text-red-600 dark:text-red-400">{error}</p>
						{/if}

						<button
							type="submit"
							disabled={loading}
							class="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-200"
						>
							{loading ? 'Signing in...' : 'Sign in'}
						</button>
					</form>
				{/if}

				{#if authInfo.oidc_enabled}
					{#if authInfo.local_enabled}
						<div class="my-6 flex items-center gap-3">
							<div class="flex-1 border-t border-zinc-200 dark:border-zinc-700"></div>
							<span class="text-xs text-zinc-400 dark:text-zinc-500">or</span>
							<div class="flex-1 border-t border-zinc-200 dark:border-zinc-700"></div>
						</div>
					{/if}

					<a
						href="/auth/login"
						class="mt-{authInfo.local_enabled ? '0' : '8'} inline-flex w-full items-center justify-center rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
					>
						Sign in with SSO
					</a>
				{/if}

				{#if authInfo.passwordless_login_enabled}
					<div class="my-6 flex items-center gap-3">
						<div class="flex-1 border-t border-zinc-200 dark:border-zinc-700"></div>
						<span class="text-xs text-zinc-400 dark:text-zinc-500">or</span>
						<div class="flex-1 border-t border-zinc-200 dark:border-zinc-700"></div>
					</div>

					<button
						onclick={handlePasskeyLogin}
						disabled={loading}
						class="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 disabled:opacity-50 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
					>
						<KeyRound size={16} />
						Sign in with passkey
					</button>
				{/if}
			{/if}
		{:else}
			<div class="mt-8 flex justify-center">
				<div class="h-6 w-6 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900 dark:border-zinc-600 dark:border-t-zinc-100"></div>
			</div>
		{/if}
	</div>
</div>
