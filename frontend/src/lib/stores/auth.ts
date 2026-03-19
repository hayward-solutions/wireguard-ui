import { writable } from 'svelte/store';

interface User {
	id: string;
	email: string;
	name: string;
	role: string;
	username: string;
	mfa_setup_required?: boolean;
}

export const user = writable<User | null>(null);
export const loading = writable(true);

export async function checkAuth() {
	loading.set(true);
	try {
		// Use raw fetch — don't go through api.request() which auto-redirects on 401
		const res = await fetch('/auth/me', { credentials: 'include' });
		if (res.ok) {
			const json = await res.json();
			user.set(json.data);
		} else {
			user.set(null);
		}
	} catch {
		user.set(null);
	} finally {
		loading.set(false);
	}
}

function getCSRFToken(): string | undefined {
	const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
	return match ? decodeURIComponent(match[1]) : undefined;
}

export async function logout() {
	try {
		const headers: Record<string, string> = {};
		const csrf = getCSRFToken();
		if (csrf) {
			headers['X-CSRF-Token'] = csrf;
		}
		await fetch('/auth/logout', { method: 'POST', headers, credentials: 'include' });
	} finally {
		user.set(null);
		window.location.href = '/login';
	}
}
