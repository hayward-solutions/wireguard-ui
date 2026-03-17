import { writable } from 'svelte/store';

export type Theme = 'light' | 'dark' | 'system';

const stored = typeof localStorage !== 'undefined' ? (localStorage.getItem('theme') as Theme) : null;
export const theme = writable<Theme>(stored || 'system');

export function initTheme() {
	const mq = window.matchMedia('(prefers-color-scheme: dark)');

	function apply(t: Theme) {
		const dark = t === 'dark' || (t === 'system' && mq.matches);
		document.documentElement.classList.toggle('dark', dark);
	}

	// Apply on store change
	theme.subscribe((t) => {
		localStorage.setItem('theme', t);
		apply(t);
	});

	// Listen for OS preference changes when in system mode
	mq.addEventListener('change', () => {
		let current: Theme;
		theme.subscribe((t) => (current = t))();
		if (current! === 'system') apply('system');
	});
}

export function cycleTheme() {
	theme.update((t) => {
		if (t === 'light') return 'dark';
		if (t === 'dark') return 'system';
		return 'light';
	});
}
