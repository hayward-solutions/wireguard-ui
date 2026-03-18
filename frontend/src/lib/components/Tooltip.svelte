<script lang="ts">
	import { HelpCircle } from 'lucide-svelte';

	let { text, position = 'top' }: { text: string; position?: 'top' | 'bottom' } = $props();
</script>

<span class="group/tip relative ml-1 inline-flex cursor-help align-middle">
	<HelpCircle
		size={14}
		class="text-zinc-400 transition-colors group-hover/tip:text-zinc-600 dark:text-zinc-500 dark:group-hover/tip:text-zinc-300"
		tabindex={0}
		role="img"
		aria-label={text}
	/>
	<span
		class="pointer-events-none absolute left-1/2 z-50 w-56 -translate-x-1/2 rounded-lg bg-zinc-800 px-3 py-2 text-xs font-normal leading-relaxed text-zinc-100 opacity-0 shadow-lg transition-opacity group-hover/tip:opacity-100 group-focus-within/tip:opacity-100 dark:bg-zinc-700 dark:text-zinc-200 {position === 'top' ? 'bottom-full mb-2' : 'top-full mt-2'}"
	>
		{text}
		<span
			class="absolute left-1/2 -translate-x-1/2 border-x-4 border-x-transparent {position === 'top' ? 'top-full border-t-4 border-t-zinc-800 dark:border-t-zinc-700' : 'bottom-full border-b-4 border-b-zinc-800 dark:border-b-zinc-700'}"
		></span>
	</span>
</span>
