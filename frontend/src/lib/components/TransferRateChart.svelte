<script lang="ts">
	import { onMount } from 'svelte';
	import type { RateSnapshot } from '$lib/stores/stats';
	import { formatRate } from '$lib/format';
	import uPlot from 'uplot';
	import 'uplot/dist/uPlot.min.css';

	let { history, height = 200 }: { history: RateSnapshot[]; height?: number } = $props();

	let container: HTMLDivElement;
	let chart: uPlot | null = null;

	function isDark(): boolean {
		return document.documentElement.classList.contains('dark');
	}

	function getColors() {
		const dark = isDark();
		return {
			axes: dark ? '#a1a1aa' : '#71717a', // zinc-400 / zinc-500
			grid: dark ? 'rgba(63,63,70,0.5)' : 'rgba(228,228,231,0.8)', // zinc-700/zinc-200
			rxStroke: '#3b82f6', // blue-500
			rxFill: dark ? 'rgba(59,130,246,0.15)' : 'rgba(59,130,246,0.1)',
			txStroke: '#a855f7', // purple-500
			txFill: dark ? 'rgba(168,85,247,0.15)' : 'rgba(168,85,247,0.1)',
			bg: 'transparent'
		};
	}

	function buildOpts(width: number): uPlot.Options {
		const c = getColors();
		return {
			width,
			height,
			cursor: { show: true },
			legend: { show: true },
			scales: {
				x: { time: true },
				y: { auto: true, range: (_u, min, max) => [0, max || 1024] }
			},
			axes: [
				{
					stroke: c.axes,
					grid: { stroke: c.grid, width: 1 },
					ticks: { stroke: c.grid, width: 1 }
				},
				{
					stroke: c.axes,
					grid: { stroke: c.grid, width: 1 },
					ticks: { stroke: c.grid, width: 1 },
					values: (_u: uPlot, vals: number[]) => vals.map((v) => formatRate(v)),
					size: 70
				}
			],
			series: [
				{},
				{
					label: 'RX',
					stroke: c.rxStroke,
					fill: c.rxFill,
					width: 2,
					paths: uPlot.paths.spline!()
				},
				{
					label: 'TX',
					stroke: c.txStroke,
					fill: c.txFill,
					width: 2,
					paths: uPlot.paths.spline!()
				}
			]
		};
	}

	function historyToData(h: RateSnapshot[]): uPlot.AlignedData {
		const timestamps = new Float64Array(h.length);
		const rx = new Float64Array(h.length);
		const tx = new Float64Array(h.length);
		for (let i = 0; i < h.length; i++) {
			timestamps[i] = h[i].timestamp / 1000; // uPlot expects seconds
			rx[i] = h[i].rx_rate;
			tx[i] = h[i].tx_rate;
		}
		return [timestamps, rx, tx];
	}

	onMount(() => {
		const width = container.clientWidth;
		const data = historyToData(history);
		chart = new uPlot(buildOpts(width), data, container);

		const ro = new ResizeObserver((entries) => {
			const w = entries[0].contentRect.width;
			if (chart && w > 0) chart.setSize({ width: w, height });
		});
		ro.observe(container);

		// Watch for theme changes
		const mo = new MutationObserver(() => {
			if (chart) {
				const w = container.clientWidth;
				chart.destroy();
				chart = new uPlot(buildOpts(w), historyToData(history), container);
			}
		});
		mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

		return () => {
			ro.disconnect();
			mo.disconnect();
			chart?.destroy();
			chart = null;
		};
	});

	$effect(() => {
		if (chart && history.length >= 2) {
			chart.setData(historyToData(history));
		}
	});
</script>

<div class="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-700 dark:bg-zinc-900">
	<h3 class="mb-3 text-sm font-medium text-zinc-500 dark:text-zinc-400">Transfer Rate</h3>
	{#if history.length < 2}
		<div class="flex items-center justify-center text-sm text-zinc-400 dark:text-zinc-500" style="height: {height}px">
			Waiting for data...
		</div>
	{/if}
	<div bind:this={container} class:hidden={history.length < 2}></div>
</div>
