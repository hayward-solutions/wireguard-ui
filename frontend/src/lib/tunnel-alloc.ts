/**
 * Auto-allocates /30 subnets for tunnel point-to-point links from a configurable range.
 */

/** Parse a CIDR string into base IP (as 32-bit number) and prefix length. */
function parseCIDR(cidr: string): { ip: number; prefix: number } | null {
	const match = cidr.trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
	if (!match) return null;
	const parts = match[1].split('.').map(Number);
	if (parts.some((p) => p < 0 || p > 255)) return null;
	const prefix = parseInt(match[2], 10);
	if (prefix < 0 || prefix > 32) return null;
	const ip = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
	return { ip, prefix };
}

/** Convert a 32-bit IP number to dotted-quad string. */
function ipToString(ip: number): string {
	return [(ip >>> 24) & 0xff, (ip >>> 16) & 0xff, (ip >>> 8) & 0xff, ip & 0xff].join('.');
}

/**
 * Allocate the next available /30 from a tunnel subnet range.
 *
 * @param tunnelSubnet - The overall range (e.g., "10.100.0.0/16")
 * @param usedAddresses - Addresses already in use by existing tunnels (e.g., ["10.100.0.1/30"])
 * @param mode - 'create' returns .1 of the /30, 'accept' returns .2
 * @returns The allocated address as CIDR (e.g., "10.100.0.1/30") or null if exhausted
 */
export function allocateTunnelAddress(
	tunnelSubnet: string,
	usedAddresses: string[],
	mode: 'create' | 'accept'
): string | null {
	const range = parseCIDR(tunnelSubnet);
	if (!range) return null;

	// Build a set of /30 network bases that are already in use.
	const usedBases = new Set<number>();
	for (const addr of usedAddresses) {
		const parsed = parseCIDR(addr);
		if (!parsed) continue;
		// Find the /30 base: mask off the bottom 2 bits
		usedBases.add((parsed.ip & 0xfffffffc) >>> 0);
	}

	// Calculate the range boundaries
	const mask = range.prefix === 0 ? 0 : (0xffffffff << (32 - range.prefix)) >>> 0;
	const rangeStart = (range.ip & mask) >>> 0;
	const rangeEnd = (rangeStart | ~mask) >>> 0;

	// Iterate /30 blocks within the range (stride of 4)
	// Start at rangeStart (which should be aligned), skip the first /30 (network base)
	for (let base = rangeStart; base + 3 <= rangeEnd; base = (base + 4) >>> 0) {
		if (usedBases.has(base)) continue;
		const hostIP = mode === 'create' ? base + 1 : base + 2;
		return `${ipToString(hostIP)}/30`;
	}

	return null; // range exhausted
}
