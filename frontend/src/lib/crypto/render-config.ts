import type { Peer, ServerConfig } from '$lib/api';

interface RenderOptions {
	privateKey: string;
	presharedKey: string;
	peer: Peer;
	server: ServerConfig;
}

/**
 * Renders a WireGuard .conf file client-side.
 * Mirrors the Go template in internal/wireguard/config.go.
 */
export function renderPeerConfig({ privateKey, presharedKey, peer, server }: RenderOptions): string {
	const dns = peer.dns || server.dns;
	const endpoint = server.endpoint.includes(':')
		? server.endpoint
		: `${server.endpoint}:${server.listen_port}`;

	let conf = `[Interface]\nPrivateKey = ${privateKey}\nAddress = ${peer.address}`;
	if (dns) {
		conf += `\nDNS = ${dns}`;
	}
	if (server.mtu) {
		conf += `\nMTU = ${server.mtu}`;
	}

	conf += `\n\n[Peer]\nPublicKey = ${server.public_key}`;
	if (presharedKey) {
		conf += `\nPresharedKey = ${presharedKey}`;
	}
	conf += `\nEndpoint = ${endpoint}`;
	conf += `\nAllowedIPs = ${peer.allowed_ips}`;
	if (peer.persistent_keepalive) {
		conf += `\nPersistentKeepalive = ${peer.persistent_keepalive}`;
	}
	conf += '\n';

	return conf;
}
