import { x25519 } from '@noble/curves/ed25519.js';

function toBase64(bytes: Uint8Array): string {
	let binary = '';
	for (const b of bytes) {
		binary += String.fromCharCode(b);
	}
	return btoa(binary);
}

/**
 * Generates a WireGuard-compatible X25519 key pair in the browser.
 * Private key: 32 random bytes (clamped per Curve25519).
 * Public key: X25519 scalar multiplication of private key with base point.
 * Both returned as base64 strings (WireGuard's native format).
 */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
	const privateBytes = crypto.getRandomValues(new Uint8Array(32));
	const publicBytes = x25519.getPublicKey(privateBytes);
	return {
		privateKey: toBase64(privateBytes),
		publicKey: toBase64(publicBytes)
	};
}
