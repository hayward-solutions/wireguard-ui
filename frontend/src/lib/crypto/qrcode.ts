import QRCode from 'qrcode';

/**
 * Generates a QR code as a data URL from a WireGuard config string.
 * Used for client-side QR generation when the server doesn't hold the private key.
 */
export async function generateQRCodeDataURL(config: string): Promise<string> {
	return QRCode.toDataURL(config, {
		width: 512,
		margin: 2,
		errorCorrectionLevel: 'M'
	});
}
