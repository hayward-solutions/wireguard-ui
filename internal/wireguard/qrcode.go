package wireguard

import (
	"fmt"

	"github.com/skip2/go-qrcode"
)

// GenerateQRCode creates a PNG QR code image from a WireGuard config string.
func GenerateQRCode(configStr string, size int) ([]byte, error) {
	png, err := qrcode.Encode(configStr, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("generate qr code: %w", err)
	}
	return png, nil
}
