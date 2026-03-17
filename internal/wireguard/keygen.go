package wireguard

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair generates a new WireGuard private/public key pair.
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return &KeyPair{
		PrivateKey: privateKey.String(),
		PublicKey:  privateKey.PublicKey().String(),
	}, nil
}

// GeneratePresharedKey generates a new WireGuard preshared key.
func GeneratePresharedKey() (string, error) {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generate preshared key: %w", err)
	}
	return key.String(), nil
}

// ValidatePublicKey checks that a base64-encoded string is a valid WireGuard key.
func ValidatePublicKey(key string) error {
	_, err := wgtypes.ParseKey(key)
	if err != nil {
		return fmt.Errorf("invalid WireGuard public key: %w", err)
	}
	return nil
}
