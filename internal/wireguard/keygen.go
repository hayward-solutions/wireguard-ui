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

// ValidateKey checks that a base64-encoded string is a valid 32-byte WireGuard key.
func ValidateKey(key string) error {
	_, err := wgtypes.ParseKey(key)
	return err
}

// ValidatePublicKey checks that a base64-encoded string is a valid WireGuard key.
func ValidatePublicKey(key string) error {
	if err := ValidateKey(key); err != nil {
		return fmt.Errorf("invalid WireGuard public key: %w", err)
	}
	return nil
}

// ValidateKeyPair checks that both keys are valid and that publicKey is derived
// from privateKey (Curve25519 key agreement).
func ValidateKeyPair(privateKey, publicKey string) error {
	priv, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	pub, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if priv.PublicKey() != pub {
		return fmt.Errorf("public key does not match private key")
	}
	return nil
}
