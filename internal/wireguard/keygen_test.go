package wireguard

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if kp == nil {
		t.Fatal("GenerateKeyPair() returned nil")
	}
	if kp.PrivateKey == "" {
		t.Error("GenerateKeyPair() PrivateKey is empty")
	}
	if kp.PublicKey == "" {
		t.Error("GenerateKeyPair() PublicKey is empty")
	}

	// WireGuard keys are 32 bytes, base64-encoded to 44 characters.
	if len(kp.PrivateKey) != 44 {
		t.Errorf("PrivateKey length got %d, want 44", len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != 44 {
		t.Errorf("PublicKey length got %d, want 44", len(kp.PublicKey))
	}

	if _, err := base64.StdEncoding.DecodeString(kp.PrivateKey); err != nil {
		t.Errorf("PrivateKey is not valid base64: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(kp.PublicKey); err != nil {
		t.Errorf("PublicKey is not valid base64: %v", err)
	}

	// Two calls should produce different keys.
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair() error = %v", err)
	}
	if kp.PrivateKey == kp2.PrivateKey {
		t.Error("two GenerateKeyPair() calls returned same PrivateKey")
	}
	if kp.PublicKey == kp2.PublicKey {
		t.Error("two GenerateKeyPair() calls returned same PublicKey")
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	key, err := GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey() error = %v", err)
	}
	if key == "" {
		t.Error("GeneratePresharedKey() returned empty string")
	}
	if len(key) != 44 {
		t.Errorf("GeneratePresharedKey() length got %d, want 44", len(key))
	}
	if _, err := base64.StdEncoding.DecodeString(key); err != nil {
		t.Errorf("GeneratePresharedKey() is not valid base64: %v", err)
	}
}

func TestValidatePublicKey(t *testing.T) {
	validKey := generateTestPublicKey(t)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid key from GenerateKeyPair",
			key:     validKey,
			wantErr: false,
		},
		{
			name:    "empty string",
			key:     "",
			wantErr: true,
		},
		{
			name:    "not a key",
			key:     "not-a-key",
			wantErr: true,
		},
		{
			name:    "truncated key",
			key:     validKey[:10],
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePublicKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePublicKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

// generateTestPublicKey is a helper that produces a valid WireGuard public key for tests.
func generateTestPublicKey(t *testing.T) string {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return kp.PublicKey
}
