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

func TestValidateKey(t *testing.T) {
	kp := generateTestKeyPair(t)

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "valid public key", key: kp.PublicKey, wantErr: false},
		{name: "valid private key", key: kp.PrivateKey, wantErr: false},
		{name: "empty string", key: "", wantErr: true},
		{name: "bad base64", key: "not-a-key!!!", wantErr: true},
		{name: "truncated key", key: kp.PublicKey[:10], wantErr: true},
		{name: "wrong length base64", key: base64.StdEncoding.EncodeToString([]byte("tooshort")), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKeyPair(t *testing.T) {
	kp := generateTestKeyPair(t)
	kp2 := generateTestKeyPair(t)

	tests := []struct {
		name       string
		privateKey string
		publicKey  string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "matching keypair",
			privateKey: kp.PrivateKey,
			publicKey:  kp.PublicKey,
			wantErr:    false,
		},
		{
			name:       "mismatched keypair",
			privateKey: kp.PrivateKey,
			publicKey:  kp2.PublicKey,
			wantErr:    true,
			errMsg:     "public key does not match private key",
		},
		{
			name:       "invalid private key",
			privateKey: "garbage",
			publicKey:  kp.PublicKey,
			wantErr:    true,
			errMsg:     "invalid private key",
		},
		{
			name:       "invalid public key",
			privateKey: kp.PrivateKey,
			publicKey:  "garbage",
			wantErr:    true,
			errMsg:     "invalid public key",
		},
		{
			name:       "both empty",
			privateKey: "",
			publicKey:  "",
			wantErr:    true,
			errMsg:     "invalid private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKeyPair(tt.privateKey, tt.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if got := err.Error(); !contains(got, tt.errMsg) {
					t.Errorf("ValidateKeyPair() error = %q, want substring %q", got, tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// generateTestPublicKey is a helper that produces a valid WireGuard public key for tests.
func generateTestPublicKey(t *testing.T) string {
	t.Helper()
	return generateTestKeyPair(t).PublicKey
}

// generateTestKeyPair is a helper that produces a valid WireGuard key pair for tests.
func generateTestKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return kp
}
