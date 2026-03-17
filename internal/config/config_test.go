package config

import (
	"strings"
	"testing"
)

// setProductionEnv sets the minimum environment variables for a valid production config.
func setProductionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET", "jwt-secret-value")
	t.Setenv("WG_ENDPOINT", "vpn.example.com:51820")
	t.Setenv("ADMIN_PASSWORD", "admin-password")
	t.Setenv("ENCRYPTION_KEY", "encryption-key-value")
	t.Setenv("WG_MOCK_MODE", "false")
}

func TestEncryptionKeyEqualsJWTSecretFails(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "jwt-secret-value") // same as JWT_SECRET

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when ENCRYPTION_KEY equals JWT_SECRET")
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY must be different from JWT_SECRET") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEncryptionKeyDifferentPasses(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "different-encryption-key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.EncryptionKey != "different-encryption-key" {
		t.Errorf("got EncryptionKey %q, want %q", cfg.EncryptionKey, "different-encryption-key")
	}
}

func TestEmptyEncryptionKeyFails(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when ENCRYPTION_KEY is empty")
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY is not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoJWTSecretFallback(t *testing.T) {
	setProductionEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// EncryptionKey must NOT fall back to JWTSecret.
	if cfg.EncryptionKey == cfg.JWTSecret {
		t.Errorf("EncryptionKey %q should not equal JWTSecret %q", cfg.EncryptionKey, cfg.JWTSecret)
	}
}

func TestEncryptionKeyDistinctInMockMode(t *testing.T) {
	t.Setenv("WG_MOCK_MODE", "true")
	t.Setenv("JWT_SECRET", "same-value")
	t.Setenv("ENCRYPTION_KEY", "same-value")
	t.Setenv("WG_ENDPOINT", "")
	t.Setenv("ADMIN_PASSWORD", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when ENCRYPTION_KEY equals JWT_SECRET even in mock mode")
	}
}

func TestMockModeDefaultEncryptionKey(t *testing.T) {
	t.Setenv("WG_MOCK_MODE", "true")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("WG_ENDPOINT", "")
	t.Setenv("ADMIN_PASSWORD", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.EncryptionKey == "" {
		t.Error("expected mock mode to set a default EncryptionKey")
	}
}
