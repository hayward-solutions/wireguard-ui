package config

import (
	"strings"
	"testing"
)

// setProductionEnv sets the minimum environment variables for a valid production config.
func setProductionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET", "jwt-secret-value!")
	t.Setenv("WG_ENDPOINT", "vpn.example.com:51820")
	t.Setenv("ADMIN_PASSWORD", "admin-password!")
	t.Setenv("ENCRYPTION_KEY", "encryption-key-val")
	t.Setenv("WG_MOCK_MODE", "false")
}

func TestEncryptionKeyEqualsJWTSecretFails(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "jwt-secret-value!") // same as JWT_SECRET

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

func TestEmptyEncryptionKeyRejectedInProduction(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when ENCRYPTION_KEY is empty in production mode")
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY is not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEncryptionKeyDoesNotFallBackToJWTSecret(t *testing.T) {
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

func TestWeakJWTSecretRejected(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("JWT_SECRET", "changeme")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for weak JWT_SECRET")
	}
	if !strings.Contains(err.Error(), "well-known weak value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWeakAdminPasswordRejected(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ADMIN_PASSWORD", "changeme")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for weak ADMIN_PASSWORD")
	}
	if !strings.Contains(err.Error(), "well-known weak value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWeakEncryptionKeyRejected(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "changeme")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for weak ENCRYPTION_KEY")
	}
	if !strings.Contains(err.Error(), "well-known weak value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestShortJWTSecretRejected(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("JWT_SECRET", "tooshort")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short JWT_SECRET")
	}
	if !strings.Contains(err.Error(), "at least 16 characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestShortEncryptionKeyRejected(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "tooshort")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short ENCRYPTION_KEY")
	}
	if !strings.Contains(err.Error(), "at least 16 characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMissingEncryptionKeyRejected(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing ENCRYPTION_KEY")
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY is not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMockModeAllowsEmptySecrets(t *testing.T) {
	t.Setenv("WG_MOCK_MODE", "true")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("WG_ENDPOINT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("mock mode should not reject empty secrets: %v", err)
	}
	if cfg.JWTSecret == "" {
		t.Error("expected mock mode to set JWTSecret fallback")
	}
	if cfg.AdminPassword == "" {
		t.Error("expected mock mode to set AdminPassword fallback")
	}
	if cfg.EncryptionKey == "" {
		t.Error("expected mock mode to set EncryptionKey fallback")
	}
}

func TestStrongSecretsPass(t *testing.T) {
	setProductionEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected valid config to pass: %v", err)
	}
	if cfg.JWTSecret != "jwt-secret-value!" {
		t.Errorf("unexpected JWTSecret: %q", cfg.JWTSecret)
	}
	if cfg.EncryptionKey != "encryption-key-val" {
		t.Errorf("unexpected EncryptionKey: %q", cfg.EncryptionKey)
	}
}
