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
	// Clear any leftover values.
	t.Setenv("ENCRYPTION_KEY", "")
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

func TestEmptyEncryptionKeyAllowed(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.EncryptionKey != "" {
		t.Errorf("got EncryptionKey %q, want empty", cfg.EncryptionKey)
	}
}

func TestNoJWTSecretFallback(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("ENCRYPTION_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// EncryptionKey must NOT fall back to JWTSecret.
	if cfg.EncryptionKey == cfg.JWTSecret {
		t.Errorf("EncryptionKey %q should not fall back to JWTSecret %q", cfg.EncryptionKey, cfg.JWTSecret)
	}
	if cfg.EncryptionKey != "" {
		t.Errorf("got EncryptionKey %q, want empty", cfg.EncryptionKey)
	}
}

// setMockEnv sets the minimum environment variables for a valid mock-mode config
// with a loopback listen address (safe default for tests).
func setMockEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WG_MOCK_MODE", "true")
	t.Setenv("LISTEN_ADDR", "127.0.0.1:8080")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("WG_ENDPOINT", "")
	t.Setenv("ADMIN_PASSWORD", "")
	t.Setenv("ENCRYPTION_KEY", "")
}

func TestIsLoopbackAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{":8080", false},
		{"0.0.0.0:8080", false},
		{"192.168.1.1:8080", false},
		{"10.0.0.1:443", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := isLoopbackAddr(tt.addr); got != tt.want {
				t.Errorf("isLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestMockModeLoopbackAllowed(t *testing.T) {
	setMockEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected mock mode with loopback to succeed: %v", err)
	}
	if cfg.JWTSecret != "dev-secret-change-me" {
		t.Errorf("expected auto-filled JWTSecret, got %q", cfg.JWTSecret)
	}
}

func TestMockModePublicDenied(t *testing.T) {
	setMockEnv(t)
	t.Setenv("LISTEN_ADDR", ":8080")

	old := devBuild
	devBuild = ""
	t.Cleanup(func() { devBuild = old })

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when mock mode binds to public address")
	}
	if !strings.Contains(err.Error(), "mock mode refuses to bind") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMockModePublicAllowedWithDevBuild(t *testing.T) {
	setMockEnv(t)
	t.Setenv("LISTEN_ADDR", ":8080")

	old := devBuild
	devBuild = "true"
	t.Cleanup(func() { devBuild = old })

	_, err := Load()
	if err != nil {
		t.Fatalf("expected mock mode with devBuild to allow public bind: %v", err)
	}
}

func TestProductionModeUnaffectedByBindCheck(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("LISTEN_ADDR", "0.0.0.0:8080")

	_, err := Load()
	if err != nil {
		t.Fatalf("production mode should not check bind address: %v", err)
	}
}

func TestEncryptionKeyDistinctInMockMode(t *testing.T) {
	t.Setenv("WG_MOCK_MODE", "true")
	t.Setenv("LISTEN_ADDR", "127.0.0.1:8080")
	t.Setenv("JWT_SECRET", "same-value")
	t.Setenv("ENCRYPTION_KEY", "same-value")
	t.Setenv("WG_ENDPOINT", "")
	t.Setenv("ADMIN_PASSWORD", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when ENCRYPTION_KEY equals JWT_SECRET even in mock mode")
	}
}
