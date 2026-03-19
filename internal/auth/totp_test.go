package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func generateTestSecret(t *testing.T, username, issuer string) *TOTPProvider {
	t.Helper()
	return &TOTPProvider{}
}

func TestTOTPProvider_GenerateSecret(t *testing.T) {
	p := &TOTPProvider{}
	key, err := p.GenerateSecret("alice", "MyApp")
	if err != nil {
		t.Fatalf("generating secret: %v", err)
	}

	if key == nil {
		t.Fatalf("got nil key, want non-nil")
	}
	if got := key.Secret(); got == "" {
		t.Errorf("got empty Secret(), want non-empty")
	}

	url := key.URL()
	if !strings.Contains(url, "MyApp") {
		t.Errorf("got URL %q, want it to contain issuer %q", url, "MyApp")
	}
	if !strings.Contains(url, "alice") {
		t.Errorf("got URL %q, want it to contain account name %q", url, "alice")
	}
}

func TestTOTPProvider_Validate_ValidCode(t *testing.T) {
	p := &TOTPProvider{}
	key, err := p.GenerateSecret("alice", "MyApp")
	if err != nil {
		t.Fatalf("generating secret: %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generating TOTP code: %v", err)
	}

	if got := p.Validate(code, key.Secret()); !got {
		t.Errorf("got Validate() = false, want true for valid code")
	}
}

func TestTOTPProvider_Validate_InvalidInputs(t *testing.T) {
	p := &TOTPProvider{}
	key, err := p.GenerateSecret("alice", "MyApp")
	if err != nil {
		t.Fatalf("generating secret: %v", err)
	}

	tests := []struct {
		name   string
		code   string
		secret string
	}{
		{name: "wrong code", code: "000000", secret: key.Secret()},
		{name: "empty code", code: "", secret: key.Secret()},
		{name: "empty secret", code: "123456", secret: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Validate(tt.code, tt.secret); got {
				t.Errorf("got Validate() = true, want false for %s", tt.name)
			}
		})
	}
}
