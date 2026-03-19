package auth

import (
	"testing"
	"time"
)

const testIssuer = "http://test.local"
const testAudience = "http://test.local"

func newTestJWTManager(t *testing.T, secret string, expiry time.Duration) *JWTManager {
	t.Helper()
	return NewJWTManager(secret, expiry, testIssuer, testAudience)
}

func issueTestToken(t *testing.T, m *JWTManager, subject, email, name, role string) string {
	t.Helper()
	token, err := m.Issue(subject, email, name, role)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}
	return token
}

func TestJWTManager_Issue(t *testing.T) {
	m := newTestJWTManager(t, "test-secret", time.Hour)
	token := issueTestToken(t, m, "user-123", "alice@example.com", "Alice", "admin")

	claims, err := m.Validate(token)
	if err != nil {
		t.Fatalf("validating token: %v", err)
	}

	if got, want := claims.Subject, "user-123"; got != want {
		t.Errorf("got Subject %q, want %q", got, want)
	}
	if got, want := claims.Email, "alice@example.com"; got != want {
		t.Errorf("got Email %q, want %q", got, want)
	}
	if got, want := claims.Name, "Alice"; got != want {
		t.Errorf("got Name %q, want %q", got, want)
	}
	if got, want := claims.Role, "admin"; got != want {
		t.Errorf("got Role %q, want %q", got, want)
	}
}

func TestJWTManager_Validate_Expired(t *testing.T) {
	m := newTestJWTManager(t, "test-secret", time.Millisecond)
	token := issueTestToken(t, m, "user-123", "a@b.com", "A", "viewer")

	time.Sleep(10 * time.Millisecond)

	_, err := m.Validate(token)
	if err == nil {
		t.Errorf("got nil error, want token-expired error")
	}
}

func TestJWTManager_Validate_InvalidInputs(t *testing.T) {
	m := newTestJWTManager(t, "test-secret", time.Hour)

	tests := []struct {
		name     string
		tokenStr string
	}{
		{name: "empty string", tokenStr: ""},
		{name: "random garbage", tokenStr: "not-a-token"},
		{name: "truncated base64", tokenStr: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Validate(tt.tokenStr)
			if err == nil {
				t.Errorf("got nil error for input %q, want error", tt.tokenStr)
			}
		})
	}
}

func TestJWTManager_Validate_WrongSecret(t *testing.T) {
	mA := newTestJWTManager(t, "secret-A", time.Hour)
	token := issueTestToken(t, mA, "user-1", "a@b.com", "A", "admin")

	mB := newTestJWTManager(t, "secret-B", time.Hour)
	_, err := mB.Validate(token)
	if err == nil {
		t.Errorf("got nil error, want signature-validation error")
	}
}

func TestJWTManager_Validate_WrongIssuer(t *testing.T) {
	mA := NewJWTManager("shared-secret-key", time.Hour, "http://issuer-a.local", testAudience)
	token := issueTestToken(t, mA, "user-1", "a@b.com", "A", "admin")

	mB := NewJWTManager("shared-secret-key", time.Hour, "http://issuer-b.local", testAudience)
	_, err := mB.Validate(token)
	if err == nil {
		t.Error("got nil error, want issuer-validation error")
	}
}

func TestJWTManager_Validate_WrongAudience(t *testing.T) {
	mA := NewJWTManager("shared-secret-key", time.Hour, testIssuer, "http://aud-a.local")
	token := issueTestToken(t, mA, "user-1", "a@b.com", "A", "admin")

	mB := NewJWTManager("shared-secret-key", time.Hour, testIssuer, "http://aud-b.local")
	_, err := mB.Validate(token)
	if err == nil {
		t.Error("got nil error, want audience-validation error")
	}
}

func TestJWTManager_Issue_ContainsIssuerAudience(t *testing.T) {
	m := newTestJWTManager(t, "test-secret", time.Hour)
	token := issueTestToken(t, m, "user-1", "a@b.com", "A", "admin")

	claims, err := m.Validate(token)
	if err != nil {
		t.Fatalf("validating token: %v", err)
	}
	if got := claims.Issuer; got != testIssuer {
		t.Errorf("got Issuer %q, want %q", got, testIssuer)
	}
	aud, _ := claims.GetAudience()
	if len(aud) != 1 || aud[0] != testAudience {
		t.Errorf("got Audience %v, want [%q]", aud, testAudience)
	}
}

func TestJWTManager_Expiry(t *testing.T) {
	want := 30 * time.Minute
	m := newTestJWTManager(t, "test-secret", want)

	if got := m.Expiry(); got != want {
		t.Errorf("got Expiry %v, want %v", got, want)
	}
}
