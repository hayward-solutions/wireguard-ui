package auth

import (
	"encoding/base64"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func newTestWebAuthnProvider(t *testing.T, baseURL string) *WebAuthnProvider {
	t.Helper()
	p, err := NewWebAuthnProvider(baseURL)
	if err != nil {
		t.Fatalf("creating WebAuthnProvider: %v", err)
	}
	return p
}

func TestNewWebAuthnProvider(t *testing.T) {
	p := newTestWebAuthnProvider(t, "https://wg.example.com")

	if got, want := p.RPID(), "wg.example.com"; got != want {
		t.Errorf("got RPID %q, want %q", got, want)
	}
}

func TestNewWebAuthnProvider_WithPort(t *testing.T) {
	p := newTestWebAuthnProvider(t, "https://wg.example.com:8443")

	if got, want := p.RPID(), "wg.example.com"; got != want {
		t.Errorf("got RPID %q, want %q", got, want)
	}
}

func TestNewWebAuthnProvider_InvalidURL(t *testing.T) {
	// Use a URL with a control character that url.Parse rejects.
	_, err := NewWebAuthnProvider("https://\x00bad.example.com")
	if err == nil {
		t.Errorf("got nil error, want error for URL with invalid characters")
	}
}

func TestStoreSession_ConsumeSession(t *testing.T) {
	p := newTestWebAuthnProvider(t, "https://wg.example.com")

	session := &webauthn.SessionData{
		Challenge: "test-challenge-123",
	}

	p.StoreSession("chal-1", session)

	got, ok := p.ConsumeSession("chal-1")
	if !ok {
		t.Fatalf("got ok=false, want ok=true")
	}
	if got == nil {
		t.Fatalf("got nil session, want non-nil")
	}
	if got.Challenge != session.Challenge {
		t.Errorf("got Challenge %q, want %q", got.Challenge, session.Challenge)
	}
}

func TestConsumeSession_NotFound(t *testing.T) {
	p := newTestWebAuthnProvider(t, "https://wg.example.com")

	_, ok := p.ConsumeSession("nonexistent")
	if ok {
		t.Errorf("got ok=true, want ok=false for unknown challenge ID")
	}
}

func TestConsumeSession_DoubleConsume(t *testing.T) {
	p := newTestWebAuthnProvider(t, "https://wg.example.com")

	session := &webauthn.SessionData{
		Challenge: "double-consume-test",
	}
	p.StoreSession("chal-2", session)

	_, ok := p.ConsumeSession("chal-2")
	if !ok {
		t.Fatalf("first consume: got ok=false, want ok=true")
	}

	_, ok = p.ConsumeSession("chal-2")
	if ok {
		t.Errorf("second consume: got ok=true, want ok=false")
	}
}

func TestWebAuthnUser_ID(t *testing.T) {
	u := &WebAuthnUser{
		User: &domain.User{ID: "user-abc"},
	}

	got := u.WebAuthnID()
	if want := []byte("user-abc"); string(got) != string(want) {
		t.Errorf("got WebAuthnID %q, want %q", got, want)
	}
}

func TestWebAuthnUser_Name(t *testing.T) {
	u := &WebAuthnUser{
		User: &domain.User{Username: "alice@example.com"},
	}

	if got, want := u.WebAuthnName(), "alice@example.com"; got != want {
		t.Errorf("got WebAuthnName %q, want %q", got, want)
	}
}

func TestWebAuthnUser_DisplayName(t *testing.T) {
	tests := []struct {
		name     string
		user     *domain.User
		wantName string
	}{
		{
			name:     "name set",
			user:     &domain.User{Username: "alice@example.com", Name: "Alice Smith"},
			wantName: "Alice Smith",
		},
		{
			name:     "name empty falls back to username",
			user:     &domain.User{Username: "bob@example.com", Name: ""},
			wantName: "bob@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &WebAuthnUser{User: tt.user}
			if got, want := u.WebAuthnDisplayName(), tt.wantName; got != want {
				t.Errorf("got WebAuthnDisplayName %q, want %q", got, want)
			}
		})
	}
}

func TestCredentialToDomain(t *testing.T) {
	credID := []byte("cred-id-bytes")
	pubKey := []byte("pub-key-bytes")
	aaguid := []byte("aaguid-bytes-16!")

	cred := &webauthn.Credential{
		ID:              credID,
		PublicKey:       pubKey,
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{"usb", "nfc"},
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: 42,
		},
	}

	got := CredentialToDomain("user-99", cred, "My Security Key")

	if got, want := got.UserID, "user-99"; got != want {
		t.Errorf("got UserID %q, want %q", got, want)
	}
	if got, want := got.Name, "My Security Key"; got != want {
		t.Errorf("got Name %q, want %q", got, want)
	}
	if got, want := got.SignCount, uint32(42); got != want {
		t.Errorf("got SignCount %d, want %d", got, want)
	}
	if got, want := got.AttestationType, "none"; got != want {
		t.Errorf("got AttestationType %q, want %q", got, want)
	}

	wantCredID := base64.RawURLEncoding.EncodeToString(credID)
	if got, want := got.CredentialID, wantCredID; got != want {
		t.Errorf("got CredentialID %q, want %q", got, want)
	}

	wantPubKey := base64.RawURLEncoding.EncodeToString(pubKey)
	if got, want := got.PublicKey, wantPubKey; got != want {
		t.Errorf("got PublicKey %q, want %q", got, want)
	}

	wantAAGUID := base64.RawURLEncoding.EncodeToString(aaguid)
	if got, want := got.AAGUID, wantAAGUID; got != want {
		t.Errorf("got AAGUID %q, want %q", got, want)
	}

	if got, want := len(got.Transports), 2; got != want {
		t.Fatalf("got %d transports, want %d", got, want)
	}
	if got, want := got.Transports[0], "usb"; got != want {
		t.Errorf("got Transports[0] %q, want %q", got, want)
	}
	if got, want := got.Transports[1], "nfc"; got != want {
		t.Errorf("got Transports[1] %q, want %q", got, want)
	}

	if got.CreatedAt.IsZero() {
		t.Errorf("got zero CreatedAt, want non-zero")
	}
}
