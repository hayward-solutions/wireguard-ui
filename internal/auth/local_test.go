package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

var testHMACKey = []byte("test-hmac-key-for-tokens")

// mockAPIKeyStore implements database.Store with stubs for all methods.
// Only the fields/methods relevant to APIKeyMiddleware return real data.
type mockAPIKeyStore struct {
	database.Store // embed nil interface to satisfy compiler for unused methods

	token    *domain.APIToken
	user     *domain.User
	tokenErr error
	userErr  error
}

func (m *mockAPIKeyStore) GetAPITokenByHash(_ context.Context, _ string) (*domain.APIToken, error) {
	return m.token, m.tokenErr
}

func (m *mockAPIKeyStore) GetUser(_ context.Context, _ string) (*domain.User, error) {
	return m.user, m.userErr
}

func (m *mockAPIKeyStore) UpdateAPITokenLastUsed(_ context.Context, _ string) error {
	return nil
}

// captureHandler records whether ServeHTTP was called and captures claims.
type captureHandler struct {
	called bool
	claims *Claims
}

func (h *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.claims = ClaimsFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{}
}

func hashToken(t *testing.T, raw string) string {
	t.Helper()
	return HashAPIToken(testHMACKey, raw)
}

func TestAPIKeyMiddleware_StaticKey(t *testing.T) {
	staticKey := "my-static-admin-key"
	store := &mockAPIKeyStore{}
	handler := newCaptureHandler()

	mw := APIKeyMiddleware(staticKey, store, testHMACKey)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-API-Key", staticKey)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !handler.called {
		t.Fatalf("got next handler not called, want it called")
	}
	if handler.claims == nil {
		t.Fatalf("got nil claims, want non-nil")
	}
	if got, want := handler.claims.Role, "admin"; got != want {
		t.Errorf("got Role %q, want %q", got, want)
	}
	if got, want := handler.claims.Subject, "api-key"; got != want {
		t.Errorf("got Subject %q, want %q", got, want)
	}
	if got := rr.Header().Get("Deprecation"); got != "true" {
		t.Errorf("got Deprecation header %q, want %q", got, "true")
	}
}

func TestAPIKeyMiddleware_BearerWguiToken(t *testing.T) {
	rawToken := "wgui_abc123xyz"
	tokenHash := hashToken(t, rawToken)

	store := &mockAPIKeyStore{
		token: &domain.APIToken{
			ID:        "tok-1",
			UserID:    "user-42",
			TokenHash: tokenHash,
		},
		user: &domain.User{
			ID:       "user-42",
			Username: "alice@example.com",
			Name:     "Alice",
			Role:     "editor",
		},
	}
	handler := newCaptureHandler()

	mw := APIKeyMiddleware("unused-static-key", store, testHMACKey)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !handler.called {
		t.Fatalf("got next handler not called, want it called")
	}
	if handler.claims == nil {
		t.Fatalf("got nil claims, want non-nil")
	}
	if got, want := handler.claims.Role, "editor"; got != want {
		t.Errorf("got Role %q, want %q", got, want)
	}
	if got, want := handler.claims.Email, "alice@example.com"; got != want {
		t.Errorf("got Email %q, want %q", got, want)
	}
	if got, want := handler.claims.Subject, "user-42"; got != want {
		t.Errorf("got Subject %q, want %q", got, want)
	}
}

func TestAPIKeyMiddleware_ExpiredToken(t *testing.T) {
	rawToken := "wgui_expired_token"
	tokenHash := hashToken(t, rawToken)

	expired := time.Now().Add(-time.Hour)
	store := &mockAPIKeyStore{
		token: &domain.APIToken{
			ID:        "tok-2",
			UserID:    "user-42",
			TokenHash: tokenHash,
			ExpiresAt: &expired,
		},
		user: &domain.User{
			ID:       "user-42",
			Username: "alice@example.com",
			Name:     "Alice",
			Role:     "editor",
		},
	}
	handler := newCaptureHandler()

	mw := APIKeyMiddleware("some-static-key", store, testHMACKey)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !handler.called {
		t.Fatalf("got next handler not called, want it called (pass-through)")
	}
	if handler.claims != nil {
		t.Errorf("got claims %+v, want nil (expired token should pass through)", handler.claims)
	}
	if got, want := rr.Code, http.StatusOK; got != want {
		t.Errorf("got status %d, want %d", got, want)
	}
}

func TestAPIKeyMiddleware_UnknownToken(t *testing.T) {
	rawToken := "wgui_unknown_token"

	store := &mockAPIKeyStore{
		token: nil, // not found
	}
	handler := newCaptureHandler()

	mw := APIKeyMiddleware("some-static-key", store, testHMACKey)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !handler.called {
		t.Fatalf("got next handler not called, want it called (pass-through)")
	}
	if handler.claims != nil {
		t.Errorf("got claims %+v, want nil (unknown token should pass through)", handler.claims)
	}
	if got, want := rr.Code, http.StatusOK; got != want {
		t.Errorf("got status %d, want %d", got, want)
	}
}

func TestAPIKeyMiddleware_NoKey(t *testing.T) {
	store := &mockAPIKeyStore{}
	handler := newCaptureHandler()

	mw := APIKeyMiddleware("some-static-key", store, testHMACKey)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	// No X-API-Key header, no Authorization header.
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !handler.called {
		t.Fatalf("got next handler not called, want it called (pass-through)")
	}
	if handler.claims != nil {
		t.Errorf("got claims %+v, want nil (no key should pass through)", handler.claims)
	}
	if got, want := rr.Code, http.StatusOK; got != want {
		t.Errorf("got status %d, want %d", got, want)
	}
}

func TestAPIKeyMiddleware_StaticKeyViaBearer(t *testing.T) {
	// Static key via X-API-Key should work, but via Bearer it only
	// triggers the wgui_ path. A static key without the wgui_ prefix
	// sent as Bearer should pass through without authentication.
	staticKey := "my-static-admin-key"
	store := &mockAPIKeyStore{}
	handler := newCaptureHandler()

	mw := APIKeyMiddleware(staticKey, store, testHMACKey)(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+staticKey)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !handler.called {
		t.Fatalf("got next handler not called, want it called (pass-through)")
	}
	// The Bearer path only activates for "Bearer wgui_" prefixed tokens.
	// A static key without wgui_ prefix should not match.
	if handler.claims != nil {
		t.Errorf("got claims %+v, want nil (static key via Bearer without wgui_ prefix should pass through)", handler.claims)
	}
}
