package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestAuthHandler_Info(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	// /auth/info is unauthenticated
	rr := doRequest(router, "GET", "/auth/info", "", "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Data struct {
			OIDCEnabled    bool `json:"oidc_enabled"`
			LocalEnabled   bool `json:"local_enabled"`
			WebAuthnEnabled bool `json:"webauthn_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// buildTestRouter does not configure OIDC or WebAuthn
	if resp.Data.OIDCEnabled {
		t.Error("expected oidc_enabled=false")
	}
	if !resp.Data.LocalEnabled {
		t.Error("expected local_enabled=true")
	}
	if resp.Data.WebAuthnEnabled {
		t.Error("expected webauthn_enabled=false")
	}
}

func TestAuthHandler_Info_SetsCSRFCookie(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	req := httptest.NewRequest("GET", "/auth/info", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var found bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "csrf_token" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected csrf_token cookie to be set on /auth/info when none present")
	}
}

func TestAuthHandler_Info_PreservesExistingCSRFCookie(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	req := httptest.NewRequest("GET", "/auth/info", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "existing-token"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	for _, c := range rr.Result().Cookies() {
		if c.Name == "csrf_token" {
			t.Error("expected no new csrf_token cookie when one already exists")
		}
	}
}

func TestAuthHandler_Login_RequiresCSRF(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	// POST /auth/login without CSRF token should be rejected.
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"admin","password":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestAuthHandler_Login_CSRFPassesWithToken(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	// POST /auth/login with matching CSRF cookie+header should pass CSRF check.
	// The login itself will fail (bad credentials) but should NOT be 403 CSRF_FAILED.
	csrfToken := "test-csrf-token-value"
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"nonexistent","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should get past CSRF (not 403 CSRF_FAILED). Expect 401 for bad credentials.
	if rr.Code == http.StatusForbidden {
		t.Fatalf("CSRF should have passed with matching token, got 403 (body: %s)", rr.Body.String())
	}
}

func TestAuthHandler_Me(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleViewer)
	rr := doRequest(router, "GET", "/auth/me", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.ID != testUserID {
		t.Errorf("got id %q, want %q", resp.Data.ID, testUserID)
	}
	if resp.Data.Role != domain.RoleViewer {
		t.Errorf("got role %q, want %q", resp.Data.Role, domain.RoleViewer)
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	// Logout is a POST that goes through CSRF middleware.
	// Since doRequest sets Authorization header, CSRF is bypassed.
	token := issueToken(t, domain.RoleViewer)
	rr := doRequest(router, "POST", "/auth/logout", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify the token cookie is cleared
	cookies := rr.Result().Cookies()
	tokenCleared := false
	for _, c := range cookies {
		if c.Name == "token" && c.MaxAge < 0 {
			tokenCleared = true
			break
		}
	}
	if !tokenCleared {
		t.Error("expected token cookie to be cleared (MaxAge < 0)")
	}

	// Verify the session cookie is cleared
	sessionCleared := false
	for _, c := range cookies {
		if c.Name == "session" && c.MaxAge < 0 {
			sessionCleared = true
			break
		}
	}
	if !sessionCleared {
		t.Error("expected session cookie to be cleared (MaxAge < 0)")
	}
}
