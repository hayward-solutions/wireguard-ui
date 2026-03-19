package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddleware_ValidToken(t *testing.T) {
	t.Helper()

	jwtMgr := newTestJWTManager(t, "mw-secret", time.Hour)
	token := issueTestToken(t, jwtMgr, "user-1", "alice@example.com", "Alice", "admin")

	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(jwtMgr)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if got, want := rr.Code, http.StatusOK; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	if gotClaims == nil {
		t.Fatalf("got nil claims, want non-nil")
	}
	if got, want := gotClaims.Email, "alice@example.com"; got != want {
		t.Errorf("got Email %q, want %q", got, want)
	}
	if got, want := gotClaims.Role, "admin"; got != want {
		t.Errorf("got Role %q, want %q", got, want)
	}
}

func TestMiddleware_MissingToken(t *testing.T) {
	jwtMgr := newTestJWTManager(t, "mw-secret", time.Hour)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := Middleware(jwtMgr)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if got, want := rr.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	if called {
		t.Errorf("got next handler called, want it not called")
	}
	body := rr.Body.String()
	if got, want := body, "missing token"; !containsSubstring(body, want) {
		t.Errorf("got body %q, want it to contain %q", got, want)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	jwtMgr := newTestJWTManager(t, "mw-secret", time.Hour)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	mw := Middleware(jwtMgr)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-garbage")
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if got, want := rr.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	if called {
		t.Errorf("got next handler called, want it not called")
	}
	body := rr.Body.String()
	if got, want := body, "invalid token"; !containsSubstring(body, want) {
		t.Errorf("got body %q, want it to contain %q", got, want)
	}
}

func TestMiddleware_TokenFromCookie(t *testing.T) {
	jwtMgr := newTestJWTManager(t, "mw-secret", time.Hour)
	token := issueTestToken(t, jwtMgr, "user-2", "bob@example.com", "Bob", "viewer")

	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(jwtMgr)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: token})
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if got, want := rr.Code, http.StatusOK; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	if gotClaims == nil {
		t.Fatalf("got nil claims, want non-nil")
	}
	if got, want := gotClaims.Email, "bob@example.com"; got != want {
		t.Errorf("got Email %q, want %q", got, want)
	}
}

func TestMiddleware_ClaimsAlreadySet(t *testing.T) {
	jwtMgr := newTestJWTManager(t, "mw-secret", time.Hour)

	preClaims := &Claims{
		Email: "pre@example.com",
		Name:  "Pre-Set",
		Role:  "editor",
	}

	called := false
	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		gotClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(jwtMgr)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	// No Authorization header, no cookie — but claims are pre-set.
	ctx := SetClaims(req.Context(), preClaims)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("got next handler not called, want it called")
	}
	if got, want := rr.Code, http.StatusOK; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	if gotClaims == nil {
		t.Fatalf("got nil claims, want non-nil")
	}
	if got, want := gotClaims.Email, "pre@example.com"; got != want {
		t.Errorf("got Email %q, want %q", got, want)
	}
}

func TestSetClaims_ClaimsFromContext_Roundtrip(t *testing.T) {
	original := &Claims{
		Email: "rt@example.com",
		Name:  "Round Trip",
		Role:  "admin",
	}
	original.Subject = "subj-99"

	ctx := SetClaims(context.Background(), original)
	got := ClaimsFromContext(ctx)

	if got == nil {
		t.Fatalf("got nil claims, want non-nil")
	}
	if got.Subject != original.Subject {
		t.Errorf("got Subject %q, want %q", got.Subject, original.Subject)
	}
	if got.Email != original.Email {
		t.Errorf("got Email %q, want %q", got.Email, original.Email)
	}
	if got.Name != original.Name {
		t.Errorf("got Name %q, want %q", got.Name, original.Name)
	}
	if got.Role != original.Role {
		t.Errorf("got Role %q, want %q", got.Role, original.Role)
	}
}

func TestClaimsFromContext_EmptyContext(t *testing.T) {
	got := ClaimsFromContext(context.Background())
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// containsSubstring is a small helper to keep assertions readable.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && contains(s, substr))
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
