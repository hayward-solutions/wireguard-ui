package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler is a trivial handler used as the "next" in middleware tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestCSRFMiddleware_SafeMethods(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("safe method %s: got %d, want 200", method, rr.Code)
			}
		})
	}
}

func TestCSRFMiddleware_MissingToken(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("missing CSRF token: got %d, want 403", rr.Code)
	}
}

func TestCSRFMiddleware_MismatchedToken(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "token-aaa"})
	req.Header.Set(csrfHeaderName, "token-bbb")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("mismatched CSRF token: got %d, want 403", rr.Code)
	}
}

func TestCSRFMiddleware_MatchingToken(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	token := "valid-csrf-token-12345"
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
	req.Header.Set(csrfHeaderName, token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("matching CSRF token: got %d, want 200", rr.Code)
	}
}

func TestCSRFMiddleware_ExemptWithAPIKey(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("X-API-Key", "some-api-key")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("X-API-Key exempt: got %d, want 200", rr.Code)
	}
}

func TestCSRFMiddleware_ExemptWithBearerToken(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Bearer token exempt: got %d, want 200", rr.Code)
	}
}

func TestCSRFMiddleware_AllMutatingMethods(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method+"_blocked_without_token", func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s without CSRF: got %d, want 403", method, rr.Code)
			}
		})

		t.Run(method+"_allowed_with_token", func(t *testing.T) {
			token := "test-csrf-token"
			req := httptest.NewRequest(method, "/", nil)
			req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
			req.Header.Set(csrfHeaderName, token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("%s with CSRF: got %d, want 200", method, rr.Code)
			}
		})
	}
}

func TestCSRFMiddleware_EmptyCookieValue(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: ""})
	req.Header.Set(csrfHeaderName, "something")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("empty cookie: got %d, want 403", rr.Code)
	}
}

func TestCSRFMiddleware_EmptyHeaderValue(t *testing.T) {
	handler := CSRFMiddleware(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "token"})
	req.Header.Set(csrfHeaderName, "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("empty header: got %d, want 403", rr.Code)
	}
}

func TestGenerateCSRFToken(t *testing.T) {
	token, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken: %v", err)
	}
	if len(token) != csrfTokenBytes*2 {
		t.Errorf("token length = %d, want %d hex chars", len(token), csrfTokenBytes*2)
	}

	// Tokens should be unique
	token2, err := GenerateCSRFToken()
	if err != nil {
		t.Fatalf("GenerateCSRFToken (2nd): %v", err)
	}
	if token == token2 {
		t.Error("two generated tokens should not be equal")
	}
}
