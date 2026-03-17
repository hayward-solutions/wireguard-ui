package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSRedirectMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTPSRedirectMiddleware(ok)

	t.Run("redirects plain HTTP to HTTPS", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/dashboard", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301, got %d", rr.Code)
		}
		loc := rr.Header().Get("Location")
		if loc != "https://example.com/dashboard" {
			t.Errorf("expected redirect to https://example.com/dashboard, got %s", loc)
		}
	})

	t.Run("passes through when X-Forwarded-Proto is https", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/dashboard", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		hsts := rr.Header().Get("Strict-Transport-Security")
		if hsts != "max-age=63072000; includeSubDomains" {
			t.Errorf("expected HSTS header, got %q", hsts)
		}
	})

	t.Run("health check exempt from redirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/api/v1/health", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("handles X-Forwarded-Proto case insensitively", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.Header.Set("X-Forwarded-Proto", "HTTPS")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("redirects POST requests", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://example.com/auth/login", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMovedPermanently {
			t.Errorf("expected 301, got %d", rr.Code)
		}
	})

	t.Run("preserves query string in redirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/page?foo=bar&baz=1", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		loc := rr.Header().Get("Location")
		if loc != "https://example.com/page?foo=bar&baz=1" {
			t.Errorf("expected query string preserved, got %s", loc)
		}
	})
}
