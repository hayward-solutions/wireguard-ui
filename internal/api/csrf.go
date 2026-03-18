package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenBytes = 16 // 32 hex characters
)

// CSRFMiddleware validates that mutating requests (POST, PUT, DELETE, PATCH)
// include an X-CSRF-Token header matching the csrf_token cookie.
//
// Requests with explicit Authorization or X-API-Key headers are exempt
// because they don't rely on ambient cookie credentials.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't need CSRF protection.
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		// Requests with explicit auth headers are not CSRF-vulnerable.
		if isExplicitAuthRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(csrfCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusForbidden, "CSRF_FAILED", "missing CSRF token")
			return
		}

		header := r.Header.Get(csrfHeaderName)
		if header == "" || header != cookie.Value {
			writeError(w, http.StatusForbidden, "CSRF_FAILED", "CSRF token mismatch")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isExplicitAuthRequest returns true if the request carries explicit (non-cookie)
// credentials: an X-API-Key header or an Authorization header. Such requests
// don't rely on ambient cookie auth and are therefore not CSRF-vulnerable.
func isExplicitAuthRequest(r *http.Request) bool {
	if r.Header.Get("X-API-Key") != "" {
		return true
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return true
	}
	return false
}

// GenerateCSRFToken returns a cryptographically random hex-encoded token.
func GenerateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
