package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedProxyMiddleware_NoProxies_IgnoresHeaders(t *testing.T) {
	handler := TrustedProxyMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Addr", r.RemoteAddr)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:4567"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Got-Addr"); got != "203.0.113.1:4567" {
		t.Errorf("with no trusted proxies, RemoteAddr should be unchanged; got %q", got)
	}
}

func TestTrustedProxyMiddleware_UntrustedPeer_IgnoresHeaders(t *testing.T) {
	handler := TrustedProxyMiddleware([]string{"10.0.0.0/8"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Addr", r.RemoteAddr)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:4567" // not in 10.0.0.0/8
	req.Header.Set("X-Forwarded-For", "evil.spoofed.ip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Got-Addr"); got != "203.0.113.1:4567" {
		t.Errorf("untrusted peer: RemoteAddr should be unchanged; got %q", got)
	}
}

func TestTrustedProxyMiddleware_TrustedPeer_ExtractsClientIP(t *testing.T) {
	handler := TrustedProxyMiddleware([]string{"10.0.0.1"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Addr", r.RemoteAddr)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:9999" // trusted proxy
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Got-Addr"); got != "203.0.113.50:0" {
		t.Errorf("trusted peer: expected client IP 203.0.113.50:0; got %q", got)
	}
}

func TestTrustedProxyMiddleware_TrustedPeer_XRealIP(t *testing.T) {
	handler := TrustedProxyMiddleware([]string{"10.0.0.1"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Addr", r.RemoteAddr)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Real-IP", "198.51.100.5")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-Got-Addr"); got != "198.51.100.5:0" {
		t.Errorf("trusted peer with X-Real-IP: expected 198.51.100.5:0; got %q", got)
	}
}

func TestTrustedProxyMiddleware_ChainOfProxies(t *testing.T) {
	// Two trusted proxies in chain: client -> proxy1(10.0.0.2) -> proxy2(10.0.0.1) -> server
	handler := TrustedProxyMiddleware([]string{"10.0.0.0/8"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Addr", r.RemoteAddr)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.2, 10.0.0.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should skip trusted 10.0.0.1 and 10.0.0.2, return the real client
	if got := w.Header().Get("X-Got-Addr"); got != "203.0.113.99:0" {
		t.Errorf("proxy chain: expected 203.0.113.99:0; got %q", got)
	}
}

func TestParseCIDRs(t *testing.T) {
	nets := parseCIDRs([]string{"10.0.0.1", "192.168.0.0/16", "", "  "})
	if len(nets) != 2 {
		t.Fatalf("expected 2 parsed CIDRs, got %d", len(nets))
	}
}
