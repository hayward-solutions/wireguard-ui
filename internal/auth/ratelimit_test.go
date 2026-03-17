package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(1, 2) // 1/s, burst 2
	defer rl.Stop()

	if !rl.Allow("key") {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow("key") {
		t.Fatal("second request (burst) should be allowed")
	}
	if rl.Allow("key") {
		t.Fatal("third request should be rate-limited")
	}
}

func TestRateLimiter_SeparateKeys(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	defer rl.Stop()

	if !rl.Allow("a") {
		t.Fatal("first key should be allowed")
	}
	if !rl.Allow("b") {
		t.Fatal("different key should be allowed independently")
	}
}

func TestClientIP_StripsPort(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"192.168.1.1:12345", "192.168.1.1"},
		{"10.0.0.1:80", "10.0.0.1"},
		{"[::1]:8080", "::1"},
		{"192.168.1.1", "192.168.1.1"}, // no port fallback
	}
	for _, tt := range tests {
		r := &http.Request{RemoteAddr: tt.remoteAddr}
		got := clientIP(r)
		if got != tt.want {
			t.Errorf("clientIP(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
		}
	}
}

func TestIPRateLimitMiddleware_SameIPDifferentPorts(t *testing.T) {
	rl := NewRateLimiter(1, 1) // 1/s, burst 1
	defer rl.Stop()

	handler := IPRateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from port 1111 — allowed
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "10.0.0.5:1111"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", w1.Code)
	}

	// Second request from port 2222 (same IP) — should be rate-limited
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.5:2222"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request (same IP, different port): got %d, want 429", w2.Code)
	}
}
