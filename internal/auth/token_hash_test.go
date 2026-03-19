package auth

import (
	"testing"
)

func TestHashAPIToken(t *testing.T) {
	key := []byte("test-hmac-key")

	// Same input produces same output
	h1 := HashAPIToken(key, "wgui_abc123")
	h2 := HashAPIToken(key, "wgui_abc123")
	if h1 != h2 {
		t.Error("same input produced different hashes")
	}

	// Different input produces different output
	h3 := HashAPIToken(key, "wgui_xyz789")
	if h1 == h3 {
		t.Error("different inputs produced same hash")
	}

	// Different key produces different output
	h4 := HashAPIToken([]byte("other-key"), "wgui_abc123")
	if h1 == h4 {
		t.Error("different keys produced same hash")
	}

	// Output is hex-encoded (64 chars for SHA-256)
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64", len(h1))
	}
}
