package api

import (
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestExportHandler_Config(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleViewer)
	rr := doRequest(router, "GET", "/api/v1/peers/"+testPeerID+"/config", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("got Content-Type %q, want %q", ct, "text/plain")
	}

	body := rr.Body.String()
	if body == "" {
		t.Error("expected non-empty config body")
	}
}

func TestExportHandler_Config_NotOwner(t *testing.T) {
	store := newMockStore()
	// The test peer is owned by testUserID (user-001). Our tokens are
	// also issued for user-001, so any role can access their own peer.
	// Create a peer owned by a different user.
	store.peers = append(store.peers, domain.Peer{
		ID:        "peer-other",
		Name:      "other-peer",
		PublicKey: "other-pub-key",
		Address:   "10.0.0.3/32",
		CreatedBy: "user-other",
		Enabled:   true,
	})

	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleViewer)

	rr := doRequest(router, "GET", "/api/v1/peers/peer-other/config", token, "")

	// requirePeerAccess returns 404 (not 403) for non-owners to avoid
	// leaking the existence of peers belonging to other users.
	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d (non-owner viewer should get 404)", rr.Code, http.StatusNotFound)
	}
}

func TestExportHandler_Config_NotFound(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "GET", "/api/v1/peers/nonexistent/config", token, "")

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

func TestExportHandler_QRCode(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleViewer)
	rr := doRequest(router, "GET", "/api/v1/peers/"+testPeerID+"/qrcode", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "image/png" {
		t.Errorf("got Content-Type %q, want %q", ct, "image/png")
	}

	if rr.Body.Len() == 0 {
		t.Error("expected non-empty QR code body")
	}
}
