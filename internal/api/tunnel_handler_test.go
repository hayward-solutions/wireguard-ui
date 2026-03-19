package api

import (
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// The tunnel handler calls tunnelMgr.IsRunning() in HandleList,
// which will panic if tunnelMgr is nil. Since buildTestRouter does
// not provide a TunnelManager, the routes are registered but will
// panic on any handler that touches tunnelMgr. We test authorization
// enforcement here: a non-admin should be rejected by RequireAdmin
// middleware *before* the handler runs.

func TestTunnelHandler_List_NonAdmin(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleEditor)
	rr := doRequest(router, "GET", "/api/v1/tunnels/", token, "")

	if rr.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusForbidden, rr.Body.String())
	}
}

func TestTunnelHandler_List_Admin(t *testing.T) {
	// HandleList calls tunnelMgr.IsRunning which panics when tunnelMgr is nil.
	// The router's Recoverer middleware converts panics into 500 responses.
	// This test verifies that admin auth passes (i.e. we don't get 401/403).
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "GET", "/api/v1/tunnels/", token, "")

	// We accept 500 because the mock has no TunnelManager, causing a nil
	// pointer dereference. The key assertion is that we are NOT blocked
	// by authorization (401 or 403).
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Errorf("admin should not be blocked by authz, got status %d (body: %s)", rr.Code, rr.Body.String())
	}
}
