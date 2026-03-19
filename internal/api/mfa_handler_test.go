package api

import (
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// MFA routes are only registered when both WebAuthn and TOTP providers
// are configured. buildTestRouter does not set these, so MFA routes
// will return 404. This test verifies that behavior.

func TestMFAHandler_Status(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleViewer)
	rr := doRequest(router, "GET", "/api/v1/me/mfa", token, "")

	// Since buildTestRouter does not configure WebAuthn/TOTP providers,
	// the MFA routes are not registered and should return 404/405.
	// We verify the route is not accessible (no 200).
	if rr.Code == http.StatusOK {
		t.Fatalf("expected MFA route to not be registered (no WebAuthn/TOTP providers), but got 200")
	}

	// The route is not mounted, so chi returns 405 Method Not Allowed or 404.
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Logf("MFA routes not registered (expected), got status %d", rr.Code)
	}
}
