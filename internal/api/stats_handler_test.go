package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestStatsHandler_Get(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleViewer)

	rr := doRequest(router, "GET", "/api/v1/stats", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("got Content-Type %q, want %q", ct, "application/json")
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The mock WG manager returns an empty stats slice; data should be an array
	data, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("expected data to be an array, got %T", resp.Data)
	}
	_ = data
}
