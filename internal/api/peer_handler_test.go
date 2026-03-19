package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestPeerHandler_List(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/peers", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("expected data to be an array, got %T", resp.Data)
	}
	if len(data) != 1 {
		t.Errorf("expected 1 peer, got %d", len(data))
	}
}

func TestPeerHandler_Get(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/peers/"+testPeerID, token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.ID != testPeerID {
		t.Errorf("got peer ID %q, want %q", resp.Data.ID, testPeerID)
	}
	if resp.Data.Name != "test-peer" {
		t.Errorf("got peer name %q, want %q", resp.Data.Name, "test-peer")
	}
}

func TestPeerHandler_Get_NotFound(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/peers/nonexistent", token, "")

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want 404 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestPeerHandler_Create_Viewer(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleViewer)

	rr := doRequest(router, "POST", "/api/v1/peers", token, `{"name":"new-peer"}`)

	if rr.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestPeerHandler_Config(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/peers/"+testPeerID+"/config", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
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

func TestPeerHandler_QR(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/peers/"+testPeerID+"/qrcode", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "image/png" {
		t.Errorf("got Content-Type %q, want %q", ct, "image/png")
	}

	if rr.Body.Len() == 0 {
		t.Error("expected non-empty QR code body")
	}
}

func TestPeerHandler_Toggle(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "PATCH", "/api/v1/peers/"+testPeerID+"/toggle", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			Enabled bool `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The default peer is enabled=true, toggling should make it false
	if resp.Data.Enabled != false {
		t.Errorf("expected enabled=false after toggle, got %v", resp.Data.Enabled)
	}
}
