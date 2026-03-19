package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestGroupHandler_List(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "GET", "/api/v1/groups/", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Data []domain.Group `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// mockStore returns empty slice
	if resp.Data == nil {
		t.Error("expected non-nil data array")
	}
}

func TestGroupHandler_Create(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "POST", "/api/v1/groups/", token, `{"name":"test-group"}`)

	if rr.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusCreated, rr.Body.String())
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
	if resp.Data.Name != "test-group" {
		t.Errorf("got name %q, want %q", resp.Data.Name, "test-group")
	}
	if resp.Data.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestGroupHandler_Create_MissingName(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "POST", "/api/v1/groups/", token, `{}`)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestGroupHandler_Get_NotFound(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "GET", "/api/v1/groups/nonexistent", token, "")

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}
