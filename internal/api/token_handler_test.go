package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestTokenHandler_List(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleViewer)

	rr := doRequest(router, "GET", "/api/v1/me/tokens", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The mock returns an empty slice, so data should be an array
	data, ok := resp.Data.([]interface{})
	if !ok {
		t.Fatalf("expected data to be an array, got %T", resp.Data)
	}
	// Empty list is fine — mockStore returns []domain.APIToken{}
	_ = data
}

func TestTokenHandler_Create(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleViewer)

	rr := doRequest(router, "POST", "/api/v1/me/tokens", token, `{"name":"my-token"}`)

	if rr.Code != http.StatusCreated {
		t.Fatalf("got status %d, want 201 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Token       string `json:"token"`
			TokenPrefix string `json:"token_prefix"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Data.Token == "" {
		t.Error("expected non-empty token (one-time disclosure)")
	}
	if resp.Data.Name != "my-token" {
		t.Errorf("name = %q, want %q", resp.Data.Name, "my-token")
	}
	if resp.Data.ID == "" {
		t.Error("expected non-empty token ID")
	}
	if resp.Data.TokenPrefix == "" {
		t.Error("expected non-empty token_prefix")
	}
}

func TestTokenHandler_Create_MissingName(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleViewer)

	rr := doRequest(router, "POST", "/api/v1/me/tokens", token, `{}`)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400 (body: %s)", rr.Code, rr.Body.String())
	}
}
