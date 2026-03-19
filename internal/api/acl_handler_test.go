package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestACLHandler_List(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	rr := doRequest(router, "GET", "/api/v1/acls/", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Data []domain.ACLRule `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data == nil {
		t.Error("expected non-nil data array")
	}
}

func TestACLHandler_Create(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	body := `{"name":"allow-web","dst_cidr":"10.0.0.0/24","protocol":"tcp","dst_ports":"80,443"}`
	rr := doRequest(router, "POST", "/api/v1/acls/", token, body)

	if rr.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			DstCIDR  string `json:"dst_cidr"`
			Protocol string `json:"protocol"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Name != "allow-web" {
		t.Errorf("got name %q, want %q", resp.Data.Name, "allow-web")
	}
	if resp.Data.Protocol != "tcp" {
		t.Errorf("got protocol %q, want %q", resp.Data.Protocol, "tcp")
	}
}

func TestACLHandler_Create_InvalidProtocol(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	token := issueToken(t, domain.RoleAdmin)
	body := `{"name":"bad-rule","dst_cidr":"10.0.0.0/24","protocol":"icmp"}`
	rr := doRequest(router, "POST", "/api/v1/acls/", token, body)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}
