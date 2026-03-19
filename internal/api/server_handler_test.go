package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestServerHandler_Get_ResponseShape(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/server", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ListenPort           int                    `json:"listen_port"`
			Address              string                 `json:"address"`
			DNS                  string                 `json:"dns"`
			MTU                  int                    `json:"mtu"`
			Endpoint             string                 `json:"endpoint"`
			PublicKey            string                 `json:"public_key"`
			PostUp               string                 `json:"post_up"`
			PostDown             string                 `json:"post_down"`
			FirewallConfig       *domain.FirewallConfig `json:"firewall_config"`
			CustomScriptsAllowed bool                   `json:"custom_scripts_allowed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Data.ListenPort != 51820 {
		t.Errorf("listen_port = %d, want 51820", resp.Data.ListenPort)
	}
	if resp.Data.Address != "10.0.0.1/24" {
		t.Errorf("address = %q, want %q", resp.Data.Address, "10.0.0.1/24")
	}
	if resp.Data.Endpoint != "vpn.example.com:51820" {
		t.Errorf("endpoint = %q, want %q", resp.Data.Endpoint, "vpn.example.com:51820")
	}
	if resp.Data.PublicKey != "test-pub-key" {
		t.Errorf("public_key = %q, want %q", resp.Data.PublicKey, "test-pub-key")
	}
	if resp.Data.DNS != "1.1.1.1" {
		t.Errorf("dns = %q, want %q", resp.Data.DNS, "1.1.1.1")
	}
	if resp.Data.MTU != 1420 {
		t.Errorf("mtu = %d, want 1420", resp.Data.MTU)
	}
}

func TestServerHandler_Update_ValidPayload(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	body := `{"listen_port":51821,"address":"10.0.0.1/24","endpoint":"vpn.example.com:51821"}`
	rr := doRequest(router, "PUT", "/api/v1/server", token, body)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ListenPort int    `json:"listen_port"`
			Endpoint   string `json:"endpoint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.ListenPort != 51821 {
		t.Errorf("listen_port = %d, want 51821", resp.Data.ListenPort)
	}
}

func TestServerHandler_Update_InvalidJSON(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "PUT", "/api/v1/server", token, `{invalid json`)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestServerHandler_Apply(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "POST", "/api/v1/server/apply", token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Message != "config applied" {
		t.Errorf("message = %q, want %q", resp.Data.Message, "config applied")
	}
}
