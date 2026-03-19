package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func TestUserHandler_List(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/users/", token, "")

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
		t.Errorf("expected 1 user, got %d", len(data))
	}
}

func TestUserHandler_Create(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	body := `{"username":"newuser","password":"Test1234","role":"viewer"}`
	rr := doRequest(router, "POST", "/api/v1/users/", token, body)

	if rr.Code != http.StatusCreated {
		t.Fatalf("got status %d, want 201 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Username != "newuser" {
		t.Errorf("username = %q, want %q", resp.Data.Username, "newuser")
	}
	if resp.Data.Role != "viewer" {
		t.Errorf("role = %q, want %q", resp.Data.Role, "viewer")
	}
	if resp.Data.ID == "" {
		t.Error("expected non-empty user ID")
	}
}

func TestUserHandler_Create_WeakPassword(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	body := `{"username":"newuser","password":"weak","role":"viewer"}`
	rr := doRequest(router, "POST", "/api/v1/users/", token, body)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_Create_MissingUsername(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	body := `{"username":"","password":"Test1234","role":"viewer"}`
	rr := doRequest(router, "POST", "/api/v1/users/", token, body)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_Get(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/users/"+testUserID, token, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.ID != testUserID {
		t.Errorf("id = %q, want %q", resp.Data.ID, testUserID)
	}
	if resp.Data.Username != "testuser" {
		t.Errorf("username = %q, want %q", resp.Data.Username, "testuser")
	}
}

func TestUserHandler_Get_NotFound(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "GET", "/api/v1/users/nonexistent", token, "")

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want 404 (body: %s)", rr.Code, rr.Body.String())
	}
}

func TestUserHandler_Delete_Self(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)
	// The token subject is testUserID; trying to delete yourself should fail
	token := issueToken(t, domain.RoleAdmin)

	rr := doRequest(router, "DELETE", "/api/v1/users/"+testUserID, token, "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400 (body: %s)", rr.Code, rr.Body.String())
	}
}
