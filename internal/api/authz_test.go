package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/monitor"
)

// --- Test constants ---

const (
	testUserID  = "user-001"
	testPeerID  = "peer-001"
	testJWTSecret = "test-secret-for-authz-tests"
)

// --- Mock Store ---

type mockStore struct {
	serverConfig *domain.ServerConfig
	peers        []domain.Peer
	users        []domain.User
}

func newMockStore() *mockStore {
	return &mockStore{
		serverConfig: &domain.ServerConfig{
			ID:         "srv-001",
			PublicKey:  "test-pub-key",
			ListenPort: 51820,
			Address:    "10.0.0.1/24",
			DNS:        "1.1.1.1",
			MTU:        1420,
			Endpoint:   "vpn.example.com:51820",
			PostUp:     "iptables -A FORWARD -i wg0 -j ACCEPT",
			PostDown:   "iptables -D FORWARD -i wg0 -j ACCEPT",
			FirewallConfig: &domain.FirewallConfig{
				EnableNAT:        true,
				EnableForwarding: true,
				NATOutInterface:  "eth0",
			},
		},
		peers: []domain.Peer{
			{
				ID:        testPeerID,
				Name:      "test-peer",
				PublicKey: "peer-pub-key",
				Address:   "10.0.0.2/32",
				AllowedIPs: "0.0.0.0/0",
				DNS:       "1.1.1.1",
				PersistentKeepalive: 25,
				Enabled:   true,
				CreatedBy: testUserID,
			},
		},
		users: []domain.User{
			{
				ID:       testUserID,
				Username: "testuser",
				Name:     "Test User",
				Role:     domain.RoleViewer,
			},
		},
	}
}

func (s *mockStore) GetServerConfig(_ context.Context) (*domain.ServerConfig, error) {
	if s.serverConfig == nil {
		return nil, nil
	}
	// Return a copy so handler mutations don't affect the mock
	cp := *s.serverConfig
	if s.serverConfig.FirewallConfig != nil {
		fc := *s.serverConfig.FirewallConfig
		cp.FirewallConfig = &fc
	}
	return &cp, nil
}
func (s *mockStore) SaveServerConfig(_ context.Context, _ *domain.ServerConfig) error { return nil }

func (s *mockStore) ListPeers(_ context.Context) ([]domain.Peer, error) { return s.peers, nil }
func (s *mockStore) ListPeersByUser(_ context.Context, userID string) ([]domain.Peer, error) {
	var result []domain.Peer
	for _, p := range s.peers {
		if p.CreatedBy == userID {
			result = append(result, p)
		}
	}
	return result, nil
}
func (s *mockStore) GetPeer(_ context.Context, id string) (*domain.Peer, error) {
	for i := range s.peers {
		if s.peers[i].ID == id {
			return &s.peers[i], nil
		}
	}
	return nil, nil
}
func (s *mockStore) CreatePeer(_ context.Context, _ *domain.Peer) error  { return nil }
func (s *mockStore) UpdatePeer(_ context.Context, _ *domain.Peer) error  { return nil }
func (s *mockStore) DeletePeer(_ context.Context, _ string) error        { return nil }

func (s *mockStore) ListUsers(_ context.Context) ([]domain.User, error) { return s.users, nil }
func (s *mockStore) GetUser(_ context.Context, id string) (*domain.User, error) {
	for i := range s.users {
		if s.users[i].ID == id {
			return &s.users[i], nil
		}
	}
	return nil, nil
}
func (s *mockStore) GetUserByUsername(_ context.Context, username string) (*domain.User, error) {
	for i := range s.users {
		if s.users[i].Username == username {
			return &s.users[i], nil
		}
	}
	return nil, nil
}
func (s *mockStore) CreateUser(_ context.Context, _ *domain.User) error          { return nil }
func (s *mockStore) UpdateUser(_ context.Context, _ *domain.User) error          { return nil }
func (s *mockStore) UpdateUserPassword(_ context.Context, _ string, _ string) error { return nil }
func (s *mockStore) DeleteUser(_ context.Context, _ string) error                { return nil }

func (s *mockStore) ListAPITokensByUser(_ context.Context, _ string) ([]domain.APIToken, error) {
	return []domain.APIToken{}, nil
}
func (s *mockStore) GetAPITokenByHash(_ context.Context, _ string) (*domain.APIToken, error) {
	return nil, nil
}
func (s *mockStore) CreateAPIToken(_ context.Context, _ *domain.APIToken) error { return nil }
func (s *mockStore) DeleteAPIToken(_ context.Context, _ string) error           { return nil }
func (s *mockStore) UpdateAPITokenLastUsed(_ context.Context, _ string) error   { return nil }

func (s *mockStore) ListGroups(_ context.Context) ([]domain.Group, error)          { return []domain.Group{}, nil }
func (s *mockStore) GetGroup(_ context.Context, _ string) (*domain.Group, error)   { return nil, nil }
func (s *mockStore) GetGroupByName(_ context.Context, _ string) (*domain.Group, error) { return nil, nil }
func (s *mockStore) CreateGroup(_ context.Context, _ *domain.Group) error          { return nil }
func (s *mockStore) UpdateGroup(_ context.Context, _ *domain.Group) error          { return nil }
func (s *mockStore) DeleteGroup(_ context.Context, _ string) error                 { return nil }

func (s *mockStore) GetUserGroups(_ context.Context, _ string) ([]domain.Group, error) {
	return []domain.Group{}, nil
}
func (s *mockStore) SetUserGroups(_ context.Context, _ string, _ []string) error  { return nil }
func (s *mockStore) SyncOIDCGroups(_ context.Context, _ string, _ []string) error { return nil }
func (s *mockStore) GetGroupMembers(_ context.Context, _ string) ([]domain.User, error) {
	return []domain.User{}, nil
}

func (s *mockStore) ListACLRules(_ context.Context) ([]domain.ACLRule, error) {
	return []domain.ACLRule{}, nil
}
func (s *mockStore) GetACLRule(_ context.Context, _ string) (*domain.ACLRule, error) { return nil, nil }
func (s *mockStore) CreateACLRule(_ context.Context, _ *domain.ACLRule) error        { return nil }
func (s *mockStore) UpdateACLRule(_ context.Context, _ *domain.ACLRule) error        { return nil }
func (s *mockStore) DeleteACLRule(_ context.Context, _ string) error                 { return nil }
func (s *mockStore) GetEffectiveACLRules(_ context.Context, _ string) ([]domain.ACLRule, error) {
	return []domain.ACLRule{}, nil
}

func (s *mockStore) RecordFailedLogin(_ context.Context, _ string) (int, error) { return 0, nil }
func (s *mockStore) ResetFailedLogins(_ context.Context, _ string) error        { return nil }
func (s *mockStore) LockUser(_ context.Context, _ string, _ time.Time) error    { return nil }
func (s *mockStore) UpdateLastLogin(_ context.Context, _ string) error          { return nil }

func (s *mockStore) CreateSession(_ context.Context, _ *domain.Session) error { return nil }
func (s *mockStore) GetSession(_ context.Context, _ string) (*domain.Session, error) {
	return nil, nil
}
func (s *mockStore) RevokeSession(_ context.Context, _ string) error      { return nil }
func (s *mockStore) RevokeUserSessions(_ context.Context, _ string) error { return nil }
func (s *mockStore) CleanExpiredSessions(_ context.Context) error         { return nil }

func (s *mockStore) ListTunnels(_ context.Context) ([]domain.Tunnel, error)       { return nil, nil }
func (s *mockStore) GetTunnel(_ context.Context, _ string) (*domain.Tunnel, error) { return nil, nil }
func (s *mockStore) CreateTunnel(_ context.Context, _ *domain.Tunnel) error       { return nil }
func (s *mockStore) UpdateTunnel(_ context.Context, _ *domain.Tunnel) error       { return nil }
func (s *mockStore) DeleteTunnel(_ context.Context, _ string) error               { return nil }

func (s *mockStore) HasEncryptedData(_ context.Context) (bool, error) { return false, nil }
func (s *mockStore) Migrate(_ context.Context) error                  { return nil }
func (s *mockStore) Close() error                                     { return nil }

// --- Mock WireGuard Manager ---

type mockWG struct{}

func (m *mockWG) Start(_ *domain.ServerConfig) error { return nil }
func (m *mockWG) AddPeer(_ *domain.Peer) error       { return nil }
func (m *mockWG) RemovePeer(_ string) error           { return nil }
func (m *mockWG) GetStats() ([]domain.PeerStats, error) {
	return []domain.PeerStats{}, nil
}
func (m *mockWG) Close() error { return nil }

// --- Test helpers ---

func buildTestRouter(store *mockStore) http.Handler {
	jwtMgr := auth.NewJWTManager(testJWTSecret, 15*time.Minute)
	wg := &mockWG{}
	mon := monitor.New(wg, 5*time.Second)

	return NewRouter(RouterConfig{
		Store:      store,
		WG:         wg,
		JWTManager: jwtMgr,
		Monitor:    mon,
		FrontendFS: nil,
	})
}

func issueToken(t *testing.T, role string) string {
	t.Helper()
	jwtMgr := auth.NewJWTManager(testJWTSecret, 15*time.Minute)
	token, err := jwtMgr.Issue(testUserID, "test@example.com", "Test User", role)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return token
}

func doRequest(router http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// --- Authorization Tests ---

func TestRouteAuthorization(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	tests := []struct {
		name       string
		method     string
		path       string
		role       string
		body       string
		wantStatus int
	}{
		// --- Server config ---
		{"admin can read server config", "GET", "/api/v1/server", domain.RoleAdmin, "", http.StatusOK},
		{"editor can read server config", "GET", "/api/v1/server", domain.RoleEditor, "", http.StatusOK},
		{"viewer can read server config", "GET", "/api/v1/server", domain.RoleViewer, "", http.StatusOK},
		{"admin can update server", "PUT", "/api/v1/server", domain.RoleAdmin, `{"listen_port":51820}`, http.StatusOK},
		{"editor cannot update server", "PUT", "/api/v1/server", domain.RoleEditor, `{"listen_port":51820}`, http.StatusForbidden},
		{"viewer cannot update server", "PUT", "/api/v1/server", domain.RoleViewer, `{"listen_port":51820}`, http.StatusForbidden},
		{"admin can apply server", "POST", "/api/v1/server/apply", domain.RoleAdmin, "", http.StatusOK},
		{"editor cannot apply server", "POST", "/api/v1/server/apply", domain.RoleEditor, "", http.StatusForbidden},
		{"viewer cannot apply server", "POST", "/api/v1/server/apply", domain.RoleViewer, "", http.StatusForbidden},

		// --- Peer list (all roles can list) ---
		{"admin can list peers", "GET", "/api/v1/peers", domain.RoleAdmin, "", http.StatusOK},
		{"editor can list peers", "GET", "/api/v1/peers", domain.RoleEditor, "", http.StatusOK},
		{"viewer can list peers", "GET", "/api/v1/peers", domain.RoleViewer, "", http.StatusOK},

		// --- Peer create (editor+) ---
		{"admin can create peer", "POST", "/api/v1/peers", domain.RoleAdmin, `{"name":"new-peer"}`, http.StatusCreated},
		{"editor can create peer", "POST", "/api/v1/peers", domain.RoleEditor, `{"name":"new-peer"}`, http.StatusCreated},
		{"viewer cannot create peer", "POST", "/api/v1/peers", domain.RoleViewer, `{"name":"new-peer"}`, http.StatusForbidden},

		// --- Peer get (ownership-checked, all roles) ---
		{"admin can get peer", "GET", "/api/v1/peers/" + testPeerID, domain.RoleAdmin, "", http.StatusOK},
		{"editor can get own peer", "GET", "/api/v1/peers/" + testPeerID, domain.RoleEditor, "", http.StatusOK},
		{"viewer can get own peer", "GET", "/api/v1/peers/" + testPeerID, domain.RoleViewer, "", http.StatusOK},

		// --- Peer update (editor+, ownership-checked) ---
		{"admin can update peer", "PUT", "/api/v1/peers/" + testPeerID, domain.RoleAdmin, `{"name":"updated"}`, http.StatusOK},
		{"editor can update own peer", "PUT", "/api/v1/peers/" + testPeerID, domain.RoleEditor, `{"name":"updated"}`, http.StatusOK},
		{"viewer cannot update own peer", "PUT", "/api/v1/peers/" + testPeerID, domain.RoleViewer, `{"name":"updated"}`, http.StatusForbidden},

		// --- Peer delete (editor+, ownership-checked) ---
		{"admin can delete peer", "DELETE", "/api/v1/peers/" + testPeerID, domain.RoleAdmin, "", http.StatusOK},
		{"editor can delete own peer", "DELETE", "/api/v1/peers/" + testPeerID, domain.RoleEditor, "", http.StatusOK},
		{"viewer cannot delete own peer", "DELETE", "/api/v1/peers/" + testPeerID, domain.RoleViewer, "", http.StatusForbidden},

		// --- Peer toggle (editor+, ownership-checked) ---
		{"admin can toggle peer", "PATCH", "/api/v1/peers/" + testPeerID + "/toggle", domain.RoleAdmin, "", http.StatusOK},
		{"editor can toggle own peer", "PATCH", "/api/v1/peers/" + testPeerID + "/toggle", domain.RoleEditor, "", http.StatusOK},
		{"viewer cannot toggle own peer", "PATCH", "/api/v1/peers/" + testPeerID + "/toggle", domain.RoleViewer, "", http.StatusForbidden},

		// --- Peer export (ownership-checked, all roles) ---
		{"admin can get peer config", "GET", "/api/v1/peers/" + testPeerID + "/config", domain.RoleAdmin, "", http.StatusOK},
		{"editor can get own peer config", "GET", "/api/v1/peers/" + testPeerID + "/config", domain.RoleEditor, "", http.StatusOK},
		{"viewer can get own peer config", "GET", "/api/v1/peers/" + testPeerID + "/config", domain.RoleViewer, "", http.StatusOK},

		// --- Stats (all roles can read) ---
		{"admin can get stats", "GET", "/api/v1/stats", domain.RoleAdmin, "", http.StatusOK},
		{"editor can get stats", "GET", "/api/v1/stats", domain.RoleEditor, "", http.StatusOK},
		{"viewer can get stats", "GET", "/api/v1/stats", domain.RoleViewer, "", http.StatusOK},

		// --- Self-service: tokens (all roles) ---
		{"admin can list tokens", "GET", "/api/v1/me/tokens", domain.RoleAdmin, "", http.StatusOK},
		{"editor can list tokens", "GET", "/api/v1/me/tokens", domain.RoleEditor, "", http.StatusOK},
		{"viewer can list tokens", "GET", "/api/v1/me/tokens", domain.RoleViewer, "", http.StatusOK},
		{"admin can create token", "POST", "/api/v1/me/tokens", domain.RoleAdmin, `{"name":"my-token"}`, http.StatusCreated},
		{"viewer can create token", "POST", "/api/v1/me/tokens", domain.RoleViewer, `{"name":"my-token"}`, http.StatusCreated},

		// --- Admin-only: groups ---
		{"admin can list groups", "GET", "/api/v1/groups/", domain.RoleAdmin, "", http.StatusOK},
		{"editor cannot list groups", "GET", "/api/v1/groups/", domain.RoleEditor, "", http.StatusForbidden},
		{"viewer cannot list groups", "GET", "/api/v1/groups/", domain.RoleViewer, "", http.StatusForbidden},

		// --- Admin-only: ACLs ---
		{"admin can list acls", "GET", "/api/v1/acls/", domain.RoleAdmin, "", http.StatusOK},
		{"editor cannot list acls", "GET", "/api/v1/acls/", domain.RoleEditor, "", http.StatusForbidden},
		{"viewer cannot list acls", "GET", "/api/v1/acls/", domain.RoleViewer, "", http.StatusForbidden},

		// --- Admin-only: users ---
		{"admin can list users", "GET", "/api/v1/users/", domain.RoleAdmin, "", http.StatusOK},
		{"editor cannot list users", "GET", "/api/v1/users/", domain.RoleEditor, "", http.StatusForbidden},
		{"viewer cannot list users", "GET", "/api/v1/users/", domain.RoleViewer, "", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := issueToken(t, tt.role)
			rr := doRequest(router, tt.method, tt.path, token, tt.body)

			if rr.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d (body: %s)", rr.Code, tt.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestUnauthenticatedRequests(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/server"},
		{"PUT", "/api/v1/server"},
		{"POST", "/api/v1/server/apply"},
		{"GET", "/api/v1/peers"},
		{"POST", "/api/v1/peers"},
		{"GET", "/api/v1/peers/" + testPeerID},
		{"PUT", "/api/v1/peers/" + testPeerID},
		{"DELETE", "/api/v1/peers/" + testPeerID},
		{"GET", "/api/v1/stats"},
		{"GET", "/api/v1/me/tokens"},
		{"GET", "/api/v1/groups/"},
		{"GET", "/api/v1/acls/"},
		{"GET", "/api/v1/users/"},
	}

	for _, p := range paths {
		t.Run(p.method+" "+p.path+" without auth", func(t *testing.T) {
			rr := doRequest(router, p.method, p.path, "", "")
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("got status %d, want %d", rr.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestServerConfigRedaction(t *testing.T) {
	store := newMockStore()
	router := buildTestRouter(store)

	type serverData struct {
		PostUp         string                 `json:"post_up"`
		PostDown       string                 `json:"post_down"`
		FirewallConfig *domain.FirewallConfig `json:"firewall_config,omitempty"`
		Endpoint       string                 `json:"endpoint"`
		PublicKey      string                 `json:"public_key"`
	}
	type serverEnvelope struct {
		Data serverData `json:"data"`
	}

	t.Run("admin sees full server config", func(t *testing.T) {
		token := issueToken(t, domain.RoleAdmin)
		rr := doRequest(router, "GET", "/api/v1/server", token, "")

		if rr.Code != http.StatusOK {
			t.Fatalf("got status %d, want 200", rr.Code)
		}

		var resp serverEnvelope
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if resp.Data.PostUp == "" {
			t.Error("admin should see post_up, got empty")
		}
		if resp.Data.PostDown == "" {
			t.Error("admin should see post_down, got empty")
		}
		if resp.Data.FirewallConfig == nil {
			t.Error("admin should see firewall_config, got nil")
		}
	})

	for _, role := range []string{domain.RoleEditor, domain.RoleViewer} {
		t.Run(role+" sees redacted server config", func(t *testing.T) {
			token := issueToken(t, role)
			rr := doRequest(router, "GET", "/api/v1/server", token, "")

			if rr.Code != http.StatusOK {
				t.Fatalf("got status %d, want 200", rr.Code)
			}

			var resp serverEnvelope
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if resp.Data.PostUp != "" {
				t.Errorf("%s should not see post_up, got %q", role, resp.Data.PostUp)
			}
			if resp.Data.PostDown != "" {
				t.Errorf("%s should not see post_down, got %q", role, resp.Data.PostDown)
			}
			if resp.Data.FirewallConfig != nil {
				t.Errorf("%s should not see firewall_config, got %v", role, resp.Data.FirewallConfig)
			}

			// Non-admins should still see non-sensitive fields
			if resp.Data.Endpoint == "" {
				t.Errorf("%s should still see endpoint", role)
			}
			if resp.Data.PublicKey == "" {
				t.Errorf("%s should still see public_key", role)
			}
		})
	}
}

func TestRoleRank(t *testing.T) {
	tests := []struct {
		role string
		want int
	}{
		{domain.RoleAdmin, 3},
		{domain.RoleEditor, 2},
		{domain.RoleViewer, 1},
		{"", 0},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run("role_"+tt.role, func(t *testing.T) {
			got := roleRank(tt.role)
			if got != tt.want {
				t.Errorf("roleRank(%q) = %d, want %d", tt.role, got, tt.want)
			}
		})
	}
}
