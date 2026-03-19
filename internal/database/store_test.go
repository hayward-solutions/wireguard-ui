package database

import (
	"context"
	"testing"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/crypto"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	enc, err := crypto.NewEncryptor("test-passphrase-for-unit-tests")
	if err != nil {
		t.Fatalf("create encryptor: %v", err)
	}
	store, err := NewSQLiteStore(":memory:", enc)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// createTestUser is a helper that inserts a user and returns it.
func createTestUser(t *testing.T, s *SQLiteStore, id, username, role string) *domain.User {
	t.Helper()
	u := &domain.User{
		ID:           id,
		Username:     username,
		PasswordHash: "hash-" + id,
		Name:         "Test " + username,
		Role:         role,
	}
	if err := s.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user %s: %v", id, err)
	}
	return u
}

// createTestGroup is a helper that inserts a group and returns it.
func createTestGroup(t *testing.T, s *SQLiteStore, id, name, source string) *domain.Group {
	t.Helper()
	g := &domain.Group{ID: id, Name: name, Source: source}
	if err := s.CreateGroup(context.Background(), g); err != nil {
		t.Fatalf("create group %s: %v", id, err)
	}
	return g
}

func TestServerConfig(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Initially nil
	cfg, err := s.GetServerConfig(ctx)
	if err != nil {
		t.Fatalf("get empty config: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config initially")
	}

	// Save and roundtrip
	now := time.Now().Truncate(time.Second)
	original := &domain.ServerConfig{
		ID:                "default",
		PrivateKey:        "server-private-key-secret",
		PublicKey:         "server-public-key",
		ListenPort:        51820,
		Address:           "10.0.0.1/24",
		DNS:               "1.1.1.1",
		MTU:               1420,
		PostUp:            "iptables -A FORWARD",
		PostDown:          "iptables -D FORWARD",
		Endpoint:          "vpn.example.com:51820",
		DefaultAllowedIPs: "0.0.0.0/0",
		DefaultDNS:        "8.8.8.8",
		TunnelSubnet:      "10.100.0.0/16",
		CreatedAt:         now,
		FirewallConfig: &domain.FirewallConfig{
			EnableNAT:        true,
			EnableForwarding: true,
			AllowPeerToPeer:  false,
			NATSource:        "10.0.0.0/24",
			NATOutInterface:  "eth0",
		},
	}
	if err := s.SaveServerConfig(ctx, original); err != nil {
		t.Fatalf("save config: %v", err)
	}

	got, err := s.GetServerConfig(ctx)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil config")
	}
	if got.PrivateKey != "server-private-key-secret" {
		t.Errorf("private key mismatch: got %q", got.PrivateKey)
	}
	if got.PublicKey != "server-public-key" {
		t.Errorf("public key mismatch: got %q", got.PublicKey)
	}
	if got.ListenPort != 51820 {
		t.Errorf("listen port mismatch: got %d", got.ListenPort)
	}
	if got.Address != "10.0.0.1/24" {
		t.Errorf("address mismatch: got %q", got.Address)
	}
	if got.FirewallConfig == nil {
		t.Fatal("expected firewall config")
	}
	if !got.FirewallConfig.EnableNAT {
		t.Error("expected EnableNAT true")
	}

	// Update and re-read
	original.ListenPort = 51821
	original.DNS = "8.8.4.4"
	if err := s.SaveServerConfig(ctx, original); err != nil {
		t.Fatalf("update config: %v", err)
	}
	got2, err := s.GetServerConfig(ctx)
	if err != nil {
		t.Fatalf("get updated config: %v", err)
	}
	if got2.ListenPort != 51821 {
		t.Errorf("updated listen port: got %d", got2.ListenPort)
	}
	if got2.DNS != "8.8.4.4" {
		t.Errorf("updated DNS: got %q", got2.DNS)
	}
}

func TestPeers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Create a user for the created_by field
	createTestUser(t, s, "user-1", "alice", domain.RoleAdmin)

	t.Run("CRUD", func(t *testing.T) {
		peer := &domain.Peer{
			ID:                  "peer-1",
			Name:                "my-laptop",
			PrivateKey:          "peer-priv-key",
			PublicKey:           "peer-pub-key",
			PresharedKey:        "peer-psk",
			AllowedIPs:          "10.0.0.2/32",
			Address:             "10.0.0.2",
			DNS:                 "1.1.1.1",
			PersistentKeepalive: 25,
			Enabled:             true,
			CreatedBy:           "user-1",
		}
		if err := s.CreatePeer(ctx, peer); err != nil {
			t.Fatalf("create peer: %v", err)
		}

		// List
		peers, err := s.ListPeers(ctx)
		if err != nil {
			t.Fatalf("list peers: %v", err)
		}
		if len(peers) != 1 {
			t.Fatalf("expected 1 peer, got %d", len(peers))
		}
		if peers[0].PrivateKey != "peer-priv-key" {
			t.Errorf("decrypted private key mismatch: %q", peers[0].PrivateKey)
		}
		if peers[0].PresharedKey != "peer-psk" {
			t.Errorf("decrypted psk mismatch: %q", peers[0].PresharedKey)
		}

		// GetPeer
		got, err := s.GetPeer(ctx, "peer-1")
		if err != nil {
			t.Fatalf("get peer: %v", err)
		}
		if got == nil {
			t.Fatal("expected peer")
		}
		if got.Name != "my-laptop" {
			t.Errorf("name mismatch: %q", got.Name)
		}

		// Update
		got.Name = "my-desktop"
		if err := s.UpdatePeer(ctx, got); err != nil {
			t.Fatalf("update peer: %v", err)
		}
		got2, _ := s.GetPeer(ctx, "peer-1")
		if got2.Name != "my-desktop" {
			t.Errorf("updated name: %q", got2.Name)
		}

		// Delete
		if err := s.DeletePeer(ctx, "peer-1"); err != nil {
			t.Fatalf("delete peer: %v", err)
		}
		peers, _ = s.ListPeers(ctx)
		if len(peers) != 0 {
			t.Errorf("expected 0 peers after delete, got %d", len(peers))
		}
	})

	t.Run("GetPeer_Nonexistent", func(t *testing.T) {
		got, err := s.GetPeer(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil for nonexistent peer")
		}
	})

	t.Run("ListPeersByUser", func(t *testing.T) {
		createTestUser(t, s, "user-2", "bob", domain.RoleViewer)

		for i, uid := range []string{"user-1", "user-1", "user-2"} {
			p := &domain.Peer{
				ID:        "lpu-peer-" + string(rune('a'+i)),
				Name:      "peer-" + string(rune('a'+i)),
				PublicKey: "pub-" + string(rune('a'+i)),
				Enabled:   true,
				CreatedBy: uid,
			}
			if err := s.CreatePeer(ctx, p); err != nil {
				t.Fatalf("create peer: %v", err)
			}
		}

		alicePeers, err := s.ListPeersByUser(ctx, "user-1")
		if err != nil {
			t.Fatalf("list by user: %v", err)
		}
		if len(alicePeers) != 2 {
			t.Errorf("expected 2 peers for alice, got %d", len(alicePeers))
		}

		bobPeers, err := s.ListPeersByUser(ctx, "user-2")
		if err != nil {
			t.Fatalf("list by user: %v", err)
		}
		if len(bobPeers) != 1 {
			t.Errorf("expected 1 peer for bob, got %d", len(bobPeers))
		}
	})
}

func TestUsers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		u := &domain.User{
			ID:           "u1",
			Username:     "admin",
			PasswordHash: "hashed-pw",
			Name:         "Admin User",
			Role:         domain.RoleAdmin,
		}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}

		// ListUsers
		users, err := s.ListUsers(ctx)
		if err != nil {
			t.Fatalf("list users: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("expected 1 user, got %d", len(users))
		}

		// GetUser
		got, err := s.GetUser(ctx, "u1")
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if got == nil || got.Username != "admin" {
			t.Fatalf("unexpected user: %+v", got)
		}

		// GetUserByUsername
		gotByName, err := s.GetUserByUsername(ctx, "admin")
		if err != nil {
			t.Fatalf("get by username: %v", err)
		}
		if gotByName == nil || gotByName.ID != "u1" {
			t.Fatalf("unexpected user by username: %+v", gotByName)
		}

		// UpdateUser
		got.Name = "Super Admin"
		got.Role = domain.RoleEditor
		if err := s.UpdateUser(ctx, got); err != nil {
			t.Fatalf("update user: %v", err)
		}
		got2, _ := s.GetUser(ctx, "u1")
		if got2.Name != "Super Admin" {
			t.Errorf("updated name: %q", got2.Name)
		}
		if got2.Role != domain.RoleEditor {
			t.Errorf("updated role: %q", got2.Role)
		}

		// UpdateUserPassword
		if err := s.UpdateUserPassword(ctx, "u1", "new-hash"); err != nil {
			t.Fatalf("update password: %v", err)
		}
		got3, _ := s.GetUser(ctx, "u1")
		if got3.PasswordHash != "new-hash" {
			t.Errorf("password not updated: %q", got3.PasswordHash)
		}

		// DeleteUser
		if err := s.DeleteUser(ctx, "u1"); err != nil {
			t.Fatalf("delete user: %v", err)
		}
		users, _ = s.ListUsers(ctx)
		if len(users) != 0 {
			t.Errorf("expected 0 users after delete, got %d", len(users))
		}
	})

	t.Run("GetUser_Nonexistent", func(t *testing.T) {
		got, err := s.GetUser(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})

	t.Run("GetUserByUsername_Nonexistent", func(t *testing.T) {
		got, err := s.GetUserByUsername(ctx, "nobody")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})
}

func TestAPITokens(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "u1", "alice", domain.RoleAdmin)

	t.Run("CRUD", func(t *testing.T) {
		expires := time.Now().Add(24 * time.Hour)
		token := &domain.APIToken{
			ID:          "tok-1",
			UserID:      "u1",
			Name:        "my-token",
			TokenHash:   "sha256-hash-1",
			TokenPrefix: "wg_abc",
			ExpiresAt:   &expires,
		}
		if err := s.CreateAPIToken(ctx, token); err != nil {
			t.Fatalf("create token: %v", err)
		}

		// ListAPITokensByUser
		tokens, err := s.ListAPITokensByUser(ctx, "u1")
		if err != nil {
			t.Fatalf("list tokens: %v", err)
		}
		if len(tokens) != 1 {
			t.Fatalf("expected 1 token, got %d", len(tokens))
		}
		if tokens[0].Name != "my-token" {
			t.Errorf("name mismatch: %q", tokens[0].Name)
		}

		// GetAPITokenByHash
		got, err := s.GetAPITokenByHash(ctx, "sha256-hash-1")
		if err != nil {
			t.Fatalf("get by hash: %v", err)
		}
		if got == nil || got.ID != "tok-1" {
			t.Fatalf("unexpected token: %+v", got)
		}

		// UpdateAPITokenLastUsed
		if err := s.UpdateAPITokenLastUsed(ctx, "tok-1"); err != nil {
			t.Fatalf("update last used: %v", err)
		}
		got2, _ := s.GetAPITokenByHash(ctx, "sha256-hash-1")
		if got2.LastUsed == nil {
			t.Error("expected last_used to be set")
		}

		// DeleteAPIToken
		if err := s.DeleteAPIToken(ctx, "tok-1"); err != nil {
			t.Fatalf("delete token: %v", err)
		}
		tokens, _ = s.ListAPITokensByUser(ctx, "u1")
		if len(tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(tokens))
		}
	})

	t.Run("DeleteExpiredAPITokens", func(t *testing.T) {
		expired := time.Now().Add(-1 * time.Hour)
		valid := time.Now().Add(24 * time.Hour)

		expiredToken := &domain.APIToken{
			ID:          "tok-exp",
			UserID:      "u1",
			Name:        "expired",
			TokenHash:   "hash-exp",
			TokenPrefix: "wg_exp",
			ExpiresAt:   &expired,
		}
		validToken := &domain.APIToken{
			ID:          "tok-val",
			UserID:      "u1",
			Name:        "valid",
			TokenHash:   "hash-val",
			TokenPrefix: "wg_val",
			ExpiresAt:   &valid,
		}
		if err := s.CreateAPIToken(ctx, expiredToken); err != nil {
			t.Fatalf("create expired: %v", err)
		}
		if err := s.CreateAPIToken(ctx, validToken); err != nil {
			t.Fatalf("create valid: %v", err)
		}

		if err := s.DeleteExpiredAPITokens(ctx); err != nil {
			t.Fatalf("delete expired: %v", err)
		}

		tokens, _ := s.ListAPITokensByUser(ctx, "u1")
		if len(tokens) != 1 {
			t.Fatalf("expected 1 token remaining, got %d", len(tokens))
		}
		if tokens[0].ID != "tok-val" {
			t.Errorf("wrong token remaining: %s", tokens[0].ID)
		}
	})
}

func TestGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		g := &domain.Group{ID: "g1", Name: "admins", Source: domain.GroupSourceLocal}
		if err := s.CreateGroup(ctx, g); err != nil {
			t.Fatalf("create group: %v", err)
		}

		// ListGroups
		groups, err := s.ListGroups(ctx)
		if err != nil {
			t.Fatalf("list groups: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 group, got %d", len(groups))
		}

		// GetGroup
		got, err := s.GetGroup(ctx, "g1")
		if err != nil {
			t.Fatalf("get group: %v", err)
		}
		if got == nil || got.Name != "admins" {
			t.Fatalf("unexpected group: %+v", got)
		}

		// GetGroupByName
		gotByName, err := s.GetGroupByName(ctx, "admins")
		if err != nil {
			t.Fatalf("get by name: %v", err)
		}
		if gotByName == nil || gotByName.ID != "g1" {
			t.Fatalf("unexpected group by name: %+v", gotByName)
		}

		// UpdateGroup
		got.Name = "superadmins"
		if err := s.UpdateGroup(ctx, got); err != nil {
			t.Fatalf("update group: %v", err)
		}
		got2, _ := s.GetGroup(ctx, "g1")
		if got2.Name != "superadmins" {
			t.Errorf("updated name: %q", got2.Name)
		}

		// DeleteGroup
		if err := s.DeleteGroup(ctx, "g1"); err != nil {
			t.Fatalf("delete group: %v", err)
		}
		groups, _ = s.ListGroups(ctx)
		if len(groups) != 0 {
			t.Errorf("expected 0 groups, got %d", len(groups))
		}
	})

	t.Run("GetGroup_Nonexistent", func(t *testing.T) {
		got, err := s.GetGroup(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})
}

func TestUserGroupMemberships(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1 := createTestUser(t, s, "u1", "alice", domain.RoleAdmin)
	createTestUser(t, s, "u2", "bob", domain.RoleViewer)
	g1 := createTestGroup(t, s, "g1", "engineers", domain.GroupSourceLocal)
	g2 := createTestGroup(t, s, "g2", "devops", domain.GroupSourceLocal)

	t.Run("SetUserGroups_and_GetUserGroups", func(t *testing.T) {
		if err := s.SetUserGroups(ctx, u1.ID, []string{g1.ID, g2.ID}); err != nil {
			t.Fatalf("set user groups: %v", err)
		}

		groups, err := s.GetUserGroups(ctx, u1.ID)
		if err != nil {
			t.Fatalf("get user groups: %v", err)
		}
		if len(groups) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(groups))
		}

		// Replace with only one group
		if err := s.SetUserGroups(ctx, u1.ID, []string{g1.ID}); err != nil {
			t.Fatalf("re-set user groups: %v", err)
		}
		groups, _ = s.GetUserGroups(ctx, u1.ID)
		if len(groups) != 1 {
			t.Errorf("expected 1 group after update, got %d", len(groups))
		}
	})

	t.Run("GetGroupMembers", func(t *testing.T) {
		if err := s.SetUserGroups(ctx, "u1", []string{"g1"}); err != nil {
			t.Fatalf("set: %v", err)
		}
		if err := s.SetUserGroups(ctx, "u2", []string{"g1"}); err != nil {
			t.Fatalf("set: %v", err)
		}

		members, err := s.GetGroupMembers(ctx, "g1")
		if err != nil {
			t.Fatalf("get members: %v", err)
		}
		if len(members) != 2 {
			t.Errorf("expected 2 members, got %d", len(members))
		}
	})

	t.Run("SyncOIDCGroups", func(t *testing.T) {
		g3 := createTestGroup(t, s, "g3", "oidc-eng", domain.GroupSourceOIDC)

		// Set a local group first
		if err := s.SetUserGroups(ctx, "u1", []string{"g1"}); err != nil {
			t.Fatalf("set local: %v", err)
		}

		// Sync OIDC groups
		if err := s.SyncOIDCGroups(ctx, "u1", []string{g3.ID}); err != nil {
			t.Fatalf("sync oidc: %v", err)
		}

		groups, err := s.GetUserGroups(ctx, "u1")
		if err != nil {
			t.Fatalf("get groups: %v", err)
		}
		// Should have local g1 + oidc g3
		if len(groups) != 2 {
			t.Errorf("expected 2 groups (local+oidc), got %d", len(groups))
		}

		// Sync again with empty OIDC - should remove only OIDC memberships
		if err := s.SyncOIDCGroups(ctx, "u1", nil); err != nil {
			t.Fatalf("sync empty oidc: %v", err)
		}
		groups, _ = s.GetUserGroups(ctx, "u1")
		if len(groups) != 1 {
			t.Errorf("expected 1 group after oidc clear, got %d", len(groups))
		}
		if groups[0].ID != "g1" {
			t.Errorf("remaining group should be local g1, got %s", groups[0].ID)
		}
	})
}

func TestACLRules(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		createTestUser(t, s, "acl-crud-u1", "aclcruduser", domain.RoleViewer)
		userID := "acl-crud-u1"
		rule := &domain.ACLRule{
			ID:          "acl-1",
			Name:        "allow-web",
			Description: "Allow web traffic",
			Priority:    10,
			Action:      domain.ACLActionAllow,
			Protocol:    domain.ACLProtocolTCP,
			DstCIDR:     "10.0.0.0/24",
			DstPorts:    "80,443",
			UserID:      &userID,
			Enabled:     true,
		}
		if err := s.CreateACLRule(ctx, rule); err != nil {
			t.Fatalf("create acl rule: %v", err)
		}

		// List
		rules, err := s.ListACLRules(ctx)
		if err != nil {
			t.Fatalf("list rules: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(rules))
		}

		// Get
		got, err := s.GetACLRule(ctx, "acl-1")
		if err != nil {
			t.Fatalf("get rule: %v", err)
		}
		if got == nil || got.Name != "allow-web" {
			t.Fatalf("unexpected rule: %+v", got)
		}
		if got.DstPorts != "80,443" {
			t.Errorf("dst ports: %q", got.DstPorts)
		}

		// Update
		got.Priority = 5
		got.DstPorts = "80,443,8080"
		if err := s.UpdateACLRule(ctx, got); err != nil {
			t.Fatalf("update rule: %v", err)
		}
		got2, _ := s.GetACLRule(ctx, "acl-1")
		if got2.Priority != 5 {
			t.Errorf("updated priority: %d", got2.Priority)
		}
		if got2.DstPorts != "80,443,8080" {
			t.Errorf("updated ports: %q", got2.DstPorts)
		}

		// Delete
		if err := s.DeleteACLRule(ctx, "acl-1"); err != nil {
			t.Fatalf("delete rule: %v", err)
		}
		rules, _ = s.ListACLRules(ctx)
		if len(rules) != 0 {
			t.Errorf("expected 0 rules, got %d", len(rules))
		}
	})

	t.Run("GetACLRule_Nonexistent", func(t *testing.T) {
		got, err := s.GetACLRule(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})

	t.Run("GetEffectiveACLRules", func(t *testing.T) {
		createTestUser(t, s, "acl-u1", "acluser", domain.RoleViewer)
		g := createTestGroup(t, s, "acl-g1", "aclgroup", domain.GroupSourceLocal)
		if err := s.SetUserGroups(ctx, "acl-u1", []string{g.ID}); err != nil {
			t.Fatalf("set groups: %v", err)
		}

		userID := "acl-u1"
		groupID := g.ID

		// Rule targeting user directly
		r1 := &domain.ACLRule{
			ID: "eff-1", Name: "user-rule", Priority: 1,
			Action: domain.ACLActionAllow, Protocol: domain.ACLProtocolAny,
			DstCIDR: "0.0.0.0/0", UserID: &userID, Enabled: true,
		}
		// Rule targeting group
		r2 := &domain.ACLRule{
			ID: "eff-2", Name: "group-rule", Priority: 2,
			Action: domain.ACLActionAllow, Protocol: domain.ACLProtocolTCP,
			DstCIDR: "10.0.0.0/8", GroupID: &groupID, Enabled: true,
		}
		// Global rule (no user/group)
		r3 := &domain.ACLRule{
			ID: "eff-3", Name: "global-rule", Priority: 3,
			Action: domain.ACLActionAllow, Protocol: domain.ACLProtocolAny,
			DstCIDR: "192.168.0.0/16", Enabled: true,
		}
		// Disabled rule - should not appear
		r4 := &domain.ACLRule{
			ID: "eff-4", Name: "disabled-rule", Priority: 0,
			Action: domain.ACLActionAllow, Protocol: domain.ACLProtocolAny,
			DstCIDR: "0.0.0.0/0", UserID: &userID, Enabled: false,
		}

		for _, r := range []*domain.ACLRule{r1, r2, r3, r4} {
			if err := s.CreateACLRule(ctx, r); err != nil {
				t.Fatalf("create rule %s: %v", r.ID, err)
			}
		}

		effective, err := s.GetEffectiveACLRules(ctx, "acl-u1")
		if err != nil {
			t.Fatalf("get effective: %v", err)
		}
		if len(effective) != 3 {
			t.Errorf("expected 3 effective rules, got %d", len(effective))
			for _, r := range effective {
				t.Logf("  rule: %s (%s)", r.ID, r.Name)
			}
		}
	})
}

func TestLoginSecurity(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "sec-u1", "secuser", domain.RoleAdmin)

	t.Run("RecordFailedLogin", func(t *testing.T) {
		attempts, err := s.RecordFailedLogin(ctx, "sec-u1")
		if err != nil {
			t.Fatalf("record failed login: %v", err)
		}
		if attempts != 1 {
			t.Errorf("expected 1 attempt, got %d", attempts)
		}

		attempts, err = s.RecordFailedLogin(ctx, "sec-u1")
		if err != nil {
			t.Fatalf("record 2nd: %v", err)
		}
		if attempts != 2 {
			t.Errorf("expected 2 attempts, got %d", attempts)
		}
	})

	t.Run("ResetFailedLogins", func(t *testing.T) {
		if err := s.ResetFailedLogins(ctx, "sec-u1"); err != nil {
			t.Fatalf("reset: %v", err)
		}
		u, _ := s.GetUser(ctx, "sec-u1")
		if u.FailedLoginAttempts != 0 {
			t.Errorf("expected 0 attempts after reset, got %d", u.FailedLoginAttempts)
		}
	})

	t.Run("LockUser", func(t *testing.T) {
		lockUntil := time.Now().Add(1 * time.Hour)
		if err := s.LockUser(ctx, "sec-u1", lockUntil); err != nil {
			t.Fatalf("lock: %v", err)
		}
		u, _ := s.GetUser(ctx, "sec-u1")
		if u.LockedUntil == nil {
			t.Fatal("expected locked_until to be set")
		}

		// Reset clears the lock
		if err := s.ResetFailedLogins(ctx, "sec-u1"); err != nil {
			t.Fatalf("reset: %v", err)
		}
		u, _ = s.GetUser(ctx, "sec-u1")
		if u.LockedUntil != nil {
			t.Error("expected locked_until to be nil after reset")
		}
	})

	t.Run("UpdateLastLogin", func(t *testing.T) {
		if err := s.UpdateLastLogin(ctx, "sec-u1"); err != nil {
			t.Fatalf("update last login: %v", err)
		}
		u, _ := s.GetUser(ctx, "sec-u1")
		if u.LastLogin == nil {
			t.Error("expected last_login to be set")
		}
	})
}

func TestSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "su1", "sessuser", domain.RoleAdmin)

	t.Run("CreateAndGet", func(t *testing.T) {
		sess := &domain.Session{
			ID:        "sess-1",
			UserID:    "su1",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		if err := s.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session: %v", err)
		}

		got, err := s.GetSession(ctx, "sess-1")
		if err != nil {
			t.Fatalf("get session: %v", err)
		}
		if got == nil || got.UserID != "su1" {
			t.Fatalf("unexpected session: %+v", got)
		}
		if got.Revoked {
			t.Error("expected not revoked")
		}
	})

	t.Run("RevokeSession", func(t *testing.T) {
		if err := s.RevokeSession(ctx, "sess-1"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		got, _ := s.GetSession(ctx, "sess-1")
		if !got.Revoked {
			t.Error("expected revoked")
		}
	})

	t.Run("RevokeUserSessions", func(t *testing.T) {
		sess2 := &domain.Session{
			ID:        "sess-2",
			UserID:    "su1",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		if err := s.CreateSession(ctx, sess2); err != nil {
			t.Fatalf("create: %v", err)
		}

		if err := s.RevokeUserSessions(ctx, "su1"); err != nil {
			t.Fatalf("revoke all: %v", err)
		}
		got, _ := s.GetSession(ctx, "sess-2")
		if !got.Revoked {
			t.Error("expected sess-2 revoked")
		}
	})

	t.Run("CleanExpiredSessions", func(t *testing.T) {
		// Create an expired session
		expired := &domain.Session{
			ID:        "sess-exp",
			UserID:    "su1",
			CreatedAt: time.Now().Add(-48 * time.Hour),
			ExpiresAt: time.Now().Add(-24 * time.Hour),
		}
		if err := s.CreateSession(ctx, expired); err != nil {
			t.Fatalf("create expired: %v", err)
		}

		// Create a valid (non-revoked) session
		valid := &domain.Session{
			ID:        "sess-valid",
			UserID:    "su1",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		if err := s.CreateSession(ctx, valid); err != nil {
			t.Fatalf("create valid: %v", err)
		}

		if err := s.CleanExpiredSessions(ctx); err != nil {
			t.Fatalf("clean: %v", err)
		}

		// Expired and revoked sessions should be gone
		got, _ := s.GetSession(ctx, "sess-exp")
		if got != nil {
			t.Error("expired session should be cleaned")
		}

		// Previously revoked sessions should also be cleaned
		got, _ = s.GetSession(ctx, "sess-1")
		if got != nil {
			t.Error("revoked session should be cleaned")
		}

		// Valid session should remain
		got, _ = s.GetSession(ctx, "sess-valid")
		if got == nil {
			t.Error("valid session should remain")
		}
	})
}

func TestTunnels(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		tunnel := &domain.Tunnel{
			ID:                  "tun-1",
			Name:                "office-vpn",
			Description:         "Office VPN tunnel",
			PrivateKey:          "tunnel-priv-key",
			PublicKey:           "tunnel-pub-key",
			Address:             "10.100.0.1/30",
			ListenPort:          0,
			DNS:                 "10.0.0.1",
			MTU:                 1420,
			PeerPublicKey:       "remote-pub-key",
			PeerEndpoint:        "vpn.office.com:51820",
			PresharedKey:        "tunnel-psk",
			PeerAllowedIPs:      "10.1.0.0/24",
			PersistentKeepalive: 25,
			Enabled:             true,
		}
		if err := s.CreateTunnel(ctx, tunnel); err != nil {
			t.Fatalf("create tunnel: %v", err)
		}

		// ListTunnels
		tunnels, err := s.ListTunnels(ctx)
		if err != nil {
			t.Fatalf("list tunnels: %v", err)
		}
		if len(tunnels) != 1 {
			t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
		}
		if tunnels[0].PrivateKey != "tunnel-priv-key" {
			t.Errorf("decrypted private key mismatch: %q", tunnels[0].PrivateKey)
		}
		if tunnels[0].PresharedKey != "tunnel-psk" {
			t.Errorf("decrypted psk mismatch: %q", tunnels[0].PresharedKey)
		}

		// GetTunnel
		got, err := s.GetTunnel(ctx, "tun-1")
		if err != nil {
			t.Fatalf("get tunnel: %v", err)
		}
		if got == nil || got.Name != "office-vpn" {
			t.Fatalf("unexpected tunnel: %+v", got)
		}

		// GetTunnelByName
		gotByName, err := s.GetTunnelByName(ctx, "office-vpn")
		if err != nil {
			t.Fatalf("get by name: %v", err)
		}
		if gotByName == nil || gotByName.ID != "tun-1" {
			t.Fatalf("unexpected tunnel by name: %+v", gotByName)
		}

		// UpdateTunnel
		got.Description = "Updated description"
		got.PeerEndpoint = "vpn2.office.com:51820"
		if err := s.UpdateTunnel(ctx, got); err != nil {
			t.Fatalf("update tunnel: %v", err)
		}
		got2, _ := s.GetTunnel(ctx, "tun-1")
		if got2.Description != "Updated description" {
			t.Errorf("description not updated: %q", got2.Description)
		}
		if got2.PeerEndpoint != "vpn2.office.com:51820" {
			t.Errorf("endpoint not updated: %q", got2.PeerEndpoint)
		}

		// DeleteTunnel
		if err := s.DeleteTunnel(ctx, "tun-1"); err != nil {
			t.Fatalf("delete tunnel: %v", err)
		}
		tunnels, _ = s.ListTunnels(ctx)
		if len(tunnels) != 0 {
			t.Errorf("expected 0 tunnels, got %d", len(tunnels))
		}
	})

	t.Run("GetTunnel_Nonexistent", func(t *testing.T) {
		got, err := s.GetTunnel(ctx, "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Error("expected nil")
		}
	})

	t.Run("ListEnabledTunnels", func(t *testing.T) {
		enabled := &domain.Tunnel{
			ID: "tun-en", Name: "enabled-tun", PublicKey: "pk1",
			PeerPublicKey: "rpk1", PeerEndpoint: "e1:51820",
			Enabled: true,
		}
		disabled := &domain.Tunnel{
			ID: "tun-dis", Name: "disabled-tun", PublicKey: "pk2",
			PeerPublicKey: "rpk2", PeerEndpoint: "e2:51820",
			Enabled: false,
		}
		if err := s.CreateTunnel(ctx, enabled); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := s.CreateTunnel(ctx, disabled); err != nil {
			t.Fatalf("create: %v", err)
		}

		tunnels, err := s.ListEnabledTunnels(ctx)
		if err != nil {
			t.Fatalf("list enabled: %v", err)
		}
		if len(tunnels) != 1 {
			t.Fatalf("expected 1 enabled tunnel, got %d", len(tunnels))
		}
		if tunnels[0].ID != "tun-en" {
			t.Errorf("wrong tunnel: %s", tunnels[0].ID)
		}
	})
}

func TestWebAuthnCredentials(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "wa-u1", "wauser", domain.RoleAdmin)

	cred := &domain.WebAuthnCredential{
		ID:              "wac-1",
		UserID:          "wa-u1",
		CredentialID:    "cred-id-abc123",
		PublicKey:       "webauthn-public-key",
		AttestationType: "none",
		AAGUID:          "00000000-0000-0000-0000-000000000000",
		SignCount:       0,
		Transports:      []string{"usb", "nfc"},
		Name:            "YubiKey 5",
		CreatedAt:       time.Now(),
	}

	t.Run("Create_and_List", func(t *testing.T) {
		if err := s.CreateWebAuthnCredential(ctx, cred); err != nil {
			t.Fatalf("create: %v", err)
		}

		creds, err := s.ListWebAuthnCredentials(ctx, "wa-u1")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(creds) != 1 {
			t.Fatalf("expected 1 credential, got %d", len(creds))
		}
		if creds[0].Name != "YubiKey 5" {
			t.Errorf("name mismatch: %q", creds[0].Name)
		}
		if len(creds[0].Transports) != 2 {
			t.Errorf("transports mismatch: %v", creds[0].Transports)
		}
	})

	t.Run("GetByCredentialID", func(t *testing.T) {
		got, err := s.GetWebAuthnCredentialByCredentialID(ctx, "cred-id-abc123")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil || got.ID != "wac-1" {
			t.Fatalf("unexpected: %+v", got)
		}
	})

	t.Run("UpdateSignCount", func(t *testing.T) {
		if err := s.UpdateWebAuthnSignCount(ctx, "cred-id-abc123", 42); err != nil {
			t.Fatalf("update sign count: %v", err)
		}
		got, _ := s.GetWebAuthnCredentialByCredentialID(ctx, "cred-id-abc123")
		if got.SignCount != 42 {
			t.Errorf("sign count: %d", got.SignCount)
		}
		if got.LastUsedAt == nil {
			t.Error("expected last_used_at to be set")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := s.DeleteWebAuthnCredential(ctx, "wac-1"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		creds, _ := s.ListWebAuthnCredentials(ctx, "wa-u1")
		if len(creds) != 0 {
			t.Errorf("expected 0 after delete, got %d", len(creds))
		}
	})
}

func TestTOTP(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "totp-u1", "totpuser", domain.RoleAdmin)

	t.Run("Create_and_Get", func(t *testing.T) {
		totp := &domain.UserTOTP{
			UserID:    "totp-u1",
			Secret:    "JBSWY3DPEHPK3PXP",
			Verified:  false,
			CreatedAt: time.Now(),
		}
		if err := s.CreateUserTOTP(ctx, totp); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := s.GetUserTOTP(ctx, "totp-u1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil {
			t.Fatal("expected totp")
		}
		if got.Secret != "JBSWY3DPEHPK3PXP" {
			t.Errorf("secret mismatch: %q", got.Secret)
		}
		if got.Verified {
			t.Error("expected not verified")
		}
	})

	t.Run("Verify", func(t *testing.T) {
		if err := s.VerifyUserTOTP(ctx, "totp-u1"); err != nil {
			t.Fatalf("verify: %v", err)
		}
		got, _ := s.GetUserTOTP(ctx, "totp-u1")
		if !got.Verified {
			t.Error("expected verified")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := s.DeleteUserTOTP(ctx, "totp-u1"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		got, err := s.GetUserTOTP(ctx, "totp-u1")
		if err != nil {
			t.Fatalf("get after delete: %v", err)
		}
		if got != nil {
			t.Error("expected nil after delete")
		}
	})
}

func TestMFASettings(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "mfa-u1", "mfauser", domain.RoleAdmin)

	// Initially MFA disabled
	u, _ := s.GetUser(ctx, "mfa-u1")
	if u.MFAEnabled {
		t.Error("expected MFA disabled initially")
	}

	// Enable
	if err := s.SetMFAEnabled(ctx, "mfa-u1", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	u, _ = s.GetUser(ctx, "mfa-u1")
	if !u.MFAEnabled {
		t.Error("expected MFA enabled")
	}

	// Disable
	if err := s.SetMFAEnabled(ctx, "mfa-u1", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	u, _ = s.GetUser(ctx, "mfa-u1")
	if u.MFAEnabled {
		t.Error("expected MFA disabled")
	}
}

func TestMFAChallenges(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	createTestUser(t, s, "ch-u1", "chuser", domain.RoleAdmin)

	t.Run("Create_Get_Use", func(t *testing.T) {
		ch := &domain.MFAChallenge{
			ID:        "ch-1",
			UserID:    "ch-u1",
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		if err := s.CreateMFAChallenge(ctx, ch); err != nil {
			t.Fatalf("create: %v", err)
		}

		got, err := s.GetMFAChallenge(ctx, "ch-1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got == nil || got.UserID != "ch-u1" {
			t.Fatalf("unexpected: %+v", got)
		}
		if got.Used {
			t.Error("expected not used")
		}

		if err := s.UseMFAChallenge(ctx, "ch-1"); err != nil {
			t.Fatalf("use: %v", err)
		}
		got2, _ := s.GetMFAChallenge(ctx, "ch-1")
		if !got2.Used {
			t.Error("expected used")
		}
	})

	t.Run("CleanExpiredMFAChallenges", func(t *testing.T) {
		// Create an already-expired challenge with a time far in the past
		// to avoid any timestamp format edge cases between Go and SQLite
		expired := &domain.MFAChallenge{
			ID:        "ch-exp",
			UserID:    "ch-u1",
			CreatedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2020, 1, 1, 0, 5, 0, 0, time.UTC),
		}
		if err := s.CreateMFAChallenge(ctx, expired); err != nil {
			t.Fatalf("create expired: %v", err)
		}

		// Create a valid, unused challenge far in the future
		valid := &domain.MFAChallenge{
			ID:        "ch-val",
			UserID:    "ch-u1",
			CreatedAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2099, 1, 1, 0, 5, 0, 0, time.UTC),
		}
		if err := s.CreateMFAChallenge(ctx, valid); err != nil {
			t.Fatalf("create valid: %v", err)
		}

		if err := s.CleanExpiredMFAChallenges(ctx); err != nil {
			t.Fatalf("clean: %v", err)
		}

		// Expired challenge should be gone
		got, _ := s.GetMFAChallenge(ctx, "ch-exp")
		if got != nil {
			t.Error("expired challenge should be cleaned")
		}

		// Used challenge (ch-1 from previous subtest) should also be cleaned
		got, _ = s.GetMFAChallenge(ctx, "ch-1")
		if got != nil {
			t.Error("used challenge should be cleaned")
		}

		// Valid unused challenge should remain
		got, _ = s.GetMFAChallenge(ctx, "ch-val")
		if got == nil {
			t.Error("valid challenge should remain")
		}
	})
}

func TestHasEncryptedData(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	has, err := s.HasEncryptedData(ctx)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if has {
		t.Error("expected no encrypted data initially")
	}

	// After saving a server config with encryption enabled, the data should be encrypted
	cfg := &domain.ServerConfig{
		ID:         "default",
		PrivateKey: "some-key",
		PublicKey:  "pub-key",
		ListenPort: 51820,
		Address:    "10.0.0.1/24",
		CreatedAt:  time.Now(),
	}
	if err := s.SaveServerConfig(ctx, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	has, err = s.HasEncryptedData(ctx)
	if err != nil {
		t.Fatalf("check after save: %v", err)
	}
	if !has {
		t.Error("expected encrypted data after saving config with encryptor")
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Migrate was already called in newTestStore; calling again should be a no-op
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	// And a third time for good measure
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("third migrate: %v", err)
	}
}

func TestClose(t *testing.T) {
	enc, err := crypto.NewEncryptor("test-key")
	if err != nil {
		t.Fatalf("encryptor: %v", err)
	}
	store, err := NewSQLiteStore(":memory:", enc)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// After close, operations should fail
	_, err = store.ListUsers(context.Background())
	if err == nil {
		t.Error("expected error after close")
	}
}
