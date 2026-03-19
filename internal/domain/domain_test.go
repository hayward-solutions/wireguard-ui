package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustMarshal(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestPeerJSON(t *testing.T) {
	t.Helper()

	p := Peer{
		ID:         "peer-1",
		Name:       "my-peer",
		PrivateKey: "SECRET_PRIVATE_KEY",
		PublicKey:  "PUBLIC_KEY_VALUE",
		PresharedKey: "SECRET_PSK",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: "10.0.0.0/24",
	}

	out := mustMarshal(t, p)

	tests := []struct {
		field string
		value string
		want  bool // true = should be present
	}{
		{field: "PrivateKey", value: "SECRET_PRIVATE_KEY", want: false},
		{field: "PresharedKey", value: "SECRET_PSK", want: false},
		{field: "Endpoint", value: "1.2.3.4:51820", want: false},
		{field: "public_key", value: "PUBLIC_KEY_VALUE", want: true},
		{field: "name", value: "my-peer", want: true},
		{field: "id", value: "peer-1", want: true},
	}

	for _, tt := range tests {
		present := strings.Contains(out, tt.value)
		if present != tt.want {
			t.Errorf("Peer JSON %s (%q): got present=%v, want present=%v", tt.field, tt.value, present, tt.want)
		}
	}
}

func TestUserJSON(t *testing.T) {
	t.Helper()

	now := time.Now()
	u := User{
		ID:                  "user-1",
		Username:            "admin",
		PasswordHash:        "SECRET_HASH",
		Role:                "admin",
		FailedLoginAttempts: 5,
		LockedUntil:         &now,
	}

	out := mustMarshal(t, u)

	tests := []struct {
		field string
		value string
		want  bool
	}{
		{field: "PasswordHash", value: "SECRET_HASH", want: false},
		{field: "FailedLoginAttempts", value: "failed_login", want: false},
		{field: "LockedUntil", value: "locked_until", want: false},
		{field: "username", value: "admin", want: true},
		{field: "role", value: `"role"`, want: true},
	}

	for _, tt := range tests {
		present := strings.Contains(out, tt.value)
		if present != tt.want {
			t.Errorf("User JSON %s (%q): got present=%v, want present=%v", tt.field, tt.value, present, tt.want)
		}
	}
}

func TestServerConfigJSON(t *testing.T) {
	t.Helper()

	sc := ServerConfig{
		ID:                 "sc-1",
		PrivateKey:         "SECRET_SERVER_KEY",
		PublicKey:          "SERVER_PUBLIC_KEY",
		AllowCustomScripts: true,
	}

	out := mustMarshal(t, sc)

	tests := []struct {
		field string
		value string
		want  bool
	}{
		{field: "PrivateKey", value: "SECRET_SERVER_KEY", want: false},
		{field: "AllowCustomScripts", value: "allow_custom_scripts", want: false},
		{field: "public_key", value: "SERVER_PUBLIC_KEY", want: true},
	}

	for _, tt := range tests {
		present := strings.Contains(out, tt.value)
		if present != tt.want {
			t.Errorf("ServerConfig JSON %s (%q): got present=%v, want present=%v", tt.field, tt.value, present, tt.want)
		}
	}
}

func TestTunnelJSON(t *testing.T) {
	t.Helper()

	tun := Tunnel{
		ID:           "tun-1",
		Name:         "my-tunnel",
		PrivateKey:   "SECRET_TUN_KEY",
		PublicKey:    "TUN_PUBLIC_KEY",
		PresharedKey: "SECRET_TUN_PSK",
	}

	out := mustMarshal(t, tun)

	tests := []struct {
		field string
		value string
		want  bool
	}{
		{field: "PrivateKey", value: "SECRET_TUN_KEY", want: false},
		{field: "PresharedKey", value: "SECRET_TUN_PSK", want: false},
		{field: "public_key", value: "TUN_PUBLIC_KEY", want: true},
	}

	for _, tt := range tests {
		present := strings.Contains(out, tt.value)
		if present != tt.want {
			t.Errorf("Tunnel JSON %s (%q): got present=%v, want present=%v", tt.field, tt.value, present, tt.want)
		}
	}
}

func TestAPITokenJSON(t *testing.T) {
	t.Helper()

	tok := APIToken{
		ID:          "tok-1",
		Name:        "my-token",
		TokenHash:   "SECRET_TOKEN_HASH",
		TokenPrefix: "wg_abc",
	}

	out := mustMarshal(t, tok)

	if strings.Contains(out, "SECRET_TOKEN_HASH") {
		t.Errorf("APIToken JSON: got TokenHash present, want absent")
	}
	if !strings.Contains(out, "my-token") {
		t.Errorf("APIToken JSON: got Name absent, want present")
	}
}

func TestWebAuthnCredentialJSON(t *testing.T) {
	t.Helper()

	cred := WebAuthnCredential{
		ID:        "cred-1",
		PublicKey: "SECRET_WEBAUTHN_KEY",
		Name:      "my-key",
	}

	out := mustMarshal(t, cred)

	if strings.Contains(out, "SECRET_WEBAUTHN_KEY") {
		t.Errorf("WebAuthnCredential JSON: got PublicKey present, want absent")
	}
	if !strings.Contains(out, "my-key") {
		t.Errorf("WebAuthnCredential JSON: got Name absent, want present")
	}
}

func TestUserTOTPJSON(t *testing.T) {
	t.Helper()

	totp := UserTOTP{
		UserID: "user-1",
		Secret: "SECRET_TOTP_VALUE",
	}

	out := mustMarshal(t, totp)

	if strings.Contains(out, "SECRET_TOTP_VALUE") {
		t.Errorf("UserTOTP JSON: got Secret present, want absent")
	}
	if !strings.Contains(out, "user-1") {
		t.Errorf("UserTOTP JSON: got UserID absent, want present")
	}
}

func TestRoleConstants(t *testing.T) {
	t.Helper()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "RoleAdmin", got: RoleAdmin, want: "admin"},
		{name: "RoleEditor", got: RoleEditor, want: "editor"},
		{name: "RoleViewer", got: RoleViewer, want: "viewer"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

func TestGroupSourceConstants(t *testing.T) {
	t.Helper()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "GroupSourceLocal", got: GroupSourceLocal, want: "local"},
		{name: "GroupSourceOIDC", got: GroupSourceOIDC, want: "oidc"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}

func TestACLConstants(t *testing.T) {
	t.Helper()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "ACLActionAllow", got: ACLActionAllow, want: "allow"},
		{name: "ACLProtocolAny", got: ACLProtocolAny, want: "any"},
		{name: "ACLProtocolTCP", got: ACLProtocolTCP, want: "tcp"},
		{name: "ACLProtocolUDP", got: ACLProtocolUDP, want: "udp"},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}
