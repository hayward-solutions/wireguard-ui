package wireguard

import (
	"strings"
	"testing"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

func newTestPeer(t *testing.T) *domain.Peer {
	t.Helper()
	return &domain.Peer{
		ID:                  "peer-1",
		Name:                "test-peer",
		PrivateKey:          "cPrivKey1234567890abcdefghijklmnopqrstuv0=",
		PublicKey:           "cPubKey01234567890abcdefghijklmnopqrstuv0=",
		PresharedKey:        "cPSK0000001234567890abcdefghijklmnopqrst0=",
		AllowedIPs:          "0.0.0.0/0",
		Address:             "10.0.0.2/32",
		DNS:                 "",
		PersistentKeepalive: 25,
		Enabled:             true,
	}
}

func newTestServer(t *testing.T) *domain.ServerConfig {
	t.Helper()
	return &domain.ServerConfig{
		ID:         "server-1",
		PrivateKey: "sPrivKey1234567890abcdefghijklmnopqrstuv0=",
		PublicKey:  "sPubKey01234567890abcdefghijklmnopqrstuv0=",
		ListenPort: 51820,
		Address:    "10.0.0.1/24",
		DNS:        "1.1.1.1",
		MTU:        1420,
		Endpoint:   "vpn.example.com",
	}
}

func TestRenderPeerConfig(t *testing.T) {
	peer := newTestPeer(t)
	server := newTestServer(t)

	got, err := RenderPeerConfig(peer, server)
	if err != nil {
		t.Fatalf("RenderPeerConfig() error = %v", err)
	}

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + peer.PrivateKey,
		"Address = " + peer.Address,
		"DNS = " + server.DNS,
		"[Peer]",
		"PublicKey = " + server.PublicKey,
		"PresharedKey = " + peer.PresharedKey,
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = " + peer.AllowedIPs,
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderPeerConfig() output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestRenderPeerConfig_NoPresharedKey(t *testing.T) {
	peer := newTestPeer(t)
	peer.PresharedKey = ""
	server := newTestServer(t)

	got, err := RenderPeerConfig(peer, server)
	if err != nil {
		t.Fatalf("RenderPeerConfig() error = %v", err)
	}

	if strings.Contains(got, "PresharedKey") {
		t.Errorf("RenderPeerConfig() output should not contain PresharedKey when empty\ngot:\n%s", got)
	}
}

func TestRenderPeerConfig_NoPersistentKeepalive(t *testing.T) {
	peer := newTestPeer(t)
	peer.PersistentKeepalive = 0
	server := newTestServer(t)

	got, err := RenderPeerConfig(peer, server)
	if err != nil {
		t.Fatalf("RenderPeerConfig() error = %v", err)
	}

	if strings.Contains(got, "PersistentKeepalive") {
		t.Errorf("RenderPeerConfig() output should not contain PersistentKeepalive when zero\ngot:\n%s", got)
	}
}

func TestRenderPeerConfig_PeerDNSOverridesServer(t *testing.T) {
	peer := newTestPeer(t)
	peer.DNS = "8.8.8.8"
	server := newTestServer(t)

	got, err := RenderPeerConfig(peer, server)
	if err != nil {
		t.Fatalf("RenderPeerConfig() error = %v", err)
	}

	if !strings.Contains(got, "DNS = 8.8.8.8") {
		t.Errorf("RenderPeerConfig() should use peer DNS, got:\n%s", got)
	}
	if strings.Contains(got, "DNS = 1.1.1.1") {
		t.Errorf("RenderPeerConfig() should not contain server DNS when peer DNS is set, got:\n%s", got)
	}
}

func TestRenderPeerConfig_EndpointWithPort(t *testing.T) {
	peer := newTestPeer(t)
	server := newTestServer(t)
	server.Endpoint = "vpn.example.com:9999"

	got, err := RenderPeerConfig(peer, server)
	if err != nil {
		t.Fatalf("RenderPeerConfig() error = %v", err)
	}

	if !strings.Contains(got, "Endpoint = vpn.example.com:9999") {
		t.Errorf("RenderPeerConfig() should use endpoint as-is when port included, got:\n%s", got)
	}
}

func TestRenderPeerConfig_EndpointWithoutPort(t *testing.T) {
	peer := newTestPeer(t)
	server := newTestServer(t)
	server.Endpoint = "vpn.example.com"
	server.ListenPort = 51820

	got, err := RenderPeerConfig(peer, server)
	if err != nil {
		t.Fatalf("RenderPeerConfig() error = %v", err)
	}

	if !strings.Contains(got, "Endpoint = vpn.example.com:51820") {
		t.Errorf("RenderPeerConfig() should append ListenPort when no port in endpoint, got:\n%s", got)
	}
}

func TestDerivePeerAddress(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "first host to second host in /30",
			input: "10.100.0.1/30",
			want:  "10.100.0.2/30",
		},
		{
			name:  "second host advances to third in /30",
			input: "10.100.0.2/30",
			want:  "10.100.0.3/30",
		},
		{
			name:  "last host wraps to first host in /30",
			input: "10.100.0.3/30",
			want:  "10.100.0.1/30",
		},
		{
			name:  "invalid input returned as-is",
			input: "not-an-address",
			want:  "not-an-address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := derivePeerAddress(tt.input)
			if got != tt.want {
				t.Errorf("derivePeerAddress(%q) got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRenderTunnelRemoteConfig(t *testing.T) {
	tunnel := &domain.Tunnel{
		Name:                "site-to-site",
		PublicKey:           "tPubKey01234567890abcdefghijklmnopqrstuv0=",
		Address:             "10.100.0.1/30",
		PresharedKey:        "tPSK0000001234567890abcdefghijklmnopqrst0=",
		PersistentKeepalive: 25,
		DNS:                 "1.1.1.1",
		MTU:                 1420,
	}

	got, err := RenderTunnelRemoteConfig(tunnel, "vpn.example.com:51820", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("RenderTunnelRemoteConfig() error = %v", err)
	}

	for _, want := range []string{
		"# Tunnel: site-to-site",
		"Address = 10.100.0.2/30",
		"PublicKey = " + tunnel.PublicKey,
		"PresharedKey = " + tunnel.PresharedKey,
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 10.0.0.0/24",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderTunnelRemoteConfig() output missing %q\ngot:\n%s", want, got)
		}
	}
}
