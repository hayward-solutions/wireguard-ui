package domain

import "time"

// Tunnel represents a WireGuard tunnel connection to a remote server.
// Each tunnel runs on its own WireGuard interface (netstack or userspace).
type Tunnel struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`

	// Local WireGuard interface config
	PrivateKey string `json:"-"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`     // VPN address for this end, e.g. "10.100.0.1/30"
	ListenPort int    `json:"listen_port"` // 0 = ephemeral (outbound-only)
	DNS        string `json:"dns"`
	MTU        int    `json:"mtu"`

	// Remote peer config
	PeerPublicKey       string `json:"peer_public_key"`
	PeerEndpoint        string `json:"peer_endpoint"`    // e.g. "vpn-west.example.com:51820"
	PresharedKey        string `json:"-"`
	PeerAllowedIPs      string `json:"peer_allowed_ips"` // remote subnets, e.g. "10.1.0.0/24, 10.2.0.0/24"
	PersistentKeepalive int    `json:"persistent_keepalive"`

	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TunnelStatus represents the runtime connection status of a tunnel.
type TunnelStatus struct {
	TunnelID      string    `json:"tunnel_id"`
	Connected     bool      `json:"connected"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	TransferRx    int64     `json:"transfer_rx"`
	TransferTx    int64     `json:"transfer_tx"`
	Endpoint      string    `json:"endpoint,omitempty"`
}
