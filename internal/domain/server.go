package domain

import "time"

// FirewallConfig provides structured firewall rule management without shell execution.
// When set, iptables commands are called directly with individual arguments (no sh -c).
type FirewallConfig struct {
	EnableNAT        bool   `json:"enable_nat"`
	EnableForwarding bool   `json:"enable_forwarding"`
	AllowPeerToPeer  bool   `json:"allow_peer_to_peer"` // when false (default), drops wg→wg traffic to isolate peers
	NATSource        string `json:"nat_source"`          // CIDR for POSTROUTING; defaults to server Address
	NATOutInterface  string `json:"nat_out_interface"`   // outbound interface glob; defaults to "eth+"
}

type ServerConfig struct {
	ID                string          `json:"id"`
	PrivateKey        string          `json:"-"`
	PublicKey         string          `json:"public_key"`
	ListenPort        int             `json:"listen_port"`
	Address           string          `json:"address"`
	DNS               string          `json:"dns"`
	MTU               int             `json:"mtu"`
	FirewallConfig    *FirewallConfig `json:"firewall_config,omitempty"`
	PostUp            string          `json:"post_up"`
	PostDown          string          `json:"post_down"`
	Endpoint          string          `json:"endpoint"`
	DefaultAllowedIPs string          `json:"default_allowed_ips"`
	DefaultDNS        string          `json:"default_dns"`
	TunnelSubnet      string          `json:"tunnel_subnet"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`

	// AllowCustomScripts is a transient flag (not persisted) set from ALLOW_CUSTOM_SCRIPTS env var.
	// When false, PostUp/PostDown scripts are not executed and cannot be set via API.
	AllowCustomScripts bool `json:"-"`
}
