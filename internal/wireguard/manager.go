package wireguard

import "github.com/hayward-solutions/wireguard-ui/internal/domain"

// Manager defines the interface for WireGuard operations.
type Manager interface {
	// Start initializes the WireGuard interface with the given server config.
	Start(cfg *domain.ServerConfig) error

	// AddPeer configures a peer on the WireGuard interface.
	AddPeer(p *domain.Peer) error

	// RemovePeer removes a peer from the WireGuard interface by public key.
	RemovePeer(publicKey string) error

	// GetStats returns current stats for all peers on the interface.
	GetStats() ([]domain.PeerStats, error)

	// Close shuts down the WireGuard interface.
	Close() error
}
