package wireguard

import (
	"log/slog"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// MockManager is a no-op WireGuard manager for development without a WireGuard interface.
type MockManager struct{}

func NewMockManager() *MockManager {
	slog.Warn("wireguard: running in mock mode — no real WireGuard interface")
	return &MockManager{}
}

func (m *MockManager) Start(cfg *domain.ServerConfig) error {
	slog.Info("wireguard mock: start", "address", cfg.Address, "port", cfg.ListenPort)
	return nil
}

func (m *MockManager) AddPeer(p *domain.Peer) error {
	slog.Info("wireguard mock: add peer", "name", p.Name, "public_key", p.PublicKey)
	return nil
}

func (m *MockManager) RemovePeer(publicKey string) error {
	slog.Info("wireguard mock: remove peer", "public_key", publicKey)
	return nil
}

func (m *MockManager) GetStats() ([]domain.PeerStats, error) {
	return []domain.PeerStats{}, nil
}

func (m *MockManager) Close() error {
	return nil
}

var _ Manager = (*MockManager)(nil)

// MockManagerWithPeers extends MockManager to return fake stats for testing the UI.
type MockManagerWithPeers struct {
	peers map[string]*domain.Peer
}

func NewMockManagerWithPeers() *MockManagerWithPeers {
	slog.Warn("wireguard: running in mock mode with fake stats")
	return &MockManagerWithPeers{peers: make(map[string]*domain.Peer)}
}

func (m *MockManagerWithPeers) Start(cfg *domain.ServerConfig) error { return nil }

func (m *MockManagerWithPeers) AddPeer(p *domain.Peer) error {
	m.peers[p.PublicKey] = p
	return nil
}

func (m *MockManagerWithPeers) RemovePeer(publicKey string) error {
	delete(m.peers, publicKey)
	return nil
}

func (m *MockManagerWithPeers) GetStats() ([]domain.PeerStats, error) {
	var stats []domain.PeerStats
	for _, p := range m.peers {
		stats = append(stats, domain.PeerStats{
			PublicKey:     p.PublicKey,
			Endpoint:      "192.168.1.100:51820",
			LastHandshake: time.Now().Add(-30 * time.Second),
			TransferRx:    1024 * 1024 * 5,
			TransferTx:    1024 * 1024 * 2,
			Connected:     true,
		})
	}
	return stats, nil
}

func (m *MockManagerWithPeers) Close() error { return nil }

var _ Manager = (*MockManagerWithPeers)(nil)
