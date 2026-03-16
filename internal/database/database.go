package database

import (
	"context"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// Store defines the persistence interface for all application data.
type Store interface {
	// Server config (singleton)
	GetServerConfig(ctx context.Context) (*domain.ServerConfig, error)
	SaveServerConfig(ctx context.Context, cfg *domain.ServerConfig) error

	// Peers
	ListPeers(ctx context.Context) ([]domain.Peer, error)
	GetPeer(ctx context.Context, id string) (*domain.Peer, error)
	CreatePeer(ctx context.Context, p *domain.Peer) error
	UpdatePeer(ctx context.Context, p *domain.Peer) error
	DeletePeer(ctx context.Context, id string) error

	// Users
	UpsertUser(ctx context.Context, u *domain.User) error
	GetUser(ctx context.Context, id string) (*domain.User, error)

	// Tunnels (stretch)
	ListTunnels(ctx context.Context) ([]domain.Tunnel, error)
	GetTunnel(ctx context.Context, id string) (*domain.Tunnel, error)
	CreateTunnel(ctx context.Context, t *domain.Tunnel) error
	UpdateTunnel(ctx context.Context, t *domain.Tunnel) error
	DeleteTunnel(ctx context.Context, id string) error

	// Lifecycle
	Migrate(ctx context.Context) error
	Close() error
}
