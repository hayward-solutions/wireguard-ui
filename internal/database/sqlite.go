package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/database/migrations"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite doesn't support concurrent writes
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	sqlBytes, err := migrations.FS.ReadFile("001_initial.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	_, err = s.db.ExecContext(ctx, string(sqlBytes))
	if err != nil {
		return fmt.Errorf("exec migration: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// --- Server Config ---

func (s *SQLiteStore) GetServerConfig(ctx context.Context) (*domain.ServerConfig, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, private_key, public_key, listen_port, address, dns, mtu,
		       post_up, post_down, endpoint, created_at, updated_at
		FROM server_config WHERE id = 'default'`)

	var cfg domain.ServerConfig
	err := row.Scan(&cfg.ID, &cfg.PrivateKey, &cfg.PublicKey, &cfg.ListenPort,
		&cfg.Address, &cfg.DNS, &cfg.MTU, &cfg.PostUp, &cfg.PostDown,
		&cfg.Endpoint, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get server config: %w", err)
	}
	return &cfg, nil
}

func (s *SQLiteStore) SaveServerConfig(ctx context.Context, cfg *domain.ServerConfig) error {
	cfg.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO server_config (id, private_key, public_key, listen_port, address, dns, mtu, post_up, post_down, endpoint, created_at, updated_at)
		VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			private_key = excluded.private_key,
			public_key = excluded.public_key,
			listen_port = excluded.listen_port,
			address = excluded.address,
			dns = excluded.dns,
			mtu = excluded.mtu,
			post_up = excluded.post_up,
			post_down = excluded.post_down,
			endpoint = excluded.endpoint,
			updated_at = excluded.updated_at`,
		cfg.PrivateKey, cfg.PublicKey, cfg.ListenPort, cfg.Address, cfg.DNS,
		cfg.MTU, cfg.PostUp, cfg.PostDown, cfg.Endpoint, cfg.CreatedAt, cfg.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save server config: %w", err)
	}
	return nil
}

// --- Peers ---

func (s *SQLiteStore) ListPeers(ctx context.Context) ([]domain.Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, email, private_key, public_key, preshared_key,
		       allowed_ips, address, dns, persistent_keepalive, enabled,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM peers ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var peers []domain.Peer
	for rows.Next() {
		var p domain.Peer
		if err := rows.Scan(&p.ID, &p.Name, &p.Email, &p.PrivateKey, &p.PublicKey,
			&p.PresharedKey, &p.AllowedIPs, &p.Address, &p.DNS,
			&p.PersistentKeepalive, &p.Enabled, &p.CreatedBy,
			&p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

func (s *SQLiteStore) GetPeer(ctx context.Context, id string) (*domain.Peer, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, email, private_key, public_key, preshared_key,
		       allowed_ips, address, dns, persistent_keepalive, enabled,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM peers WHERE id = ?`, id)

	var p domain.Peer
	err := row.Scan(&p.ID, &p.Name, &p.Email, &p.PrivateKey, &p.PublicKey,
		&p.PresharedKey, &p.AllowedIPs, &p.Address, &p.DNS,
		&p.PersistentKeepalive, &p.Enabled, &p.CreatedBy,
		&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get peer: %w", err)
	}
	return &p, nil
}

func (s *SQLiteStore) CreatePeer(ctx context.Context, p *domain.Peer) error {
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO peers (id, name, email, private_key, public_key, preshared_key,
		                   allowed_ips, address, dns, persistent_keepalive, enabled, created_by,
		                   created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Email, p.PrivateKey, p.PublicKey, p.PresharedKey,
		p.AllowedIPs, p.Address, p.DNS, p.PersistentKeepalive, p.Enabled,
		p.CreatedBy, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create peer: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdatePeer(ctx context.Context, p *domain.Peer) error {
	p.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE peers SET name = ?, email = ?, allowed_ips = ?, dns = ?,
		       persistent_keepalive = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.Email, p.AllowedIPs, p.DNS,
		p.PersistentKeepalive, p.Enabled, p.UpdatedAt, p.ID)
	if err != nil {
		return fmt.Errorf("update peer: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeletePeer(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	return nil
}

// --- Users ---

func (s *SQLiteStore) UpsertUser(ctx context.Context, u *domain.User) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, name, role, last_login, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			email = excluded.email,
			name = excluded.name,
			last_login = excluded.last_login`,
		u.ID, u.Email, u.Name, u.Role, u.LastLogin, u.CreatedAt)
	if err != nil {
		return fmt.Errorf("upsert user: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, role, last_login, created_at
		FROM users WHERE id = ?`, id)

	var u domain.User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.LastLogin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

// --- Tunnels ---

func (s *SQLiteStore) ListTunnels(ctx context.Context) ([]domain.Tunnel, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, description, config, enabled, created_at, updated_at
		FROM tunnels ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tunnels: %w", err)
	}
	defer rows.Close()

	var tunnels []domain.Tunnel
	for rows.Next() {
		var t domain.Tunnel
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Description, &t.Config,
			&t.Enabled, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan tunnel: %w", err)
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, rows.Err()
}

func (s *SQLiteStore) GetTunnel(ctx context.Context, id string) (*domain.Tunnel, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, description, config, enabled, created_at, updated_at
		FROM tunnels WHERE id = ?`, id)

	var t domain.Tunnel
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Description, &t.Config,
		&t.Enabled, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get tunnel: %w", err)
	}
	return &t, nil
}

func (s *SQLiteStore) CreateTunnel(ctx context.Context, t *domain.Tunnel) error {
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tunnels (id, name, type, description, config, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Type, t.Description, t.Config, t.Enabled, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create tunnel: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateTunnel(ctx context.Context, t *domain.Tunnel) error {
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE tunnels SET name = ?, type = ?, description = ?, config = ?,
		       enabled = ?, updated_at = ?
		WHERE id = ?`,
		t.Name, t.Type, t.Description, t.Config, t.Enabled, t.UpdatedAt, t.ID)
	if err != nil {
		return fmt.Errorf("update tunnel: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteTunnel(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tunnels WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete tunnel: %w", err)
	}
	return nil
}
