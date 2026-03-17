package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/crypto"
	"github.com/hayward-solutions/wireguard-ui/internal/database/migrations"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db        *sql.DB
	encryptor *crypto.Encryptor
}

func NewSQLiteStore(dsn string, encryptor *crypto.Encryptor) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn+"?_pragma=journal_mode(wal)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite doesn't support concurrent writes
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return &SQLiteStore{db: db, encryptor: encryptor}, nil
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	// Bootstrap schema_migrations table
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		var count int
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", entry.Name()).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", entry.Name(), err)
		}
		if count > 0 {
			continue
		}

		sqlBytes, err := migrations.FS.ReadFile(entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		if _, err := s.db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
		}

		if _, err := s.db.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", entry.Name()); err != nil {
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}

		slog.Info("applied migration", "version", entry.Name(), "driver", "sqlite")
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
		       post_up, post_down, endpoint,
		       COALESCE(default_allowed_ips, '0.0.0.0/0, ::/0'),
		       COALESCE(default_dns, ''),
		       created_at, updated_at
		FROM server_config WHERE id = 'default'`)

	var cfg domain.ServerConfig
	err := row.Scan(&cfg.ID, &cfg.PrivateKey, &cfg.PublicKey, &cfg.ListenPort,
		&cfg.Address, &cfg.DNS, &cfg.MTU, &cfg.PostUp, &cfg.PostDown,
		&cfg.Endpoint, &cfg.DefaultAllowedIPs, &cfg.DefaultDNS,
		&cfg.CreatedAt, &cfg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get server config: %w", err)
	}

	// Decrypt private key
	cfg.PrivateKey, err = s.encryptor.Decrypt(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt server private key: %w", err)
	}

	return &cfg, nil
}

func (s *SQLiteStore) SaveServerConfig(ctx context.Context, cfg *domain.ServerConfig) error {
	cfg.UpdatedAt = time.Now()

	// Encrypt private key
	encPrivKey, err := s.encryptor.Encrypt(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("encrypt server private key: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO server_config (id, private_key, public_key, listen_port, address, dns, mtu, post_up, post_down, endpoint, default_allowed_ips, default_dns, created_at, updated_at)
		VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			default_allowed_ips = excluded.default_allowed_ips,
			default_dns = excluded.default_dns,
			updated_at = excluded.updated_at`,
		encPrivKey, cfg.PublicKey, cfg.ListenPort, cfg.Address, cfg.DNS,
		cfg.MTU, cfg.PostUp, cfg.PostDown, cfg.Endpoint,
		cfg.DefaultAllowedIPs, cfg.DefaultDNS, cfg.CreatedAt, cfg.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save server config: %w", err)
	}
	return nil
}

// --- Peers ---

func (s *SQLiteStore) ListPeers(ctx context.Context) ([]domain.Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, private_key, public_key, preshared_key,
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
		if err := rows.Scan(&p.ID, &p.Name, &p.PrivateKey, &p.PublicKey,
			&p.PresharedKey, &p.AllowedIPs, &p.Address, &p.DNS,
			&p.PersistentKeepalive, &p.Enabled, &p.CreatedBy,
			&p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}

		// Decrypt private keys
		p.PrivateKey, err = s.encryptor.Decrypt(p.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt peer private key: %w", err)
		}
		p.PresharedKey, err = s.encryptor.Decrypt(p.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt peer preshared key: %w", err)
		}

		peers = append(peers, p)
	}
	return peers, rows.Err()
}

func (s *SQLiteStore) ListPeersByUser(ctx context.Context, userID string) ([]domain.Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, private_key, public_key, preshared_key,
		       allowed_ips, address, dns, persistent_keepalive, enabled,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM peers WHERE created_by = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list peers by user: %w", err)
	}
	defer rows.Close()

	var peers []domain.Peer
	for rows.Next() {
		var p domain.Peer
		if err := rows.Scan(&p.ID, &p.Name, &p.PrivateKey, &p.PublicKey,
			&p.PresharedKey, &p.AllowedIPs, &p.Address, &p.DNS,
			&p.PersistentKeepalive, &p.Enabled, &p.CreatedBy,
			&p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}

		p.PrivateKey, err = s.encryptor.Decrypt(p.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt peer private key: %w", err)
		}
		p.PresharedKey, err = s.encryptor.Decrypt(p.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt peer preshared key: %w", err)
		}

		peers = append(peers, p)
	}
	return peers, rows.Err()
}

func (s *SQLiteStore) GetPeer(ctx context.Context, id string) (*domain.Peer, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, private_key, public_key, preshared_key,
		       allowed_ips, address, dns, persistent_keepalive, enabled,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM peers WHERE id = ?`, id)

	var p domain.Peer
	err := row.Scan(&p.ID, &p.Name, &p.PrivateKey, &p.PublicKey,
		&p.PresharedKey, &p.AllowedIPs, &p.Address, &p.DNS,
		&p.PersistentKeepalive, &p.Enabled, &p.CreatedBy,
		&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get peer: %w", err)
	}

	// Decrypt private keys
	p.PrivateKey, err = s.encryptor.Decrypt(p.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt peer private key: %w", err)
	}
	p.PresharedKey, err = s.encryptor.Decrypt(p.PresharedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt peer preshared key: %w", err)
	}

	return &p, nil
}

func (s *SQLiteStore) CreatePeer(ctx context.Context, p *domain.Peer) error {
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now

	// Encrypt private keys
	encPrivKey, err := s.encryptor.Encrypt(p.PrivateKey)
	if err != nil {
		return fmt.Errorf("encrypt peer private key: %w", err)
	}
	encPSK, err := s.encryptor.Encrypt(p.PresharedKey)
	if err != nil {
		return fmt.Errorf("encrypt peer preshared key: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO peers (id, name, private_key, public_key, preshared_key,
		                   allowed_ips, address, dns, persistent_keepalive, enabled, created_by,
		                   created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, encPrivKey, p.PublicKey, encPSK,
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
		UPDATE peers SET name = ?, allowed_ips = ?, dns = ?,
		       persistent_keepalive = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.AllowedIPs, p.DNS,
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

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, password_hash, name, role, last_login, created_at
		FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Name, &u.Role, &u.LastLogin, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, name, role, last_login, created_at
		FROM users WHERE id = ?`, id)

	var u domain.User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Name, &u.Role, &u.LastLogin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, name, role, last_login, created_at
		FROM users WHERE username = ?`, username)

	var u domain.User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Name, &u.Role, &u.LastLogin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return &u, nil
}

func (s *SQLiteStore) CreateUser(ctx context.Context, u *domain.User) error {
	u.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, name, role, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.Name, u.Role, u.CreatedAt)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, u *domain.User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET username = ?, name = ?, role = ? WHERE id = ?`,
		u.Username, u.Name, u.Role, u.ID)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateUserPassword(ctx context.Context, id string, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// --- API Tokens ---

func (s *SQLiteStore) ListAPITokensByUser(ctx context.Context, userID string) ([]domain.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, token_prefix, last_used, expires_at, created_at
		FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens by user: %w", err)
	}
	defer rows.Close()

	var tokens []domain.APIToken
	for rows.Next() {
		var t domain.APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenPrefix, &t.LastUsed, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) GetAPITokenByHash(ctx context.Context, tokenHash string) (*domain.APIToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, last_used, expires_at, created_at
		FROM api_tokens WHERE token_hash = ?`, tokenHash)

	var t domain.APIToken
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.TokenPrefix, &t.LastUsed, &t.ExpiresAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get api token by hash: %w", err)
	}
	return &t, nil
}

func (s *SQLiteStore) CreateAPIToken(ctx context.Context, token *domain.APIToken) error {
	token.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.UserID, token.Name, token.TokenHash, token.TokenPrefix, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete api token: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateAPITokenLastUsed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("update api token last used: %w", err)
	}
	return nil
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
