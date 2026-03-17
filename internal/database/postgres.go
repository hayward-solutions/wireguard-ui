package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/crypto"
	pg_migrations "github.com/hayward-solutions/wireguard-ui/internal/database/pg_migrations"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	db        *sql.DB
	encryptor *crypto.Encryptor
}

func NewPostgresStore(dsn string, encryptor *crypto.Encryptor) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	// Connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &PostgresStore{db: db, encryptor: encryptor}, nil
}

func (s *PostgresStore) Migrate(ctx context.Context) error {
	// Bootstrap schema_migrations table
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := pg_migrations.FS.ReadDir(".")
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
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = $1", entry.Name()).Scan(&count)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", entry.Name(), err)
		}
		if count > 0 {
			continue
		}

		sqlBytes, err := pg_migrations.FS.ReadFile(entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		if _, err := s.db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
		}

		if _, err := s.db.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", entry.Name()); err != nil {
			return fmt.Errorf("record migration %s: %w", entry.Name(), err)
		}

		slog.Info("applied migration", "version", entry.Name(), "driver", "postgres")
	}

	return nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// --- Server Config ---

func (s *PostgresStore) GetServerConfig(ctx context.Context) (*domain.ServerConfig, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, private_key, public_key, listen_port, address, dns, mtu,
		       post_up, post_down, endpoint,
		       COALESCE(default_allowed_ips, '0.0.0.0/0, ::/0'),
		       COALESCE(default_dns, ''),
		       COALESCE(firewall_config, ''),
		       created_at, updated_at
		FROM server_config WHERE id = 'default'`)

	var cfg domain.ServerConfig
	var firewallJSON string
	err := row.Scan(&cfg.ID, &cfg.PrivateKey, &cfg.PublicKey, &cfg.ListenPort,
		&cfg.Address, &cfg.DNS, &cfg.MTU, &cfg.PostUp, &cfg.PostDown,
		&cfg.Endpoint, &cfg.DefaultAllowedIPs, &cfg.DefaultDNS,
		&firewallJSON, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get server config: %w", err)
	}

	if firewallJSON != "" {
		var fc domain.FirewallConfig
		if err := json.Unmarshal([]byte(firewallJSON), &fc); err != nil {
			return nil, fmt.Errorf("unmarshal firewall config: %w", err)
		}
		cfg.FirewallConfig = &fc
	}

	// Decrypt private key
	cfg.PrivateKey, err = s.encryptor.Decrypt(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt server private key: %w", err)
	}

	return &cfg, nil
}

func (s *PostgresStore) SaveServerConfig(ctx context.Context, cfg *domain.ServerConfig) error {
	cfg.UpdatedAt = time.Now()

	// Encrypt private key
	encPrivKey, err := s.encryptor.Encrypt(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("encrypt server private key: %w", err)
	}

	var firewallJSON string
	if cfg.FirewallConfig != nil {
		b, err := json.Marshal(cfg.FirewallConfig)
		if err != nil {
			return fmt.Errorf("marshal firewall config: %w", err)
		}
		firewallJSON = string(b)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO server_config (id, private_key, public_key, listen_port, address, dns, mtu, post_up, post_down, endpoint, default_allowed_ips, default_dns, firewall_config, created_at, updated_at)
		VALUES ('default', $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT(id) DO UPDATE SET
			private_key = EXCLUDED.private_key,
			public_key = EXCLUDED.public_key,
			listen_port = EXCLUDED.listen_port,
			address = EXCLUDED.address,
			dns = EXCLUDED.dns,
			mtu = EXCLUDED.mtu,
			post_up = EXCLUDED.post_up,
			post_down = EXCLUDED.post_down,
			endpoint = EXCLUDED.endpoint,
			default_allowed_ips = EXCLUDED.default_allowed_ips,
			default_dns = EXCLUDED.default_dns,
			firewall_config = EXCLUDED.firewall_config,
			updated_at = EXCLUDED.updated_at`,
		encPrivKey, cfg.PublicKey, cfg.ListenPort, cfg.Address, cfg.DNS,
		cfg.MTU, cfg.PostUp, cfg.PostDown, cfg.Endpoint,
		cfg.DefaultAllowedIPs, cfg.DefaultDNS, firewallJSON, cfg.CreatedAt, cfg.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save server config: %w", err)
	}
	return nil
}

// --- Peers ---

func (s *PostgresStore) ListPeers(ctx context.Context) ([]domain.Peer, error) {
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

func (s *PostgresStore) ListPeersByUser(ctx context.Context, userID string) ([]domain.Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, private_key, public_key, preshared_key,
		       allowed_ips, address, dns, persistent_keepalive, enabled,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM peers WHERE created_by = $1 ORDER BY created_at DESC`, userID)
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

func (s *PostgresStore) GetPeer(ctx context.Context, id string) (*domain.Peer, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, private_key, public_key, preshared_key,
		       allowed_ips, address, dns, persistent_keepalive, enabled,
		       COALESCE(created_by, ''), created_at, updated_at
		FROM peers WHERE id = $1`, id)

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

func (s *PostgresStore) CreatePeer(ctx context.Context, p *domain.Peer) error {
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
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		p.ID, p.Name, encPrivKey, p.PublicKey, encPSK,
		p.AllowedIPs, p.Address, p.DNS, p.PersistentKeepalive, p.Enabled,
		p.CreatedBy, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create peer: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdatePeer(ctx context.Context, p *domain.Peer) error {
	p.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE peers SET name = $1, allowed_ips = $2, dns = $3,
		       persistent_keepalive = $4, enabled = $5, updated_at = $6
		WHERE id = $7`,
		p.Name, p.AllowedIPs, p.DNS,
		p.PersistentKeepalive, p.Enabled, p.UpdatedAt, p.ID)
	if err != nil {
		return fmt.Errorf("update peer: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeletePeer(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	return nil
}

// --- Users ---

func (s *PostgresStore) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, password_hash, name, role, last_login,
		       failed_login_attempts, locked_until, created_at
		FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Name, &u.Role, &u.LastLogin,
			&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, name, role, last_login,
		       failed_login_attempts, locked_until, created_at
		FROM users WHERE id = $1`, id)

	var u domain.User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Name, &u.Role, &u.LastLogin,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, name, role, last_login,
		       failed_login_attempts, locked_until, created_at
		FROM users WHERE username = $1`, username)

	var u domain.User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Name, &u.Role, &u.LastLogin,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	return &u, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, u *domain.User) error {
	u.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, name, role, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		u.ID, u.Username, u.PasswordHash, u.Name, u.Role, u.CreatedAt)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateUser(ctx context.Context, u *domain.User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET username = $1, name = $2, role = $3 WHERE id = $4`,
		u.Username, u.Name, u.Role, u.ID)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id string, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, id)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

// --- Login Security ---

func (s *PostgresStore) RecordFailedLogin(ctx context.Context, userID string) (int, error) {
	var attempts int
	err := s.db.QueryRowContext(ctx, `
		UPDATE users SET failed_login_attempts = failed_login_attempts + 1
		WHERE id = $1 RETURNING failed_login_attempts`, userID).Scan(&attempts)
	if err != nil {
		return 0, fmt.Errorf("record failed login: %w", err)
	}
	return attempts, nil
}

func (s *PostgresStore) ResetFailedLogins(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("reset failed logins: %w", err)
	}
	return nil
}

func (s *PostgresStore) LockUser(ctx context.Context, userID string, until time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET locked_until = $1 WHERE id = $2`, until, userID)
	if err != nil {
		return fmt.Errorf("lock user: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateLastLogin(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login = $1 WHERE id = $2`, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return nil
}

// --- Sessions ---

func (s *PostgresStore) CreateSession(ctx context.Context, sess *domain.Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, created_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, FALSE)`,
		sess.ID, sess.UserID, sess.CreatedAt, sess.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSession(ctx context.Context, id string) (*domain.Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at, revoked
		FROM sessions WHERE id = $1`, id)

	var sess domain.Session
	err := row.Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.Revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return &sess, nil
}

func (s *PostgresStore) RevokeSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked = TRUE WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *PostgresStore) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked = TRUE WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}

func (s *PostgresStore) CleanExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < NOW() OR revoked = TRUE`)
	if err != nil {
		return fmt.Errorf("clean expired sessions: %w", err)
	}
	return nil
}

// --- API Tokens ---

func (s *PostgresStore) ListAPITokensByUser(ctx context.Context, userID string) ([]domain.APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, token_prefix, last_used, expires_at, created_at
		FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
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

func (s *PostgresStore) GetAPITokenByHash(ctx context.Context, tokenHash string) (*domain.APIToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, last_used, expires_at, created_at
		FROM api_tokens WHERE token_hash = $1`, tokenHash)

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

func (s *PostgresStore) CreateAPIToken(ctx context.Context, token *domain.APIToken) error {
	token.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		token.ID, token.UserID, token.Name, token.TokenHash, token.TokenPrefix, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteAPIToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete api token: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateAPITokenLastUsed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used = $1 WHERE id = $2`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("update api token last used: %w", err)
	}
	return nil
}

// --- Tunnels ---

func (s *PostgresStore) ListTunnels(ctx context.Context) ([]domain.Tunnel, error) {
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

func (s *PostgresStore) GetTunnel(ctx context.Context, id string) (*domain.Tunnel, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, description, config, enabled, created_at, updated_at
		FROM tunnels WHERE id = $1`, id)

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

func (s *PostgresStore) CreateTunnel(ctx context.Context, t *domain.Tunnel) error {
	now := time.Now()
	t.CreatedAt = now
	t.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tunnels (id, name, type, description, config, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.Name, t.Type, t.Description, t.Config, t.Enabled, t.CreatedAt, t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create tunnel: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateTunnel(ctx context.Context, t *domain.Tunnel) error {
	t.UpdatedAt = time.Now()
	_, err := s.db.ExecContext(ctx, `
		UPDATE tunnels SET name = $1, type = $2, description = $3, config = $4,
		       enabled = $5, updated_at = $6
		WHERE id = $7`,
		t.Name, t.Type, t.Description, t.Config, t.Enabled, t.UpdatedAt, t.ID)
	if err != nil {
		return fmt.Errorf("update tunnel: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteTunnel(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tunnels WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete tunnel: %w", err)
	}
	return nil
}

var _ Store = (*PostgresStore)(nil)
