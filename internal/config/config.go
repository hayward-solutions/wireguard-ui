package config

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// devBuild is set to "true" via -ldflags in development builds.
// It allows mock mode to bind to non-loopback addresses.
var devBuild string

type Config struct {
	// Server
	ListenAddr string
	BaseURL    string

	// Database
	DatabaseDriver string
	DatabaseDSN    string

	// OIDC
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       string
	OIDCAdminGroup   string
	OIDCGroupsClaim  string

	// JWT
	JWTSecret     string
	JWTExpiry     time.Duration
	SessionExpiry time.Duration

	// WireGuard
	WGInterfaceName      string
	WGListenPort         int
	WGAddress            string
	WGEndpoint           string
	WGDNS                string
	WGMTU                int
	WGDefaultAllowedIPs  string
	WGUserspaceMode      bool
	WGNetstackMode       bool
	WGMockMode           bool

	// Local Auth
	AdminUsername string
	AdminPassword string
	AdminAPIKey   string

	// Encryption
	EncryptionKey string

	// Tunnels
	TunnelPeers  string // JSON array from TUNNEL_PEERS env var for first-boot
	TunnelSubnet string // CIDR range for auto-allocating tunnel /30 addresses

	// Monitoring
	StatsInterval time.Duration

	// API Tokens
	APITokenMaxLifetime time.Duration

	// Security
	RequireHTTPS       bool
	AllowCustomScripts bool
	CORSOrigins        []string
	TrustedProxies     []string

	// Development
	DevMode bool
}

// OIDCEnabled returns true if OIDC is configured.
func (c *Config) OIDCEnabled() bool {
	return c.OIDCIssuerURL != "" && c.OIDCClientID != "" && c.OIDCClientSecret != ""
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:      envOrDefault("LISTEN_ADDR", ":8080"),
		BaseURL:         envOrDefault("BASE_URL", "http://localhost:8080"),
		DatabaseDriver:  envOrDefault("DATABASE_DRIVER", "sqlite"),
		DatabaseDSN:     envOrDefault("DATABASE_DSN", "/data/wireguard.db"),
		OIDCIssuerURL:   os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:    os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL: os.Getenv("OIDC_REDIRECT_URL"),
		OIDCScopes:      envOrDefault("OIDC_SCOPES", "openid,profile,email"),
		OIDCAdminGroup:  os.Getenv("OIDC_ADMIN_GROUP"),
		OIDCGroupsClaim: envOrDefault("OIDC_GROUPS_CLAIM", "cognito:groups"),
		JWTSecret:       os.Getenv("JWT_SECRET"),
		WGInterfaceName: envOrDefault("WG_INTERFACE_NAME", "wg0"),
		WGAddress:       envOrDefault("WG_ADDRESS", "10.0.0.1/24"),
		WGEndpoint:      os.Getenv("WG_ENDPOINT"),
		WGDNS:           envOrDefault("WG_DNS", "1.1.1.1,8.8.8.8"),
		WGDefaultAllowedIPs: envOrDefault("WG_DEFAULT_ALLOWED_IPS", "0.0.0.0/0, ::/0"),
		AdminUsername:        envOrDefault("ADMIN_USERNAME", "admin"),
		TunnelPeers:     os.Getenv("TUNNEL_PEERS"),
		TunnelSubnet:    envOrDefault("TUNNEL_SUBNET", "10.100.0.0/16"),
		AdminPassword:   os.Getenv("ADMIN_PASSWORD"),
		AdminAPIKey:     os.Getenv("ADMIN_API_KEY"),
		EncryptionKey:   os.Getenv("ENCRYPTION_KEY"),
		DevMode:         envOrDefault("DEV_MODE", "false") == "true",
	}

	var err error

	cfg.WGListenPort, err = envOrDefaultInt("WG_LISTEN_PORT", 51820)
	if err != nil {
		return nil, fmt.Errorf("invalid WG_LISTEN_PORT: %w", err)
	}

	cfg.WGMTU, err = envOrDefaultInt("WG_MTU", 1420)
	if err != nil {
		return nil, fmt.Errorf("invalid WG_MTU: %w", err)
	}

	cfg.RequireHTTPS = envOrDefault("REQUIRE_HTTPS", "false") == "true"
	cfg.AllowCustomScripts = envOrDefault("ALLOW_CUSTOM_SCRIPTS", "false") == "true"
	cfg.WGUserspaceMode = envOrDefault("WG_USERSPACE_MODE", "true") == "true"
	cfg.WGNetstackMode = envOrDefault("WG_NETSTACK_MODE", "false") == "true"
	cfg.WGMockMode = envOrDefault("WG_MOCK_MODE", "false") == "true"

	if origins := os.Getenv("CORS_ORIGINS"); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, trimmed)
			}
		}
	}

	if proxies := os.Getenv("TRUSTED_PROXIES"); proxies != "" {
		for _, p := range strings.Split(proxies, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cfg.TrustedProxies = append(cfg.TrustedProxies, trimmed)
			}
		}
	}

	expiryStr := envOrDefault("JWT_EXPIRY", "15m")
	cfg.JWTExpiry, err = time.ParseDuration(expiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_EXPIRY: %w", err)
	}

	sessionExpiryStr := envOrDefault("SESSION_EXPIRY", "168h")
	cfg.SessionExpiry, err = time.ParseDuration(sessionExpiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid SESSION_EXPIRY: %w", err)
	}

	intervalStr := envOrDefault("STATS_INTERVAL", "10s")
	cfg.StatsInterval, err = time.ParseDuration(intervalStr)
	if err != nil {
		return nil, fmt.Errorf("invalid STATS_INTERVAL: %w", err)
	}

	tokenLifetimeStr := envOrDefault("API_TOKEN_MAX_LIFETIME", "2160h") // 90 days
	cfg.APITokenMaxLifetime, err = time.ParseDuration(tokenLifetimeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid API_TOKEN_MAX_LIFETIME: %w", err)
	}
	if cfg.APITokenMaxLifetime <= 0 {
		return nil, fmt.Errorf("API_TOKEN_MAX_LIFETIME must be positive")
	}

	if cfg.OIDCRedirectURL == "" {
		cfg.OIDCRedirectURL = cfg.BaseURL + "/auth/callback"
	}

	if cfg.AdminAPIKey != "" {
		slog.Warn("ADMIN_API_KEY is deprecated and will be removed in a future release; create per-user API tokens instead")
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	// Enforce key separation in all modes.
	if c.EncryptionKey != "" && c.EncryptionKey == c.JWTSecret {
		return fmt.Errorf("ENCRYPTION_KEY must be different from JWT_SECRET")
	}

	if c.WGMockMode {
		if c.JWTSecret == "" {
			c.JWTSecret = "dev-secret-change-me"
		}
		if c.AdminPassword == "" {
			c.AdminPassword = "admin"
		}
		if c.EncryptionKey == "" {
			c.EncryptionKey = "dev-encryption-key-00"
		}
		if len(c.CORSOrigins) == 0 {
			c.CORSOrigins = []string{"*"}
		}
		if !isLoopbackAddr(c.ListenAddr) {
			if devBuild == "true" {
				slog.Warn("mock mode bound to non-loopback address (allowed by dev build)",
					"listen_addr", c.ListenAddr)
			} else {
				return fmt.Errorf(
					"mock mode refuses to bind to %q; use a loopback address (127.0.0.1, localhost, [::1]) "+
						"or build with -ldflags '-X github.com/hayward-solutions/wireguard-ui/internal/config.devBuild=true'",
					c.ListenAddr,
				)
			}
		}
		return nil
	}

	if c.JWTSecret == "" {
		return fmt.Errorf("required environment variable JWT_SECRET is not set")
	}
	if c.EncryptionKey == "" {
		return fmt.Errorf("required environment variable ENCRYPTION_KEY is not set")
	}
	if c.WGEndpoint == "" {
		return fmt.Errorf("required environment variable WG_ENDPOINT is not set")
	}

	// Must have either OIDC or local admin credentials
	hasOIDC := c.OIDCEnabled()
	hasLocal := c.AdminPassword != ""
	if !hasOIDC && !hasLocal {
		return fmt.Errorf("must configure either OIDC (OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) or local auth (ADMIN_PASSWORD)")
	}

	// Reject well-known weak values.
	weakValues := []string{"changeme", "secret", "password", "admin", "test", "dev-secret-change-me"}
	for _, weak := range weakValues {
		if c.JWTSecret == weak {
			return fmt.Errorf("JWT_SECRET is set to a well-known weak value %q; choose a strong, unique secret", weak)
		}
		if c.AdminPassword == weak {
			return fmt.Errorf("ADMIN_PASSWORD is set to a well-known weak value %q; choose a strong password", weak)
		}
		if c.EncryptionKey == weak {
			return fmt.Errorf("ENCRYPTION_KEY is set to a well-known weak value %q; choose a strong, unique key", weak)
		}
	}

	// Enforce minimum length for cryptographic secrets.
	if len(c.JWTSecret) < 16 {
		return fmt.Errorf("JWT_SECRET must be at least 16 characters (got %d)", len(c.JWTSecret))
	}
	if len(c.EncryptionKey) < 16 {
		return fmt.Errorf("ENCRYPTION_KEY must be at least 16 characters (got %d)", len(c.EncryptionKey))
	}

	return nil
}

func envOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func envOrDefaultInt(key string, defaultVal int) (int, error) {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal, nil
	}
	return strconv.Atoi(val)
}

// isLoopbackAddr returns true if addr binds only to a loopback interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":8080" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
