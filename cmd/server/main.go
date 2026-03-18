package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/frontend"
	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"github.com/hayward-solutions/wireguard-ui/internal/api"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/config"
	"github.com/hayward-solutions/wireguard-ui/internal/crypto"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/monitor"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Load config
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Initialize encryptor for at-rest encryption
	encryptor, err := crypto.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return err
	}
	if encryptor != nil {
		slog.Info("at-rest encryption enabled")
	}

	// Initialize database
	var store database.Store
	switch cfg.DatabaseDriver {
	case "sqlite":
		store, err = database.NewSQLiteStore(cfg.DatabaseDSN, encryptor)
	case "postgres":
		store, err = database.NewPostgresStore(cfg.DatabaseDSN, encryptor)
	default:
		return fmt.Errorf("unsupported database driver: %s", cfg.DatabaseDriver)
	}
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("database migrated", "driver", cfg.DatabaseDriver)

	// Refuse to start if database has encrypted data but no encryption key is configured.
	if encryptor == nil {
		hasEnc, err := store.HasEncryptedData(ctx)
		if err != nil {
			return fmt.Errorf("check encrypted data: %w", err)
		}
		if hasEnc {
			return fmt.Errorf("database contains encrypted data but ENCRYPTION_KEY is not set; set ENCRYPTION_KEY to decrypt existing data")
		}
	}

	// Seed default admin user if no users exist
	if cfg.AdminPassword != "" {
		if err := api.EnsureDefaultAdmin(ctx, store, cfg.AdminUsername, cfg.AdminPassword); err != nil {
			return fmt.Errorf("failed to ensure default admin: %w", err)
		}
	}

	// Initialize ACL policy engine
	policyEngine := acl.NewPolicyEngine()
	if err := policyEngine.Reload(ctx, store); err != nil {
		slog.Warn("initial ACL policy load failed", "error", err)
	}

	// Initialize WireGuard manager
	var wg wireguard.Manager
	if cfg.WGMockMode {
		wg = wireguard.NewMockManager()
	} else if cfg.WGNetstackMode {
		nm := wireguard.NewNetstackManager()
		nm.SetPolicyEngine(policyEngine)
		wg = nm
	} else if cfg.WGUserspaceMode {
		um, err := wireguard.NewUserspaceManager(cfg.WGInterfaceName)
		if err != nil {
			return err
		}
		enforcer := wireguard.NewIptablesACLEnforcer(cfg.WGInterfaceName)
		um.SetACLEnforcer(enforcer)
		policyEngine.RegisterListener(enforcer)
		wg = um
	} else {
		wm, err := wireguard.NewWgctrlManager(cfg.WGInterfaceName)
		if err != nil {
			return err
		}
		enforcer := wireguard.NewIptablesACLEnforcer(cfg.WGInterfaceName)
		wm.SetACLEnforcer(enforcer)
		policyEngine.RegisterListener(enforcer)
		wg = wm
	}

	// Auto-initialize server config on first boot
	serverCfg, err := store.GetServerConfig(ctx)
	if err != nil {
		return err
	}
	if serverCfg == nil {
		slog.Info("first boot: generating server keypair")
		keyPair, err := wireguard.GenerateKeyPair()
		if err != nil {
			return err
		}

		// Build structured firewall config for NAT masquerade.
		// In netstack mode this is skipped (no kernel interface for iptables).
		var fwCfg *domain.FirewallConfig
		if !cfg.WGNetstackMode {
			fwCfg = &domain.FirewallConfig{
				EnableNAT:        true,
				EnableForwarding: true,
				NATSource:        cfg.WGAddress,
				NATOutInterface:  "eth+",
			}
		}

		serverCfg = &domain.ServerConfig{
			ID:                "default",
			PrivateKey:        keyPair.PrivateKey,
			PublicKey:         keyPair.PublicKey,
			ListenPort:        cfg.WGListenPort,
			Address:           cfg.WGAddress,
			DNS:               cfg.WGDNS,
			MTU:               cfg.WGMTU,
			FirewallConfig:    fwCfg,
			Endpoint:          cfg.WGEndpoint,
			DefaultAllowedIPs: cfg.WGDefaultAllowedIPs,
			DefaultDNS:        cfg.WGDNS,
			CreatedAt:         time.Now(),
		}
		if err := store.SaveServerConfig(ctx, serverCfg); err != nil {
			return err
		}
	} else {
		// Existing install: auto-migrate default PostUp/PostDown to structured FirewallConfig
		if serverCfg.FirewallConfig == nil && serverCfg.PostUp != "" {
			if wireguard.IsDefaultFirewallScript(serverCfg.PostUp, serverCfg.Address, cfg.WGInterfaceName) {
				slog.Info("migrating default PostUp/PostDown to structured FirewallConfig")
				serverCfg.FirewallConfig = &domain.FirewallConfig{
					EnableNAT:        true,
					EnableForwarding: true,
					NATSource:        serverCfg.Address,
					NATOutInterface:  "eth+",
				}
				serverCfg.PostUp = ""
				serverCfg.PostDown = ""
				if err := store.SaveServerConfig(ctx, serverCfg); err != nil {
					return fmt.Errorf("migrate firewall config: %w", err)
				}
			} else if !cfg.AllowCustomScripts {
				slog.Warn("custom PostUp/PostDown scripts detected but ALLOW_CUSTOM_SCRIPTS is not set; scripts will not be executed",
					"post_up_length", len(serverCfg.PostUp),
					"post_down_length", len(serverCfg.PostDown))
			}
		}
	}

	// Set transient config flags before starting
	serverCfg.AllowCustomScripts = cfg.AllowCustomScripts

	// Start WireGuard interface
	if err := wg.Start(serverCfg); err != nil {
		if cfg.WGMockMode {
			slog.Warn("failed to start wireguard (mock mode, continuing)", "error", err)
		} else {
			return fmt.Errorf("failed to start wireguard: %w", err)
		}
	}

	// Re-sync all enabled peers from DB into the WireGuard interface.
	// This ensures peers survive container restarts.
	{
		peers, err := store.ListPeers(ctx)
		if err != nil {
			slog.Error("failed to list peers for re-sync", "error", err)
		} else {
			synced := 0
			for i := range peers {
				if !peers[i].Enabled {
					continue
				}
				if err := wg.AddPeer(&peers[i]); err != nil {
					slog.Error("failed to re-sync peer", "error", err, "peer", peers[i].Name)
				} else {
					synced++
				}
			}
			if synced > 0 {
				slog.Info("re-synced peers from database", "count", synced)
			}
		}
	}

	// Initialize tunnel manager
	var tunnelMode wireguard.TunnelMode
	switch {
	case cfg.WGMockMode:
		tunnelMode = wireguard.TunnelModeMock
	case cfg.WGNetstackMode:
		tunnelMode = wireguard.TunnelModeNetstack
	case cfg.WGUserspaceMode:
		tunnelMode = wireguard.TunnelModeUserspace
	default:
		tunnelMode = wireguard.TunnelModeKernel
	}
	tunnelMgr := wireguard.NewTunnelManager(tunnelMode, cfg.WGInterfaceName)

	// For netstack mode, give the TunnelManager a reference to the main
	// NetstackManager so tunnel dialers can be registered on the forwarder.
	if cfg.WGNetstackMode {
		if nm, ok := wg.(*wireguard.NetstackManager); ok {
			tunnelMgr.SetMainNetstackManager(nm)
		}
	}

	// Bootstrap tunnels from TUNNEL_PEERS env var (first-boot)
	if cfg.TunnelPeers != "" {
		if err := bootstrapTunnels(ctx, store, cfg.TunnelPeers); err != nil {
			slog.Error("failed to bootstrap tunnels from TUNNEL_PEERS", "error", err)
		}
	}

	// Start all enabled tunnels from database
	{
		tunnels, err := store.ListEnabledTunnels(ctx)
		if err != nil {
			slog.Error("failed to list tunnels for startup", "error", err)
		} else {
			started := 0
			for i := range tunnels {
				if err := tunnelMgr.StartTunnel(&tunnels[i]); err != nil {
					slog.Error("failed to start tunnel", "error", err, "tunnel", tunnels[i].Name)
				} else {
					started++
				}
			}
			if started > 0 {
				slog.Info("started tunnels from database", "count", started)
			}
		}
	}

	// Reload ACL policies now that listeners are registered and peers are synced.
	// The initial Reload() above ran before listeners were registered.
	if err := policyEngine.Reload(ctx, store); err != nil {
		slog.Warn("ACL policy reload after listener registration failed", "error", err)
	}

	// Start stats monitor
	mon := monitor.New(wg, cfg.StatsInterval)
	mon.Start()
	defer mon.Stop()

	// Initialize rate limiters
	authRateLimiter := auth.NewRateLimiter(5, 10)    // 5/s burst 10 for auth endpoints
	loginRateLimiter := auth.NewRateLimiter(1, 5)     // 1/s burst 5 per-username
	passwordRateLimiter := auth.NewRateLimiter(3, 5)   // 3/s burst 5 for password endpoints
	defer authRateLimiter.Stop()
	defer loginRateLimiter.Stop()
	defer passwordRateLimiter.Stop()

	// Start session cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.CleanExpiredSessions(context.Background()); err != nil {
					slog.Error("failed to clean expired sessions", "error", err)
				}
				if err := store.DeleteExpiredAPITokens(context.Background()); err != nil {
					slog.Error("failed to clean expired API tokens", "error", err)
				}
			}
		}
	}()

	// Initialize JWT manager
	jwtMgr := auth.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiry)

	// Initialize OIDC provider (optional)
	var oidcProvider *auth.OIDCProvider
	if cfg.OIDCEnabled() {
		oidcProvider, err = auth.NewOIDCProvider(ctx, auth.OIDCConfig{
			IssuerURL:    cfg.OIDCIssuerURL,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       cfg.OIDCScopes,
		})
		if err != nil {
			slog.Error("failed to init oidc provider", "error", err)
			if !cfg.WGMockMode {
				return err
			}
		}
	}

	// Build router
	frontendFS := frontend.FS()
	router := api.NewRouter(api.RouterConfig{
		Store:               store,
		WG:                  wg,
		TunnelManager:       tunnelMgr,
		JWTManager:          jwtMgr,
		OIDCProvider:        oidcProvider,
		Monitor:             mon,
		PolicyEngine:        policyEngine,
		FrontendFS:          frontendFS,
		AuthRateLimiter:     authRateLimiter,
		LoginRateLimiter:    loginRateLimiter,
		PasswordRateLimiter: passwordRateLimiter,
		SessionExpiry:       cfg.SessionExpiry,
		DevMode:             cfg.DevMode,
		AdminAPIKey:         cfg.AdminAPIKey,
		APITokenMaxLifetime: cfg.APITokenMaxLifetime,
		OIDCAdminGroup:      cfg.OIDCAdminGroup,
		RequireHTTPS:        cfg.RequireHTTPS,
		AllowCustomScripts:  cfg.AllowCustomScripts,
		CORSOrigins:         cfg.CORSOrigins,
		TrustedProxies:      cfg.TrustedProxies,
	})

	// Start HTTP server
	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("server starting", "addr", cfg.ListenAddr, "mock_mode", cfg.WGMockMode)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	tunnelMgr.Close()
	wg.Close()
	return server.Shutdown(shutdownCtx)
}

// tunnelPeerSpec represents a tunnel definition from the TUNNEL_PEERS env var.
type tunnelPeerSpec struct {
	Name                string `json:"name"`
	Address             string `json:"address"`
	ListenPort          int    `json:"listen_port"`
	PeerPublicKey       string `json:"peer_public_key"`
	PeerEndpoint        string `json:"peer_endpoint"`
	PeerAllowedIPs      string `json:"peer_allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	DNS                 string `json:"dns"`
	MTU                 int    `json:"mtu"`
}

// bootstrapTunnels parses the TUNNEL_PEERS JSON array and creates tunnels that don't already exist.
func bootstrapTunnels(ctx context.Context, store database.Store, tunnelPeersJSON string) error {
	var specs []tunnelPeerSpec
	if err := json.Unmarshal([]byte(tunnelPeersJSON), &specs); err != nil {
		return fmt.Errorf("parse TUNNEL_PEERS JSON: %w", err)
	}

	for _, spec := range specs {
		if spec.Name == "" {
			slog.Warn("skipping tunnel with empty name in TUNNEL_PEERS")
			continue
		}

		existing, err := store.GetTunnelByName(ctx, spec.Name)
		if err != nil {
			return fmt.Errorf("check existing tunnel %q: %w", spec.Name, err)
		}
		if existing != nil {
			slog.Info("tunnel already exists, skipping bootstrap", "name", spec.Name)
			continue
		}

		keyPair, err := wireguard.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate keypair for tunnel %q: %w", spec.Name, err)
		}

		psk := ""
		pskKey, err := wireguard.GeneratePresharedKey()
		if err != nil {
			slog.Warn("failed to generate PSK for tunnel, continuing without", "name", spec.Name, "error", err)
		} else {
			psk = pskKey
		}

		address := spec.Address
		if address == "" {
			address = "10.100.0.1/30"
		}
		mtu := spec.MTU
		if mtu == 0 {
			mtu = 1420
		}
		keepalive := spec.PersistentKeepalive
		if keepalive == 0 {
			keepalive = 25
		}

		tunnel := &domain.Tunnel{
			ID:                  uuid.New().String(),
			Name:                spec.Name,
			PrivateKey:          keyPair.PrivateKey,
			PublicKey:           keyPair.PublicKey,
			Address:             address,
			ListenPort:          spec.ListenPort,
			DNS:                 spec.DNS,
			MTU:                 mtu,
			PeerPublicKey:       spec.PeerPublicKey,
			PeerEndpoint:        spec.PeerEndpoint,
			PresharedKey:        psk,
			PeerAllowedIPs:      spec.PeerAllowedIPs,
			PersistentKeepalive: keepalive,
			Enabled:             true,
		}

		if err := store.CreateTunnel(ctx, tunnel); err != nil {
			return fmt.Errorf("create tunnel %q: %w", spec.Name, err)
		}

		slog.Info("bootstrapped tunnel from TUNNEL_PEERS",
			"name", tunnel.Name,
			"id", tunnel.ID,
			"public_key", tunnel.PublicKey)
	}

	return nil
}
