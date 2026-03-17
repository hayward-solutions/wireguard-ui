package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		wg, err = wireguard.NewUserspaceManager(cfg.WGInterfaceName)
		if err != nil {
			return err
		}
	} else {
		wg, err = wireguard.NewWgctrlManager(cfg.WGInterfaceName)
		if err != nil {
			return err
		}
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

	// Start stats monitor
	mon := monitor.New(wg, cfg.StatsInterval)
	mon.Start()
	defer mon.Stop()

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
		Store:        store,
		WG:           wg,
		JWTManager:   jwtMgr,
		OIDCProvider: oidcProvider,
		Monitor:      mon,
		PolicyEngine: policyEngine,
		FrontendFS:   frontendFS,
		DevMode:            cfg.DevMode,
		AdminAPIKey:        cfg.AdminAPIKey,
		OIDCAdminGroup:     cfg.OIDCAdminGroup,
		RequireHTTPS:       cfg.RequireHTTPS,
		AllowCustomScripts: cfg.AllowCustomScripts,
	})

	// Start HTTP server
	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // Disabled for SSE
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

	wg.Close()
	return server.Shutdown(shutdownCtx)
}
