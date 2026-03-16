package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hayward-solutions/wireguard-ui/frontend"
	"github.com/hayward-solutions/wireguard-ui/internal/api"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/config"
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

	// Initialize database
	var store database.Store
	switch cfg.DatabaseDriver {
	case "sqlite":
		store, err = database.NewSQLiteStore(cfg.DatabaseDSN)
	default:
		slog.Error("unsupported database driver", "driver", cfg.DatabaseDriver)
		return err
	}
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		return err
	}
	slog.Info("database migrated", "driver", cfg.DatabaseDriver)

	// Initialize WireGuard manager
	var wg wireguard.Manager
	if cfg.WGMockMode {
		wg = wireguard.NewMockManager()
	} else {
		wg = wireguard.NewMockManager() // TODO: replace with real wgctrl manager
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
		serverCfg = &domain.ServerConfig{
			ID:         "default",
			PrivateKey: keyPair.PrivateKey,
			PublicKey:  keyPair.PublicKey,
			ListenPort: cfg.WGListenPort,
			Address:    cfg.WGAddress,
			DNS:        cfg.WGDNS,
			MTU:        cfg.WGMTU,
			Endpoint:   cfg.WGEndpoint,
			CreatedAt:  time.Now(),
		}
		if err := store.SaveServerConfig(ctx, serverCfg); err != nil {
			return err
		}
	}

	// Start WireGuard interface
	if err := wg.Start(serverCfg); err != nil {
		slog.Error("failed to start wireguard", "error", err)
		// Non-fatal in mock mode
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
		Store:         store,
		WG:            wg,
		JWTManager:    jwtMgr,
		OIDCProvider:  oidcProvider,
		Monitor:       mon,
		FrontendFS:    frontendFS,
		DevMode:       cfg.DevMode,
		AdminUsername: cfg.AdminUsername,
		AdminPassword: cfg.AdminPassword,
		APIKey:        cfg.APIKey,
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
