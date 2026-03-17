package api

import (
	"io/fs"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/monitor"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type RouterConfig struct {
	Store        database.Store
	WG           wireguard.Manager
	JWTManager   *auth.JWTManager
	OIDCProvider *auth.OIDCProvider
	Monitor      *monitor.Monitor
	PolicyEngine *acl.PolicyEngine
	FrontendFS   fs.FS
	AuthRateLimiter    *auth.RateLimiter
	LoginRateLimiter   *auth.RateLimiter
	PasswordRateLimiter *auth.RateLimiter
	SessionExpiry      time.Duration
	DevMode            bool
	AdminAPIKey        string
	OIDCAdminGroup     string
	RequireHTTPS       bool
	AllowCustomScripts bool
	CORSOrigins        []string
}

func NewRouter(cfg RouterConfig) *chi.Mux {
	r := chi.NewRouter()

	// HTTPS enforcement (must be first to redirect before any other processing)
	if cfg.RequireHTTPS {
		r.Use(HTTPSRedirectMiddleware)
	}

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// Only allow credentialed cross-origin requests for explicitly listed origins.
	// Wildcard ("*") disables credentials to prevent ambient-authority attacks.
	allowCreds := len(cfg.CORSOrigins) > 0 && cfg.CORSOrigins[0] != "*"
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key"},
		AllowCredentials: allowCreds,
		MaxAge:           300,
	}))

	authHandler := NewAuthHandler(AuthHandlerConfig{
		OIDC:           cfg.OIDCProvider,
		JWT:            cfg.JWTManager,
		Store:          cfg.Store,
		LoginLimiter:   cfg.LoginRateLimiter,
		OIDCAdminGroup: cfg.OIDCAdminGroup,
		SecureCookie:   cfg.RequireHTTPS,
		PolicyEngine:   cfg.PolicyEngine,
		SessionExpiry:  cfg.SessionExpiry,
	})

	// Health check (unauthenticated)
	r.Get("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Auth routes (unauthenticated, rate-limited by IP)
	r.Group(func(r chi.Router) {
		if cfg.AuthRateLimiter != nil {
			r.Use(auth.IPRateLimitMiddleware(cfg.AuthRateLimiter))
		}
		r.Get("/auth/info", authHandler.HandleAuthInfo)
		r.Get("/auth/login", authHandler.HandleLoginPage)
		r.Post("/auth/login", authHandler.HandleLocalLogin)
		r.Get("/auth/callback", authHandler.HandleCallback)
		r.Post("/auth/logout", authHandler.HandleLogout)
		r.Post("/auth/refresh", authHandler.HandleRefresh)
	})

	// Authenticated API routes
	r.Group(func(r chi.Router) {
		// API key middleware runs first — sets claims if valid key provided
		r.Use(auth.APIKeyMiddleware(cfg.AdminAPIKey, cfg.Store))
		r.Use(auth.Middleware(cfg.JWTManager))

		r.Get("/auth/me", authHandler.HandleMe)

		// Server config (read: all authenticated, write: admin only)
		serverHandler := NewServerHandler(cfg.Store, cfg.WG, cfg.AllowCustomScripts)
		r.Get("/api/v1/server", serverHandler.HandleGet)
		r.With(RequireAdmin).Put("/api/v1/server", serverHandler.HandleUpdate)
		r.With(RequireAdmin).Post("/api/v1/server/apply", serverHandler.HandleApply)

		// Peers (read: all authenticated, write: editor+, ownership enforced in handlers)
		peerHandler := NewPeerHandler(cfg.Store, cfg.WG, cfg.PolicyEngine)
		r.Get("/api/v1/peers", peerHandler.HandleList)
		r.With(RequireRole(domain.RoleEditor)).Post("/api/v1/peers", peerHandler.HandleCreate)
		r.Get("/api/v1/peers/{id}", peerHandler.HandleGet)
		r.With(RequireRole(domain.RoleEditor)).Put("/api/v1/peers/{id}", peerHandler.HandleUpdate)
		r.With(RequireRole(domain.RoleEditor)).Delete("/api/v1/peers/{id}", peerHandler.HandleDelete)
		r.With(RequireRole(domain.RoleEditor)).Patch("/api/v1/peers/{id}/toggle", peerHandler.HandleToggle)

		// Export (ownership enforced in handlers)
		exportHandler := NewExportHandler(cfg.Store)
		r.Get("/api/v1/peers/{id}/config", exportHandler.HandleConfig)
		r.Get("/api/v1/peers/{id}/qrcode", exportHandler.HandleQRCode)

		// Stats
		statsHandler := NewStatsHandler(cfg.Monitor, cfg.Store)
		r.Get("/api/v1/stats", statsHandler.HandleGet)
		r.Get("/api/v1/stats/stream", statsHandler.HandleStream)

		// Self-service: password change and API tokens (with tighter rate limit)
		userHandler := NewUserHandler(cfg.Store)
		if cfg.PasswordRateLimiter != nil {
			r.With(auth.IPRateLimitMiddleware(cfg.PasswordRateLimiter)).Post("/api/v1/me/password", userHandler.HandleChangePassword)
		} else {
			r.Post("/api/v1/me/password", userHandler.HandleChangePassword)
		}

		tokenHandler := NewTokenHandler(cfg.Store)
		r.Get("/api/v1/me/tokens", tokenHandler.HandleList)
		r.Post("/api/v1/me/tokens", tokenHandler.HandleCreate)
		r.Delete("/api/v1/me/tokens/{id}", tokenHandler.HandleDelete)

		// Groups (admin only)
		groupHandler := NewGroupHandler(cfg.Store, cfg.PolicyEngine)
		r.Route("/api/v1/groups", func(r chi.Router) {
			r.Use(RequireAdmin)
			r.Get("/", groupHandler.HandleList)
			r.Post("/", groupHandler.HandleCreate)
			r.Get("/{id}", groupHandler.HandleGet)
			r.Put("/{id}", groupHandler.HandleUpdate)
			r.Delete("/{id}", groupHandler.HandleDelete)
			r.Get("/{id}/members", groupHandler.HandleMembers)
		})

		// ACL rules (admin only)
		aclHandler := NewACLHandler(cfg.Store, cfg.PolicyEngine)
		r.Route("/api/v1/acls", func(r chi.Router) {
			r.Use(RequireAdmin)
			r.Get("/", aclHandler.HandleList)
			r.Post("/", aclHandler.HandleCreate)
			r.Get("/effective/{userID}", aclHandler.HandleEffective)
			r.Post("/reload", aclHandler.HandleReload)
			r.Get("/{id}", aclHandler.HandleGet)
			r.Put("/{id}", aclHandler.HandleUpdate)
			r.Delete("/{id}", aclHandler.HandleDelete)
		})

		// User management (admin only)
		r.Route("/api/v1/users", func(r chi.Router) {
			r.Use(RequireAdmin)
			if cfg.PasswordRateLimiter != nil {
				r.Use(auth.IPRateLimitMiddleware(cfg.PasswordRateLimiter))
			}
			r.Get("/", userHandler.HandleList)
			r.Post("/", userHandler.HandleCreate)
			r.Get("/{id}", userHandler.HandleGet)
			r.Put("/{id}", userHandler.HandleUpdate)
			r.Delete("/{id}", userHandler.HandleDelete)
			r.Post("/{id}/reset-password", userHandler.HandleResetPassword)
			r.Put("/{id}/groups", groupHandler.HandleSetUserGroups)
			r.Get("/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
				userID := chi.URLParam(r, "id")
				groups, err := cfg.Store.GetUserGroups(r.Context(), userID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get user groups")
					return
				}
				if groups == nil {
					groups = []domain.Group{}
				}
				writeJSON(w, http.StatusOK, groups)
			})
		})
	})

	// Serve frontend SPA
	if cfg.FrontendFS != nil {
		spaHandler := spaFileServer(cfg.FrontendFS)
		r.NotFound(spaHandler)
	}

	return r
}

func spaFileServer(frontendFS fs.FS) http.HandlerFunc {
	fileServer := http.FileServerFS(frontendFS)
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "index.html"
		}
		if _, err := fs.Stat(frontendFS, path[1:]); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	}
}
