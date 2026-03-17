package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type ServerHandler struct {
	store              database.Store
	wg                 wireguard.Manager
	allowCustomScripts bool
}

func NewServerHandler(store database.Store, wg wireguard.Manager, allowCustomScripts bool) *ServerHandler {
	return &ServerHandler{store: store, wg: wg, allowCustomScripts: allowCustomScripts}
}

func (h *ServerHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetServerConfig(r.Context())
	if err != nil {
		slog.Error("get server config", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get server config")
		return
	}
	if cfg == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "server config not initialized")
		return
	}

	// Include custom_scripts_allowed so the frontend knows the state
	type serverConfigResponse struct {
		*domain.ServerConfig
		CustomScriptsAllowed bool `json:"custom_scripts_allowed"`
	}
	writeJSON(w, http.StatusOK, serverConfigResponse{
		ServerConfig:         cfg,
		CustomScriptsAllowed: h.allowCustomScripts,
	})
}

func (h *ServerHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	var update struct {
		ListenPort        int                    `json:"listen_port"`
		Address           string                 `json:"address"`
		DNS               string                 `json:"dns"`
		MTU               int                    `json:"mtu"`
		FirewallConfig    *domain.FirewallConfig  `json:"firewall_config,omitempty"`
		PostUp            string                 `json:"post_up"`
		PostDown          string                 `json:"post_down"`
		Endpoint          string                 `json:"endpoint"`
		DefaultAllowedIPs *string                `json:"default_allowed_ips"`
		DefaultDNS        *string                `json:"default_dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	// Block custom scripts if not allowed
	if (update.PostUp != "" || update.PostDown != "") && !h.allowCustomScripts {
		writeError(w, http.StatusForbidden, "SCRIPTS_DISABLED",
			"custom script execution is disabled; use firewall_config for structured rules or set ALLOW_CUSTOM_SCRIPTS=true")
		return
	}

	// Validate firewall config if provided
	if update.FirewallConfig != nil {
		if err := validateFirewallConfig(update.FirewallConfig); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
	}

	cfg, err := h.store.GetServerConfig(r.Context())
	if err != nil || cfg == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get server config")
		return
	}

	// Audit log script changes
	claims := auth.ClaimsFromContext(r.Context())
	username := "unknown"
	if claims != nil {
		username = claims.Subject
	}

	if update.PostUp != cfg.PostUp {
		slog.Warn("server config script modified",
			"field", "post_up",
			"user", username,
			"old_hash", shortHash(cfg.PostUp),
			"new_hash", shortHash(update.PostUp))
	}
	if update.PostDown != cfg.PostDown {
		slog.Warn("server config script modified",
			"field", "post_down",
			"user", username,
			"old_hash", shortHash(cfg.PostDown),
			"new_hash", shortHash(update.PostDown))
	}

	if update.ListenPort > 0 {
		cfg.ListenPort = update.ListenPort
	}
	if update.Address != "" {
		cfg.Address = update.Address
	}
	if update.DNS != "" {
		cfg.DNS = update.DNS
	}
	if update.MTU > 0 {
		cfg.MTU = update.MTU
	}
	if update.FirewallConfig != nil {
		cfg.FirewallConfig = update.FirewallConfig
	}
	cfg.PostUp = update.PostUp
	cfg.PostDown = update.PostDown
	if update.Endpoint != "" {
		cfg.Endpoint = update.Endpoint
	}
	if update.DefaultAllowedIPs != nil {
		cfg.DefaultAllowedIPs = *update.DefaultAllowedIPs
	}
	if update.DefaultDNS != nil {
		cfg.DefaultDNS = *update.DefaultDNS
	}

	if err := h.store.SaveServerConfig(r.Context(), cfg); err != nil {
		slog.Error("save server config", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to save server config")
		return
	}

	slog.Warn("audit", "action", "server_config_updated", "actor", username)

	writeJSON(w, http.StatusOK, cfg)
}

func (h *ServerHandler) HandleApply(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetServerConfig(r.Context())
	if err != nil || cfg == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get server config")
		return
	}

	// Set the transient AllowCustomScripts flag before starting
	cfg.AllowCustomScripts = h.allowCustomScripts

	if err := h.wg.Start(cfg); err != nil {
		slog.Error("apply server config", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to apply config")
		return
	}

	// Re-add all enabled peers
	peers, err := h.store.ListPeers(r.Context())
	if err != nil {
		slog.Error("list peers for apply", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list peers")
		return
	}

	for i := range peers {
		if !peers[i].Enabled {
			continue
		}
		if err := h.wg.AddPeer(&peers[i]); err != nil {
			slog.Error("add peer during apply", "error", err, "peer", peers[i].Name)
		}
	}

	slog.Warn("audit", "action", "server_config_applied", "actor", actorFromRequest(r))

	writeJSON(w, http.StatusOK, map[string]string{"message": "config applied"})
}

// validateFirewallConfig checks that the FirewallConfig fields are valid.
func validateFirewallConfig(fc *domain.FirewallConfig) error {
	if fc.NATSource != "" {
		if _, _, err := net.ParseCIDR(fc.NATSource); err != nil {
			return fmt.Errorf("invalid nat_source CIDR: %w", err)
		}
	}
	if fc.NATOutInterface != "" {
		// Basic validation: interface names are alphanumeric with optional + glob suffix
		for i, c := range fc.NATOutInterface {
			if c == '+' && i == len(fc.NATOutInterface)-1 {
				continue // trailing + is a valid iptables glob
			}
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
				return fmt.Errorf("invalid nat_out_interface: contains invalid character %q", c)
			}
		}
	}
	return nil
}

// shortHash returns a short SHA-256 hex prefix for audit logging.
func shortHash(s string) string {
	if s == "" {
		return "(empty)"
	}
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}
