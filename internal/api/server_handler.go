package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type ServerHandler struct {
	store database.Store
	wg    wireguard.Manager
}

func NewServerHandler(store database.Store, wg wireguard.Manager) *ServerHandler {
	return &ServerHandler{store: store, wg: wg}
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
	writeJSON(w, http.StatusOK, cfg)
}

func (h *ServerHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	var update struct {
		ListenPort        int     `json:"listen_port"`
		Address           string  `json:"address"`
		DNS               string  `json:"dns"`
		MTU               int     `json:"mtu"`
		PostUp            string  `json:"post_up"`
		PostDown          string  `json:"post_down"`
		Endpoint          string  `json:"endpoint"`
		DefaultAllowedIPs *string `json:"default_allowed_ips"`
		DefaultDNS        *string `json:"default_dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	cfg, err := h.store.GetServerConfig(r.Context())
	if err != nil || cfg == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get server config")
		return
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

	writeJSON(w, http.StatusOK, cfg)
}

func (h *ServerHandler) HandleApply(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetServerConfig(r.Context())
	if err != nil || cfg == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get server config")
		return
	}

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

	writeJSON(w, http.StatusOK, map[string]string{"message": "config applied"})
}

var _ = (*domain.ServerConfig)(nil) // ensure import
