package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type TunnelHandler struct {
	store     database.Store
	tunnelMgr *wireguard.TunnelManager
}

func NewTunnelHandler(store database.Store, tunnelMgr *wireguard.TunnelManager) *TunnelHandler {
	return &TunnelHandler{store: store, tunnelMgr: tunnelMgr}
}

func (h *TunnelHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	tunnels, err := h.store.ListTunnels(r.Context())
	if err != nil {
		slog.Error("list tunnels", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list tunnels")
		return
	}
	if tunnels == nil {
		tunnels = []domain.Tunnel{}
	}

	type tunnelWithStatus struct {
		domain.Tunnel
		Status *domain.TunnelStatus `json:"status"`
	}

	result := make([]tunnelWithStatus, len(tunnels))
	for i, t := range tunnels {
		result[i].Tunnel = t
		if h.tunnelMgr.IsRunning(t.ID) {
			status, _ := h.tunnelMgr.GetTunnelStatus(t.ID)
			result[i].Status = status
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *TunnelHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tunnel, err := h.store.GetTunnel(r.Context(), id)
	if err != nil {
		slog.Error("get tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel")
		return
	}
	if tunnel == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tunnel not found")
		return
	}
	writeJSON(w, http.StatusOK, tunnel)
}

func (h *TunnelHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                string `json:"name"`
		Description         string `json:"description"`
		Address             string `json:"address"`
		ListenPort          int    `json:"listen_port"`
		DNS                 string `json:"dns"`
		MTU                 int    `json:"mtu"`
		PeerPublicKey       string `json:"peer_public_key"`
		PeerEndpoint        string `json:"peer_endpoint"`
		PeerAllowedIPs      string `json:"peer_allowed_ips"`
		PersistentKeepalive int    `json:"persistent_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}

	// Generate keypair for this end of the tunnel
	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		slog.Error("generate tunnel keypair", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate keys")
		return
	}

	psk := ""
	if pskKey, err := wireguard.GeneratePresharedKey(); err == nil {
		psk = pskKey
	}

	address := req.Address
	if address == "" {
		address = "10.100.0.1/30"
	}
	mtu := req.MTU
	if mtu == 0 {
		mtu = 1420
	}
	keepalive := req.PersistentKeepalive
	if keepalive == 0 {
		keepalive = 25
	}

	tunnel := &domain.Tunnel{
		ID:                  uuid.New().String(),
		Name:                req.Name,
		Description:         req.Description,
		PrivateKey:          keyPair.PrivateKey,
		PublicKey:           keyPair.PublicKey,
		Address:             address,
		ListenPort:          req.ListenPort,
		DNS:                 req.DNS,
		MTU:                 mtu,
		PeerPublicKey:       req.PeerPublicKey,
		PeerEndpoint:        req.PeerEndpoint,
		PresharedKey:        psk,
		PeerAllowedIPs:      req.PeerAllowedIPs,
		PersistentKeepalive: keepalive,
		Enabled:             true,
	}

	if err := h.store.CreateTunnel(r.Context(), tunnel); err != nil {
		slog.Error("create tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create tunnel")
		return
	}

	slog.Warn("audit", "action", "tunnel_created", "actor", actorFromRequest(r),
		"target_id", tunnel.ID, "target_name", tunnel.Name)

	// Start the tunnel if it has a remote peer configured
	if tunnel.PeerPublicKey != "" {
		if err := h.tunnelMgr.StartTunnel(tunnel); err != nil {
			slog.Error("failed to start tunnel after creation", "error", err, "tunnel", tunnel.Name)
		}
	}

	// Return with PSK visible (one-time disclosure like peer creation)
	type createResponse struct {
		*domain.Tunnel
		PresharedKey string `json:"preshared_key,omitempty"`
	}
	writeJSON(w, http.StatusCreated, createResponse{
		Tunnel:       tunnel,
		PresharedKey: psk,
	})
}

func (h *TunnelHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tunnel, err := h.store.GetTunnel(r.Context(), id)
	if err != nil {
		slog.Error("get tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel")
		return
	}
	if tunnel == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tunnel not found")
		return
	}

	var req struct {
		Name                *string `json:"name"`
		Description         *string `json:"description"`
		Address             *string `json:"address"`
		ListenPort          *int    `json:"listen_port"`
		DNS                 *string `json:"dns"`
		MTU                 *int    `json:"mtu"`
		PeerPublicKey       *string `json:"peer_public_key"`
		PeerEndpoint        *string `json:"peer_endpoint"`
		PeerAllowedIPs      *string `json:"peer_allowed_ips"`
		PersistentKeepalive *int    `json:"persistent_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Name != nil {
		tunnel.Name = *req.Name
	}
	if req.Description != nil {
		tunnel.Description = *req.Description
	}
	if req.Address != nil {
		tunnel.Address = *req.Address
	}
	if req.ListenPort != nil {
		tunnel.ListenPort = *req.ListenPort
	}
	if req.DNS != nil {
		tunnel.DNS = *req.DNS
	}
	if req.MTU != nil {
		tunnel.MTU = *req.MTU
	}
	if req.PeerPublicKey != nil {
		tunnel.PeerPublicKey = *req.PeerPublicKey
	}
	if req.PeerEndpoint != nil {
		tunnel.PeerEndpoint = *req.PeerEndpoint
	}
	if req.PeerAllowedIPs != nil {
		tunnel.PeerAllowedIPs = *req.PeerAllowedIPs
	}
	if req.PersistentKeepalive != nil {
		tunnel.PersistentKeepalive = *req.PersistentKeepalive
	}

	if err := h.store.UpdateTunnel(r.Context(), tunnel); err != nil {
		slog.Error("update tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update tunnel")
		return
	}

	slog.Warn("audit", "action", "tunnel_updated", "actor", actorFromRequest(r),
		"target_id", tunnel.ID, "target_name", tunnel.Name)

	// Restart if running
	if h.tunnelMgr.IsRunning(tunnel.ID) && tunnel.Enabled {
		if err := h.tunnelMgr.RestartTunnel(tunnel); err != nil {
			slog.Error("failed to restart tunnel after update", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, tunnel)
}

func (h *TunnelHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tunnel, err := h.store.GetTunnel(r.Context(), id)
	if err != nil {
		slog.Error("get tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel")
		return
	}
	if tunnel == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tunnel not found")
		return
	}

	// Stop the tunnel if running
	h.tunnelMgr.StopTunnel(id)

	if err := h.store.DeleteTunnel(r.Context(), id); err != nil {
		slog.Error("delete tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete tunnel")
		return
	}

	slog.Warn("audit", "action", "tunnel_deleted", "actor", actorFromRequest(r),
		"target_id", id, "target_name", tunnel.Name)

	writeJSON(w, http.StatusOK, map[string]string{"message": "tunnel deleted"})
}

func (h *TunnelHandler) HandleToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tunnel, err := h.store.GetTunnel(r.Context(), id)
	if err != nil {
		slog.Error("get tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel")
		return
	}
	if tunnel == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tunnel not found")
		return
	}

	tunnel.Enabled = !tunnel.Enabled
	if err := h.store.UpdateTunnel(r.Context(), tunnel); err != nil {
		slog.Error("toggle tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to toggle tunnel")
		return
	}

	slog.Warn("audit", "action", "tunnel_toggled", "actor", actorFromRequest(r),
		"target_id", tunnel.ID, "target_name", tunnel.Name, "enabled", tunnel.Enabled)

	if tunnel.Enabled {
		if err := h.tunnelMgr.StartTunnel(tunnel); err != nil {
			slog.Error("failed to start tunnel", "error", err, "tunnel", tunnel.Name)
		}
	} else {
		h.tunnelMgr.StopTunnel(tunnel.ID)
	}

	writeJSON(w, http.StatusOK, tunnel)
}

func (h *TunnelHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tunnel, err := h.store.GetTunnel(r.Context(), id)
	if err != nil {
		slog.Error("get tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel")
		return
	}
	if tunnel == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tunnel not found")
		return
	}

	status, err := h.tunnelMgr.GetTunnelStatus(id)
	if err != nil {
		slog.Error("get tunnel status", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel status")
		return
	}

	writeJSON(w, http.StatusOK, status)
}

func (h *TunnelHandler) HandleRemoteConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tunnel, err := h.store.GetTunnel(r.Context(), id)
	if err != nil {
		slog.Error("get tunnel", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get tunnel")
		return
	}
	if tunnel == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tunnel not found")
		return
	}

	// Get server config for the endpoint
	serverCfg, err := h.store.GetServerConfig(r.Context())
	if err != nil || serverCfg == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "server not configured")
		return
	}

	// Build local endpoint for the remote to connect to.
	// If the tunnel has its own listen port, use it; otherwise use the server endpoint as-is.
	localEndpoint := serverCfg.Endpoint
	if tunnel.ListenPort > 0 {
		// Strip any existing port from the server endpoint
		host := serverCfg.Endpoint
		if h, _, err := net.SplitHostPort(serverCfg.Endpoint); err == nil {
			host = h
		}
		localEndpoint = net.JoinHostPort(host, strconv.Itoa(tunnel.ListenPort))
	}

	// Local allowed IPs: the tunnel's own address subnet
	localAllowedIPs := tunnel.Address

	conf, err := wireguard.RenderTunnelRemoteConfig(tunnel, localEndpoint, localAllowedIPs)
	if err != nil {
		slog.Error("render tunnel remote config", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to render config")
		return
	}

	slog.Warn("audit", "action", "tunnel_remote_config_exported", "actor", actorFromRequest(r),
		"target_id", tunnel.ID, "target_name", tunnel.Name)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-remote.conf", tunnel.Name))
	w.Write([]byte(conf))
}
