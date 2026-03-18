package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

var tunnelNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

// validateTunnelName checks that the name is safe and reasonable.
func validateTunnelName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if !tunnelNameRegexp.MatchString(name) {
		return fmt.Errorf("name must be 1-63 characters, alphanumeric, hyphens, or underscores, starting with an alphanumeric")
	}
	return nil
}

// validateCIDRList validates a comma-separated list of CIDR notations.
func validateCIDRList(s, fieldName string) error {
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParsePrefix(part); err != nil {
			return fmt.Errorf("%s: invalid CIDR %q: %w", fieldName, part, err)
		}
	}
	return nil
}

// validateEndpoint validates a host:port endpoint string.
func validateEndpoint(s string) error {
	if s == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("peer_endpoint: invalid host:port format: %w", err)
	}
	if host == "" {
		return fmt.Errorf("peer_endpoint: host cannot be empty")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("peer_endpoint: port must be 1-65535")
	}
	return nil
}

// validateListenPort validates a listen port value.
func validateListenPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("listen_port must be 0-65535")
	}
	return nil
}

// validateDNS validates a comma-separated list of DNS IPs.
func validateDNS(s string) error {
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParseAddr(part); err != nil {
			return fmt.Errorf("dns: invalid IP address %q: %w", part, err)
		}
	}
	return nil
}

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
		PrivateKey          string `json:"private_key"`
		PublicKey           string `json:"public_key"`
		Address             string `json:"address"`
		ListenPort          int    `json:"listen_port"`
		DNS                 string `json:"dns"`
		MTU                 int    `json:"mtu"`
		PeerPublicKey       string `json:"peer_public_key"`
		PeerEndpoint        string `json:"peer_endpoint"`
		PresharedKey        string `json:"preshared_key"`
		PeerAllowedIPs      string `json:"peer_allowed_ips"`
		PersistentKeepalive int    `json:"persistent_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if err := validateTunnelName(req.Name); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := validateCIDRList(req.Address, "address"); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := validateListenPort(req.ListenPort); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := validateDNS(req.DNS); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := validateEndpoint(req.PeerEndpoint); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := validateCIDRList(req.PeerAllowedIPs, "peer_allowed_ips"); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	// Use client-provided keypair if both private and public keys are given,
	// otherwise generate a new keypair server-side.
	var keyPair *wireguard.KeyPair
	if req.PrivateKey != "" && req.PublicKey != "" {
		keyPair = &wireguard.KeyPair{PrivateKey: req.PrivateKey, PublicKey: req.PublicKey}
	} else {
		var err error
		keyPair, err = wireguard.GenerateKeyPair()
		if err != nil {
			slog.Error("generate tunnel keypair", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate keys")
			return
		}
	}

	// Use provided PSK (for tunnel peering where both sides need the same key),
	// or generate a new one.
	psk := req.PresharedKey
	if psk == "" {
		var err error
		psk, err = wireguard.GeneratePresharedKey()
		if err != nil {
			slog.Error("generate tunnel preshared key", "error", err)
			writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate preshared key")
			return
		}
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
		if err := validateTunnelName(*req.Name); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		tunnel.Name = *req.Name
	}
	if req.Description != nil {
		tunnel.Description = *req.Description
	}
	if req.Address != nil {
		if err := validateCIDRList(*req.Address, "address"); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		tunnel.Address = *req.Address
	}
	if req.ListenPort != nil {
		if err := validateListenPort(*req.ListenPort); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		tunnel.ListenPort = *req.ListenPort
	}
	if req.DNS != nil {
		if err := validateDNS(*req.DNS); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		tunnel.DNS = *req.DNS
	}
	if req.MTU != nil {
		tunnel.MTU = *req.MTU
	}
	if req.PeerPublicKey != nil {
		tunnel.PeerPublicKey = *req.PeerPublicKey
	}
	if req.PeerEndpoint != nil {
		if err := validateEndpoint(*req.PeerEndpoint); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		tunnel.PeerEndpoint = *req.PeerEndpoint
	}
	if req.PeerAllowedIPs != nil {
		if err := validateCIDRList(*req.PeerAllowedIPs, "peer_allowed_ips"); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
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

	// Restart if enabled (RestartTunnel is safe to call even if not currently running)
	if tunnel.Enabled && tunnel.PeerPublicKey != "" {
		if err := h.tunnelMgr.RestartTunnel(tunnel); err != nil {
			slog.Error("failed to restart tunnel after update", "error", err)
		}
	} else {
		// Stop if running but now disabled or has no peer
		h.tunnelMgr.StopTunnel(tunnel.ID)
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
	// Only include an endpoint if the tunnel has an explicit listen port —
	// when listen_port is 0, the tunnel is outbound-only and not reachable
	// at the main server's endpoint.
	var localEndpoint string
	if tunnel.ListenPort > 0 {
		host := serverCfg.Endpoint
		if h, _, err := net.SplitHostPort(serverCfg.Endpoint); err == nil {
			host = h
		}
		localEndpoint = net.JoinHostPort(host, strconv.Itoa(tunnel.ListenPort))
	}

	// Local allowed IPs: the server's VPN subnet (what the remote should route through this tunnel)
	localAllowedIPs := serverCfg.Address

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
