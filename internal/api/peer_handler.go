package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type PeerHandler struct {
	store database.Store
	wg    wireguard.Manager
}

func NewPeerHandler(store database.Store, wg wireguard.Manager) *PeerHandler {
	return &PeerHandler{store: store, wg: wg}
}

func (h *PeerHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	peers, err := h.store.ListPeers(r.Context())
	if err != nil {
		slog.Error("list peers", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list peers")
		return
	}
	if peers == nil {
		peers = []domain.Peer{}
	}
	writeJSON(w, http.StatusOK, peers)
}

func (h *PeerHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	peer, err := h.store.GetPeer(r.Context(), id)
	if err != nil {
		slog.Error("get peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to get peer")
		return
	}
	if peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

func (h *PeerHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name               string `json:"name"`
		Email              string `json:"email"`
		AllowedIPs         string `json:"allowed_ips"`
		DNS                string `json:"dns"`
		PersistentKeepalive int   `json:"persistent_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
		return
	}

	// Generate keys
	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		slog.Error("generate key pair", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate keys")
		return
	}

	psk, err := wireguard.GeneratePresharedKey()
	if err != nil {
		slog.Error("generate preshared key", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate preshared key")
		return
	}

	// Allocate IP
	serverCfg, err := h.store.GetServerConfig(r.Context())
	if err != nil || serverCfg == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "server not configured")
		return
	}

	existingPeers, err := h.store.ListPeers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to list peers")
		return
	}

	usedAddrs := []string{serverCfg.Address}
	for _, p := range existingPeers {
		usedAddrs = append(usedAddrs, p.Address)
	}

	address, err := wireguard.AllocateIP(serverCfg.Address, usedAddrs)
	if err != nil {
		slog.Error("allocate ip", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "no available IP addresses")
		return
	}

	allowedIPs := req.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}

	keepalive := req.PersistentKeepalive
	if keepalive == 0 {
		keepalive = 25
	}

	claims := auth.ClaimsFromContext(r.Context())
	createdBy := ""
	if claims != nil {
		createdBy = claims.Subject
	}

	peer := &domain.Peer{
		ID:                  uuid.New().String(),
		Name:                req.Name,
		Email:               req.Email,
		PrivateKey:          keyPair.PrivateKey,
		PublicKey:           keyPair.PublicKey,
		PresharedKey:        psk,
		AllowedIPs:          allowedIPs,
		Address:             address,
		DNS:                 req.DNS,
		PersistentKeepalive: keepalive,
		Enabled:             true,
		CreatedBy:           createdBy,
	}

	if err := h.store.CreatePeer(r.Context(), peer); err != nil {
		slog.Error("create peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create peer")
		return
	}

	// Add to WireGuard interface
	if err := h.wg.AddPeer(peer); err != nil {
		slog.Error("add peer to wg", "error", err)
		// Peer is saved in DB but not active — non-fatal
	}

	writeJSON(w, http.StatusCreated, peer)
}

func (h *PeerHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	peer, err := h.store.GetPeer(r.Context(), id)
	if err != nil || peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
		return
	}

	var req struct {
		Name                string `json:"name"`
		Email               string `json:"email"`
		AllowedIPs          string `json:"allowed_ips"`
		DNS                 string `json:"dns"`
		PersistentKeepalive *int   `json:"persistent_keepalive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
		return
	}

	if req.Name != "" {
		peer.Name = req.Name
	}
	if req.Email != "" {
		peer.Email = req.Email
	}
	if req.AllowedIPs != "" {
		peer.AllowedIPs = req.AllowedIPs
	}
	if req.DNS != "" {
		peer.DNS = req.DNS
	}
	if req.PersistentKeepalive != nil {
		peer.PersistentKeepalive = *req.PersistentKeepalive
	}

	if err := h.store.UpdatePeer(r.Context(), peer); err != nil {
		slog.Error("update peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to update peer")
		return
	}

	writeJSON(w, http.StatusOK, peer)
}

func (h *PeerHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	peer, err := h.store.GetPeer(r.Context(), id)
	if err != nil || peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
		return
	}

	// Remove from WireGuard
	if err := h.wg.RemovePeer(peer.PublicKey); err != nil {
		slog.Error("remove peer from wg", "error", err)
	}

	if err := h.store.DeletePeer(r.Context(), id); err != nil {
		slog.Error("delete peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete peer")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "peer deleted"})
}

func (h *PeerHandler) HandleToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	peer, err := h.store.GetPeer(r.Context(), id)
	if err != nil || peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
		return
	}

	peer.Enabled = !peer.Enabled
	if err := h.store.UpdatePeer(r.Context(), peer); err != nil {
		slog.Error("toggle peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to toggle peer")
		return
	}

	if peer.Enabled {
		h.wg.AddPeer(peer)
	} else {
		h.wg.RemovePeer(peer.PublicKey)
	}

	writeJSON(w, http.StatusOK, peer)
}
