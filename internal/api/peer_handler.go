package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type PeerHandler struct {
	store  database.Store
	wg     wireguard.Manager
	engine *acl.PolicyEngine
}

func NewPeerHandler(store database.Store, wg wireguard.Manager, engine *acl.PolicyEngine) *PeerHandler {
	return &PeerHandler{store: store, wg: wg, engine: engine}
}

func (h *PeerHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing credentials")
		return
	}

	var peers []domain.Peer
	var err error

	if claims.Role == domain.RoleAdmin {
		peers, err = h.store.ListPeers(r.Context())
		if err == nil {
			h.resolveOwnerNames(r, peers)
		}
	} else {
		peers, err = h.store.ListPeersByUser(r.Context(), claims.Subject)
	}

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

// resolveOwnerNames populates CreatedByName for each peer by looking up user records.
func (h *PeerHandler) resolveOwnerNames(r *http.Request, peers []domain.Peer) {
	nameMap := make(map[string]string)
	for _, p := range peers {
		if p.CreatedBy != "" {
			if _, ok := nameMap[p.CreatedBy]; !ok {
				nameMap[p.CreatedBy] = "" // mark for lookup
			}
		}
	}
	for uid := range nameMap {
		u, err := h.store.GetUser(r.Context(), uid)
		if err == nil && u != nil {
			name := u.Name
			if name == "" {
				name = u.Username
			}
			nameMap[uid] = name
		}
	}
	for i := range peers {
		if name, ok := nameMap[peers[i].CreatedBy]; ok {
			peers[i].CreatedByName = name
		}
	}
}

func (h *PeerHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

func (h *PeerHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                string `json:"name"`
		AllowedIPs          string `json:"allowed_ips"`
		DNS                 string `json:"dns"`
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

	// Allocate IP — must use ListPeers (all) to avoid IP collisions
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
		allowedIPs = serverCfg.DefaultAllowedIPs
	}
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}

	dns := req.DNS
	if dns == "" {
		dns = serverCfg.DefaultDNS
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
		PrivateKey:          keyPair.PrivateKey,
		PublicKey:           keyPair.PublicKey,
		PresharedKey:        psk,
		AllowedIPs:          allowedIPs,
		Address:             address,
		DNS:                 dns,
		PersistentKeepalive: keepalive,
		Enabled:             true,
		CreatedBy:           createdBy,
	}

	if err := h.store.CreatePeer(r.Context(), peer); err != nil {
		slog.Error("create peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to create peer")
		return
	}

	slog.Warn("audit", "action", "peer_created", "actor", actorFromRequest(r), "target_id", peer.ID, "target_name", peer.Name, "address", peer.Address)

	// Add to WireGuard interface
	if err := h.wg.AddPeer(peer); err != nil {
		slog.Error("add peer to wg", "error", err)
		// Peer is saved in DB but not active — non-fatal
	}

	h.reloadACL(r)
	writeJSON(w, http.StatusCreated, peer)
}

func (h *PeerHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
		return
	}

	var req struct {
		Name                string `json:"name"`
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

	slog.Warn("audit", "action", "peer_updated", "actor", actorFromRequest(r), "target_id", peer.ID, "target_name", peer.Name)

	writeJSON(w, http.StatusOK, peer)
}

func (h *PeerHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
		return
	}

	// Remove from WireGuard
	if err := h.wg.RemovePeer(peer.PublicKey); err != nil {
		slog.Error("remove peer from wg", "error", err)
	}

	if err := h.store.DeletePeer(r.Context(), peer.ID); err != nil {
		slog.Error("delete peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to delete peer")
		return
	}

	slog.Warn("audit", "action", "peer_deleted", "actor", actorFromRequest(r), "target_id", peer.ID, "target_name", peer.Name)

	h.reloadACL(r)
	writeJSON(w, http.StatusOK, map[string]string{"message": "peer deleted"})
}

func (h *PeerHandler) HandleToggle(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
		return
	}

	peer.Enabled = !peer.Enabled
	if err := h.store.UpdatePeer(r.Context(), peer); err != nil {
		slog.Error("toggle peer", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to toggle peer")
		return
	}

	slog.Warn("audit", "action", "peer_toggled", "actor", actorFromRequest(r), "target_id", peer.ID, "target_name", peer.Name, "enabled", peer.Enabled)

	if peer.Enabled {
		h.wg.AddPeer(peer)
	} else {
		h.wg.RemovePeer(peer.PublicKey)
	}

	h.reloadACL(r)
	writeJSON(w, http.StatusOK, peer)
}

func (h *PeerHandler) reloadACL(r *http.Request) {
	if h.engine != nil {
		if err := h.engine.Reload(r.Context(), h.store); err != nil {
			slog.Error("acl reload failed", "error", err)
		}
	}
}
