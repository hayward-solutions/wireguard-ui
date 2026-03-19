package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type ExportHandler struct {
	store database.Store
}

func NewExportHandler(store database.Store) *ExportHandler {
	return &ExportHandler{store: store}
}

// HandleConfig godoc
// @Summary Export peer config
// @Description Returns the WireGuard configuration file for a peer.
// @Tags peers
// @Produce text/plain
// @Security BearerAuth
// @Param id path string true "Peer ID"
// @Success 200 {string} string "WireGuard configuration file"
// @Failure 400 {object} Response{error=APIError}
// @Failure 401 {object} Response{error=APIError}
// @Failure 404 {object} Response{error=APIError}
// @Failure 500 {object} Response{error=APIError}
// @Router /api/v1/peers/{id}/config [get]
func (h *ExportHandler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
		return
	}

	if peer.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, "CLIENT_KEY", "config export unavailable: this peer's private key was generated client-side and is not stored on the server")
		return
	}

	server, err := h.store.GetServerConfig(r.Context())
	if err != nil || server == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "server not configured")
		return
	}

	conf, err := wireguard.RenderPeerConfig(peer, server)
	if err != nil {
		slog.Error("render peer config", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to render config")
		return
	}

	slog.Warn("audit", "action", "peer_config_exported", "actor", actorFromRequest(r), "target_id", peer.ID, "target_name", peer.Name)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, peer.Name))
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(conf))
}

// HandleQRCode godoc
// @Summary Export peer QR code
// @Description Returns a QR code image of the peer's WireGuard configuration.
// @Tags peers
// @Produce image/png
// @Security BearerAuth
// @Param id path string true "Peer ID"
// @Success 200 {file} binary "QR code PNG image"
// @Failure 400 {object} Response{error=APIError}
// @Failure 401 {object} Response{error=APIError}
// @Failure 404 {object} Response{error=APIError}
// @Failure 500 {object} Response{error=APIError}
// @Router /api/v1/peers/{id}/qrcode [get]
func (h *ExportHandler) HandleQRCode(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
		return
	}

	if peer.PrivateKey == "" {
		writeError(w, http.StatusBadRequest, "CLIENT_KEY", "QR export unavailable: this peer's private key was generated client-side and is not stored on the server")
		return
	}

	server, err := h.store.GetServerConfig(r.Context())
	if err != nil || server == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "server not configured")
		return
	}

	conf, err := wireguard.RenderPeerConfig(peer, server)
	if err != nil {
		slog.Error("render peer config for qr", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to render config")
		return
	}

	png, err := wireguard.GenerateQRCode(conf, 512)
	if err != nil {
		slog.Error("generate qr code", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL", "failed to generate QR code")
		return
	}

	slog.Warn("audit", "action", "peer_qrcode_exported", "actor", actorFromRequest(r), "target_id", peer.ID, "target_name", peer.Name)

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}
