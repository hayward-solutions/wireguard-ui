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

func (h *ExportHandler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
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

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, peer.Name))
	w.Write([]byte(conf))
}

func (h *ExportHandler) HandleQRCode(w http.ResponseWriter, r *http.Request) {
	peer, _ := requirePeerAccess(h.store, w, r)
	if peer == nil {
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

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}
