package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
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
	id := chi.URLParam(r, "id")

	peer, err := h.store.GetPeer(r.Context(), id)
	if err != nil || peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
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
	id := chi.URLParam(r, "id")

	peer, err := h.store.GetPeer(r.Context(), id)
	if err != nil || peer == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "peer not found")
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
