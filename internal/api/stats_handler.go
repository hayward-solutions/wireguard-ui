package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/auth"
	"github.com/hayward-solutions/wireguard-ui/internal/database"
	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/monitor"
)

type StatsHandler struct {
	mon   *monitor.Monitor
	store database.Store
}

func NewStatsHandler(mon *monitor.Monitor, store database.Store) *StatsHandler {
	return &StatsHandler{mon: mon, store: store}
}

func (h *StatsHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	stats := h.mon.GetStats()
	stats = h.filterStats(r, stats)
	writeJSON(w, http.StatusOK, stats)
}

func (h *StatsHandler) HandleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "streaming not supported")
		return
	}

	// Disable the global WriteTimeout for this long-lived SSE connection.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		slog.Error("failed to clear write deadline for SSE", "error", err)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(h.mon.Interval())
	defer ticker.Stop()

	// Send initial stats immediately
	h.sendStats(w, flusher, r)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			h.sendStats(w, flusher, r)
		}
	}
}

func (h *StatsHandler) filterStats(r *http.Request, stats []domain.PeerStats) []domain.PeerStats {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role == domain.RoleAdmin {
		return stats
	}

	peers, err := h.store.ListPeersByUser(r.Context(), claims.Subject)
	if err != nil {
		slog.Error("list peers for stats filtering", "error", err)
		return []domain.PeerStats{}
	}

	owned := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		owned[p.PublicKey] = struct{}{}
	}

	filtered := make([]domain.PeerStats, 0, len(peers))
	for _, s := range stats {
		if _, ok := owned[s.PublicKey]; ok {
			s.Endpoint = ""
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func (h *StatsHandler) sendStats(w http.ResponseWriter, flusher http.Flusher, r *http.Request) {
	stats := h.mon.GetStats()
	stats = h.filterStats(r, stats)
	data, err := json.Marshal(stats)
	if err != nil {
		slog.Error("marshal stats for sse", "error", err)
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}
