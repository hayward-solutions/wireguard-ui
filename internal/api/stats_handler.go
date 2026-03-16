package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/monitor"
)

type StatsHandler struct {
	mon *monitor.Monitor
}

func NewStatsHandler(mon *monitor.Monitor) *StatsHandler {
	return &StatsHandler{mon: mon}
}

func (h *StatsHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	stats := h.mon.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

func (h *StatsHandler) HandleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(h.mon.Interval())
	defer ticker.Stop()

	// Send initial stats immediately
	h.sendStats(w, flusher)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			h.sendStats(w, flusher)
		}
	}
}

func (h *StatsHandler) sendStats(w http.ResponseWriter, flusher http.Flusher) {
	stats := h.mon.GetStats()
	data, err := json.Marshal(stats)
	if err != nil {
		slog.Error("marshal stats for sse", "error", err)
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}
