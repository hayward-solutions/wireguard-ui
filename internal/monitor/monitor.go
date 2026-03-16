package monitor

import (
	"log/slog"
	"sync"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"github.com/hayward-solutions/wireguard-ui/internal/wireguard"
)

type Monitor struct {
	wg       wireguard.Manager
	interval time.Duration
	stats    []domain.PeerStats
	mu       sync.RWMutex
	stopCh   chan struct{}
}

func New(wg wireguard.Manager, interval time.Duration) *Monitor {
	return &Monitor{
		wg:       wg,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start begins periodic stats collection in the background.
func (m *Monitor) Start() {
	go m.run()
}

func (m *Monitor) run() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	// Collect immediately on start
	m.collect()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.collect()
		}
	}
}

func (m *Monitor) collect() {
	stats, err := m.wg.GetStats()
	if err != nil {
		slog.Error("collect stats", "error", err)
		return
	}

	// Mark peers as connected if last handshake was within 3 minutes
	cutoff := time.Now().Add(-3 * time.Minute)
	for i := range stats {
		stats[i].Connected = !stats[i].LastHandshake.IsZero() && stats[i].LastHandshake.After(cutoff)
	}

	m.mu.Lock()
	m.stats = stats
	m.mu.Unlock()
}

// GetStats returns the most recently collected peer stats.
func (m *Monitor) GetStats() []domain.PeerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.stats == nil {
		return []domain.PeerStats{}
	}
	result := make([]domain.PeerStats, len(m.stats))
	copy(result, m.stats)
	return result
}

// Interval returns the collection interval.
func (m *Monitor) Interval() time.Duration {
	return m.interval
}

// Stop halts the background stats collection.
func (m *Monitor) Stop() {
	close(m.stopCh)
}
