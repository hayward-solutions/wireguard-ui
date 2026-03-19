package monitor

import (
	"testing"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// mockManager implements wireguard.Manager for testing.
type mockManager struct {
	stats []domain.PeerStats
	err   error
}

func (m *mockManager) Start(_ *domain.ServerConfig) error          { return nil }
func (m *mockManager) AddPeer(_ *domain.Peer) error                { return nil }
func (m *mockManager) RemovePeer(_ string) error                   { return nil }
func (m *mockManager) GetStats() ([]domain.PeerStats, error)       { return m.stats, m.err }
func (m *mockManager) Close() error                                { return nil }

func TestNew(t *testing.T) {
	mgr := &mockManager{}
	mon := New(mgr, 5*time.Second)
	if mon == nil {
		t.Fatal("New returned nil")
	}
	if mon.Interval() != 5*time.Second {
		t.Errorf("Interval() = %v, want 5s", mon.Interval())
	}
}

func TestGetStats_BeforeStart(t *testing.T) {
	mgr := &mockManager{}
	mon := New(mgr, time.Hour)
	stats := mon.GetStats()
	if len(stats) != 0 {
		t.Errorf("GetStats before Start: got %d stats, want 0", len(stats))
	}
}

func TestMonitor_CollectsStats(t *testing.T) {
	now := time.Now()
	mgr := &mockManager{
		stats: []domain.PeerStats{
			{PublicKey: "key-1", LastHandshake: now.Add(-1 * time.Minute)},  // connected (within 3 min)
			{PublicKey: "key-2", LastHandshake: now.Add(-5 * time.Minute)},  // disconnected (> 3 min)
			{PublicKey: "key-3"},                                             // disconnected (zero time)
		},
	}
	mon := New(mgr, 50*time.Millisecond)
	mon.Start()
	defer mon.Stop()

	// Wait for at least one collection cycle
	time.Sleep(100 * time.Millisecond)

	stats := mon.GetStats()
	if len(stats) != 3 {
		t.Fatalf("got %d stats, want 3", len(stats))
	}

	if !stats[0].Connected {
		t.Error("key-1 should be connected (handshake within 3 min)")
	}
	if stats[1].Connected {
		t.Error("key-2 should be disconnected (handshake > 3 min ago)")
	}
	if stats[2].Connected {
		t.Error("key-3 should be disconnected (zero handshake)")
	}
}

func TestMonitor_Stop(t *testing.T) {
	mgr := &mockManager{stats: []domain.PeerStats{{PublicKey: "key-1"}}}
	mon := New(mgr, 50*time.Millisecond)
	mon.Start()
	time.Sleep(100 * time.Millisecond)
	mon.Stop()

	// After stop, GetStats should still return last collected data
	stats := mon.GetStats()
	if len(stats) != 1 {
		t.Errorf("got %d stats after stop, want 1", len(stats))
	}
}

func TestMonitor_GetStatsReturnsCopy(t *testing.T) {
	mgr := &mockManager{stats: []domain.PeerStats{{PublicKey: "key-1", TransferRx: 100}}}
	mon := New(mgr, 50*time.Millisecond)
	mon.Start()
	defer mon.Stop()

	time.Sleep(100 * time.Millisecond)

	stats1 := mon.GetStats()
	stats1[0].TransferRx = 999

	stats2 := mon.GetStats()
	if stats2[0].TransferRx != 100 {
		t.Errorf("GetStats did not return a copy: got TransferRx=%d, want 100", stats2[0].TransferRx)
	}
}
