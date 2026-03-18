package wireguard

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
)

// TunnelMode specifies how tunnel WireGuard interfaces are created.
type TunnelMode string

const (
	TunnelModeNetstack  TunnelMode = "netstack"
	TunnelModeUserspace TunnelMode = "userspace"
	TunnelModeKernel    TunnelMode = "kernel"
	TunnelModeMock      TunnelMode = "mock"
)

// tunnelInstance tracks a running tunnel's WireGuard interface.
type tunnelInstance struct {
	tunnel        *domain.Tunnel
	manager       Manager
	interfaceName string // kernel interface name (userspace/kernel modes only)
}

// TunnelManager manages per-tunnel WireGuard interfaces.
// Each tunnel gets its own WireGuard interface (netstack, userspace, or kernel).
type TunnelManager struct {
	mode              TunnelMode
	mainInterfaceName string // main wg0 interface name, for iptables/ip route (userspace/kernel)
	mainNetstack      *NetstackManager // reference to main netstack manager (netstack mode only)
	mu                sync.Mutex
	tunnels           map[string]*tunnelInstance // tunnel ID -> running instance
}

// NewTunnelManager creates a new TunnelManager for the given mode.
// mainIfaceName is the main WireGuard interface name (e.g. "wg0") used for
// routing rules in userspace/kernel modes.
func NewTunnelManager(mode TunnelMode, mainIfaceName string) *TunnelManager {
	return &TunnelManager{
		mode:              mode,
		mainInterfaceName: mainIfaceName,
		tunnels:           make(map[string]*tunnelInstance),
	}
}

// SetMainNetstackManager provides a reference to the main NetstackManager.
// In netstack mode, this is used to register tunnel dialers on the main forwarder
// so traffic matching tunnel subnets is routed through the tunnel's gVisor stack.
func (tm *TunnelManager) SetMainNetstackManager(nm *NetstackManager) {
	tm.mainNetstack = nm
}

// StartTunnel creates a WireGuard interface for the tunnel and configures the remote peer.
func (tm *TunnelManager) StartTunnel(t *domain.Tunnel) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.tunnels[t.ID]; exists {
		return fmt.Errorf("tunnel %s is already running", t.Name)
	}

	if t.PrivateKey == "" || t.PublicKey == "" {
		return fmt.Errorf("tunnel %s has no keypair", t.Name)
	}

	mgr, ifName, err := tm.createManager(t)
	if err != nil {
		return fmt.Errorf("create manager for tunnel %s: %w", t.Name, err)
	}

	// Convert tunnel to a ServerConfig for the WireGuard interface
	serverCfg := tunnelToServerConfig(t)

	if err := mgr.Start(serverCfg); err != nil {
		return fmt.Errorf("start tunnel %s: %w", t.Name, err)
	}

	// Add the remote peer
	peer := tunnelToRemotePeer(t)
	if err := mgr.AddPeer(peer); err != nil {
		mgr.Close()
		return fmt.Errorf("add remote peer for tunnel %s: %w", t.Name, err)
	}

	inst := &tunnelInstance{
		tunnel:        t,
		manager:       mgr,
		interfaceName: ifName,
	}
	tm.tunnels[t.ID] = inst

	// Set up routing from the main interface to this tunnel
	tm.applyRouting(t, inst)

	slog.Info("tunnel started", "name", t.Name, "id", t.ID, "mode", tm.mode, "iface", ifName)
	return nil
}

// StopTunnel shuts down the WireGuard interface for a tunnel.
func (tm *TunnelManager) StopTunnel(id string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	inst, ok := tm.tunnels[id]
	if !ok {
		return nil // not running
	}

	// Remove routing before stopping the interface
	tm.removeRouting(inst.tunnel, inst)

	if err := inst.manager.Close(); err != nil {
		slog.Error("failed to close tunnel", "id", id, "error", err)
	}

	delete(tm.tunnels, id)
	slog.Info("tunnel stopped", "name", inst.tunnel.Name, "id", id)
	return nil
}

// RestartTunnel stops and re-starts a tunnel with updated configuration.
func (tm *TunnelManager) RestartTunnel(t *domain.Tunnel) error {
	if err := tm.StopTunnel(t.ID); err != nil {
		return err
	}
	return tm.StartTunnel(t)
}

// GetTunnelStatus returns the connection status for a specific tunnel.
func (tm *TunnelManager) GetTunnelStatus(id string) (*domain.TunnelStatus, error) {
	tm.mu.Lock()
	inst, ok := tm.tunnels[id]
	tm.mu.Unlock()

	status := &domain.TunnelStatus{TunnelID: id}
	if !ok {
		return status, nil
	}

	stats, err := inst.manager.GetStats()
	if err != nil {
		return status, fmt.Errorf("get stats for tunnel %s: %w", id, err)
	}

	if len(stats) > 0 {
		s := stats[0] // single peer per tunnel
		status.Connected = s.Connected
		status.LastHandshake = s.LastHandshake
		status.TransferRx = s.TransferRx
		status.TransferTx = s.TransferTx
		status.Endpoint = s.Endpoint
	}

	return status, nil
}

// GetAllTunnelStatuses returns status for all running tunnels.
func (tm *TunnelManager) GetAllTunnelStatuses() map[string]*domain.TunnelStatus {
	tm.mu.Lock()
	ids := make([]string, 0, len(tm.tunnels))
	for id := range tm.tunnels {
		ids = append(ids, id)
	}
	tm.mu.Unlock()

	statuses := make(map[string]*domain.TunnelStatus, len(ids))
	for _, id := range ids {
		status, err := tm.GetTunnelStatus(id)
		if err != nil {
			slog.Error("failed to get tunnel status", "id", id, "error", err)
			statuses[id] = &domain.TunnelStatus{TunnelID: id}
			continue
		}
		statuses[id] = status
	}
	return statuses
}

// IsRunning returns whether a tunnel is currently active.
func (tm *TunnelManager) IsRunning(id string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	_, ok := tm.tunnels[id]
	return ok
}

// Close shuts down all running tunnel interfaces.
func (tm *TunnelManager) Close() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for id, inst := range tm.tunnels {
		tm.removeRouting(inst.tunnel, inst)
		if err := inst.manager.Close(); err != nil {
			slog.Error("failed to close tunnel", "id", id, "error", err)
		}
	}
	tm.tunnels = make(map[string]*tunnelInstance)
	return nil
}

// createManager creates a WireGuard Manager for a tunnel based on the configured mode.
// Returns the manager and the kernel interface name (empty for netstack/mock).
func (tm *TunnelManager) createManager(t *domain.Tunnel) (Manager, string, error) {
	switch tm.mode {
	case TunnelModeNetstack:
		return NewNetstackManager(), "", nil
	case TunnelModeUserspace:
		ifName := tunnelInterfaceName(t.ID)
		mgr, err := NewUserspaceManager(ifName)
		return mgr, ifName, err
	case TunnelModeKernel:
		ifName := tunnelInterfaceName(t.ID)
		mgr, err := NewWgctrlManager(ifName)
		return mgr, ifName, err
	case TunnelModeMock:
		return NewMockManager(), "", nil
	default:
		return nil, "", fmt.Errorf("unsupported tunnel mode: %s", tm.mode)
	}
}

// applyRouting sets up traffic routing from the main interface to this tunnel.
func (tm *TunnelManager) applyRouting(t *domain.Tunnel, inst *tunnelInstance) {
	if t.PeerAllowedIPs == "" {
		return
	}
	subnets := splitSubnets(t.PeerAllowedIPs)

	switch tm.mode {
	case TunnelModeUserspace, TunnelModeKernel:
		if inst.interfaceName != "" && tm.mainInterfaceName != "" {
			if err := ApplyTunnelRoutes(tm.mainInterfaceName, inst.interfaceName, subnets); err != nil {
				slog.Error("failed to apply tunnel routes", "tunnel", t.Name, "error", err)
			}
		}
	case TunnelModeNetstack:
		if tm.mainNetstack != nil {
			nm, ok := inst.manager.(*NetstackManager)
			if ok {
				dialer := newNetstackTunnelDialer(t.ID, nm, t.PeerAllowedIPs)
				tm.mainNetstack.RegisterTunnelDialer(dialer)
			}
		}
	}
}

// removeRouting tears down traffic routing for a tunnel.
func (tm *TunnelManager) removeRouting(t *domain.Tunnel, inst *tunnelInstance) {
	if t.PeerAllowedIPs == "" {
		return
	}
	subnets := splitSubnets(t.PeerAllowedIPs)

	switch tm.mode {
	case TunnelModeUserspace, TunnelModeKernel:
		if inst.interfaceName != "" && tm.mainInterfaceName != "" {
			if err := RemoveTunnelRoutes(tm.mainInterfaceName, inst.interfaceName, subnets); err != nil {
				slog.Error("failed to remove tunnel routes", "tunnel", t.Name, "error", err)
			}
		}
	case TunnelModeNetstack:
		if tm.mainNetstack != nil {
			tm.mainNetstack.UnregisterTunnelDialer(t.ID)
		}
	}
}

// splitSubnets splits a comma-separated list of CIDRs.
func splitSubnets(allowedIPs string) []string {
	var result []string
	for _, s := range strings.Split(allowedIPs, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// tunnelInterfaceName generates a unique interface name for a tunnel.
func tunnelInterfaceName(tunnelID string) string {
	// Use first 8 chars of UUID for a short but unique name
	short := tunnelID
	if len(short) > 8 {
		short = short[:8]
	}
	return "wgt-" + short
}

// tunnelToServerConfig converts a Tunnel into a ServerConfig for the WireGuard interface.
func tunnelToServerConfig(t *domain.Tunnel) *domain.ServerConfig {
	mtu := t.MTU
	if mtu == 0 {
		mtu = 1420
	}
	return &domain.ServerConfig{
		ID:         t.ID,
		PrivateKey: t.PrivateKey,
		PublicKey:  t.PublicKey,
		ListenPort: t.ListenPort,
		Address:    t.Address,
		DNS:        t.DNS,
		MTU:        mtu,
	}
}

// tunnelToRemotePeer converts a Tunnel's remote peer config into a Peer for AddPeer.
func tunnelToRemotePeer(t *domain.Tunnel) *domain.Peer {
	keepalive := t.PersistentKeepalive
	if keepalive == 0 {
		keepalive = 25
	}
	return &domain.Peer{
		ID:                  "tunnel-peer-" + t.ID,
		Name:                t.Name + " (remote)",
		PublicKey:           t.PeerPublicKey,
		PresharedKey:        t.PresharedKey,
		Address:             t.PeerAllowedIPs, // AllowedIPs for this peer on the interface
		Endpoint:            t.PeerEndpoint,   // Remote server endpoint (host:port)
		PersistentKeepalive: keepalive,
		Enabled:             true,
	}
}
