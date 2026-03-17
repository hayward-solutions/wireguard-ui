package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WgctrlManager manages a kernel WireGuard interface via wgctrl and ip commands.
type WgctrlManager struct {
	interfaceName      string
	client             *wgctrl.Client
	postDown           string
	allowCustomScripts bool
	firewallConfig     *domain.FirewallConfig
	serverAddress      string
}

func NewWgctrlManager(interfaceName string) (*WgctrlManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl client: %w", err)
	}
	return &WgctrlManager{
		interfaceName: interfaceName,
		client:        client,
	}, nil
}

func (m *WgctrlManager) Start(cfg *domain.ServerConfig) error {
	m.postDown = cfg.PostDown
	m.allowCustomScripts = cfg.AllowCustomScripts
	m.firewallConfig = cfg.FirewallConfig
	m.serverAddress = cfg.Address

	// Create interface if it doesn't exist
	if err := m.ensureInterface(); err != nil {
		return fmt.Errorf("ensure interface: %w", err)
	}

	// Configure private key and listen port
	key, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	port := cfg.ListenPort
	err = m.client.ConfigureDevice(m.interfaceName, wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &port,
		ReplacePeers: true,
	})
	if err != nil {
		return fmt.Errorf("configure device: %w", err)
	}

	// Set IP address on interface
	if err := m.setAddress(cfg.Address); err != nil {
		return fmt.Errorf("set address: %w", err)
	}

	// Bring interface up
	if err := m.linkUp(); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	// Apply structured firewall rules (no shell execution)
	if err := ApplyFirewallRules(cfg.FirewallConfig, cfg.Address, m.interfaceName); err != nil {
		slog.Warn("failed to apply firewall rules", "error", err)
	}

	// Run PostUp custom script (if allowed)
	if cfg.PostUp != "" {
		if err := RunScriptIfAllowed(cfg.PostUp, "post_up", cfg.AllowCustomScripts); err != nil {
			slog.Warn("post-up script failed", "error", err)
		}
	}

	slog.Info("wireguard interface started",
		"name", m.interfaceName,
		"address", cfg.Address,
		"port", cfg.ListenPort)
	return nil
}

func (m *WgctrlManager) AddPeer(p *domain.Peer) error {
	pubKey, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: parseAllowedIPs(p.Address), // Server-side: route peer's IP to this peer
	}

	if p.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return fmt.Errorf("parse preshared key: %w", err)
		}
		peerCfg.PresharedKey = &psk
	}

	if p.PersistentKeepalive > 0 {
		keepalive := time.Duration(p.PersistentKeepalive) * time.Second
		peerCfg.PersistentKeepaliveInterval = &keepalive
	}

	err = m.client.ConfigureDevice(m.interfaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	})
	if err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	slog.Info("wireguard: peer added", "name", p.Name, "public_key", p.PublicKey)
	return nil
}

func (m *WgctrlManager) RemovePeer(publicKey string) error {
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	err = m.client.ConfigureDevice(m.interfaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: pubKey,
				Remove:    true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	slog.Info("wireguard: peer removed", "public_key", publicKey)
	return nil
}

func (m *WgctrlManager) GetStats() ([]domain.PeerStats, error) {
	dev, err := m.client.Device(m.interfaceName)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	stats := make([]domain.PeerStats, 0, len(dev.Peers))
	for _, peer := range dev.Peers {
		endpoint := ""
		if peer.Endpoint != nil {
			endpoint = peer.Endpoint.String()
		}

		stats = append(stats, domain.PeerStats{
			PublicKey:     peer.PublicKey.String(),
			Endpoint:      endpoint,
			LastHandshake: peer.LastHandshakeTime,
			TransferRx:    peer.ReceiveBytes,
			TransferTx:    peer.TransmitBytes,
			Connected:     time.Since(peer.LastHandshakeTime) < 3*time.Minute,
		})
	}

	return stats, nil
}

func (m *WgctrlManager) Close() error {
	// Run PostDown custom script (if allowed)
	if m.postDown != "" {
		if err := RunScriptIfAllowed(m.postDown, "post_down", m.allowCustomScripts); err != nil {
			slog.Warn("post-down script failed", "error", err)
		}
	}

	// Remove structured firewall rules
	if err := RemoveFirewallRules(m.firewallConfig, m.serverAddress, m.interfaceName); err != nil {
		slog.Warn("failed to remove firewall rules", "error", err)
	}

	// Delete the interface
	if err := exec.Command("ip", "link", "del", m.interfaceName).Run(); err != nil {
		slog.Warn("failed to delete interface", "name", m.interfaceName, "error", err)
	}

	return m.client.Close()
}

// ensureInterface creates the WireGuard interface if it doesn't already exist.
func (m *WgctrlManager) ensureInterface() error {
	// Check if interface exists
	if _, err := m.client.Device(m.interfaceName); err == nil {
		slog.Info("wireguard interface already exists, reconfiguring", "name", m.interfaceName)
		return nil
	}

	// Create kernel WireGuard interface
	out, err := exec.Command("ip", "link", "add", m.interfaceName, "type", "wireguard").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link add: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// setAddress flushes existing addresses and sets the given CIDR address on the interface.
func (m *WgctrlManager) setAddress(address string) error {
	// Flush existing addresses
	exec.Command("ip", "addr", "flush", "dev", m.interfaceName).Run()

	out, err := exec.Command("ip", "addr", "add", address, "dev", m.interfaceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr add: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// linkUp brings the interface up.
func (m *WgctrlManager) linkUp() error {
	out, err := exec.Command("ip", "link", "set", m.interfaceName, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set up: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// parseAllowedIPs parses a comma-separated list of CIDRs into []net.IPNet.
func parseAllowedIPs(cidrList string) []net.IPNet {
	var nets []net.IPNet
	for _, cidr := range strings.Split(cidrList, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("failed to parse CIDR", "cidr", cidr, "error", err)
			continue
		}
		nets = append(nets, *ipNet)
	}
	return nets
}

var _ Manager = (*WgctrlManager)(nil)
