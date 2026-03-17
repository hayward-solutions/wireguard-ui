package wireguard

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// UserspaceManager manages a userspace WireGuard interface using wireguard-go.
// This enables running WireGuard without a kernel module (e.g., ECS Fargate).
type UserspaceManager struct {
	interfaceName      string
	client             *wgctrl.Client
	device             *device.Device
	uapi               net.Listener
	postDown           string
	allowCustomScripts bool
	firewallConfig     *domain.FirewallConfig
	serverAddress      string
	aclEnforcer        *IptablesACLEnforcer
}

func NewUserspaceManager(interfaceName string) (*UserspaceManager, error) {
	return &UserspaceManager{
		interfaceName: interfaceName,
	}, nil
}

// SetACLEnforcer sets the iptables ACL enforcer for this manager.
func (m *UserspaceManager) SetACLEnforcer(enforcer *IptablesACLEnforcer) {
	m.aclEnforcer = enforcer
}

func (m *UserspaceManager) Start(cfg *domain.ServerConfig) error {
	m.postDown = cfg.PostDown
	m.allowCustomScripts = cfg.AllowCustomScripts
	m.firewallConfig = cfg.FirewallConfig
	m.serverAddress = cfg.Address

	// Create TUN device
	tunDevice, err := tun.CreateTUN(m.interfaceName, cfg.MTU)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}

	// Get the actual interface name (might differ from requested on some platforms)
	actualName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return fmt.Errorf("get tun name: %w", err)
	}
	m.interfaceName = actualName

	// Create wireguard-go device
	logger := device.NewLogger(device.LogLevelSilent, fmt.Sprintf("(%s) ", m.interfaceName))
	m.device = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Set up UAPI socket so wgctrl can configure this device
	uapiFile, err := ipc.UAPIOpen(m.interfaceName)
	if err != nil {
		m.device.Close()
		return fmt.Errorf("uapi open: %w", err)
	}

	uapiListener, err := ipc.UAPIListen(m.interfaceName, uapiFile)
	if err != nil {
		uapiFile.Close()
		m.device.Close()
		return fmt.Errorf("uapi listen: %w", err)
	}
	m.uapi = uapiListener

	// Handle UAPI connections in background
	go func() {
		for {
			c, err := uapiListener.Accept()
			if err != nil {
				return
			}
			go m.device.IpcHandle(c)
		}
	}()

	// Now create the wgctrl client to configure via UAPI
	client, err := wgctrl.New()
	if err != nil {
		m.device.Close()
		uapiListener.Close()
		return fmt.Errorf("wgctrl client: %w", err)
	}
	m.client = client

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

	slog.Info("wireguard userspace interface started",
		"name", m.interfaceName,
		"address", cfg.Address,
		"port", cfg.ListenPort)
	return nil
}

func (m *UserspaceManager) AddPeer(p *domain.Peer) error {
	if m.client == nil {
		return fmt.Errorf("wireguard interface not started")
	}
	pubKey, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: parseAllowedIPs(p.Address),
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

	slog.Info("wireguard userspace: peer added", "name", p.Name, "public_key", p.PublicKey)
	return nil
}

func (m *UserspaceManager) RemovePeer(publicKey string) error {
	if m.client == nil {
		return fmt.Errorf("wireguard interface not started")
	}
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

	slog.Info("wireguard userspace: peer removed", "public_key", publicKey)
	return nil
}

func (m *UserspaceManager) GetStats() ([]domain.PeerStats, error) {
	if m.client == nil {
		return []domain.PeerStats{}, nil
	}
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

func (m *UserspaceManager) Close() error {
	// Clean up ACL iptables rules before removing firewall rules.
	if m.aclEnforcer != nil {
		m.aclEnforcer.Cleanup()
	}

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

	if m.uapi != nil {
		m.uapi.Close()
	}
	if m.device != nil {
		m.device.Close()
	}

	// Clean up interface
	exec.Command("ip", "link", "del", m.interfaceName).Run()

	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

// setAddress sets the IP address on the interface.
func (m *UserspaceManager) setAddress(address string) error {
	exec.Command("ip", "addr", "flush", "dev", m.interfaceName).Run()
	out, err := exec.Command("ip", "addr", "add", address, "dev", m.interfaceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr add: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// linkUp brings the interface up.
func (m *UserspaceManager) linkUp() error {
	out, err := exec.Command("ip", "link", "set", m.interfaceName, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set up: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

var _ Manager = (*UserspaceManager)(nil)
