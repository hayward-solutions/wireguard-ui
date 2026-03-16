package wireguard

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/hayward-solutions/wireguard-ui/internal/domain"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// NetstackManager manages a WireGuard interface using a fully userspace gVisor network stack.
// This requires no NET_ADMIN capabilities or /dev/net/tun, making it suitable for AWS Fargate.
type NetstackManager struct {
	dev       *device.Device
	gvStack   *stack.Stack
	ep        *channel.Endpoint
	forwarder *netstackForwarder
}

func NewNetstackManager() *NetstackManager {
	return &NetstackManager{}
}

func (m *NetstackManager) Start(cfg *domain.ServerConfig) error {
	// Parse server address (e.g., "10.0.0.1/24") into netip.Addr
	prefix, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("parse server address %q: %w", cfg.Address, err)
	}
	localAddr := prefix.Addr()

	// Parse DNS servers
	var dnsAddrs []netip.Addr
	for _, s := range strings.Split(cfg.DNS, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			slog.Warn("netstack: skipping invalid DNS server", "dns", s, "error", err)
			continue
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	// Create gVisor network stack (replicating CreateNetTUN logic to retain stack reference)
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	m.gvStack = stack.New(opts)
	m.ep = channel.New(1024, uint32(cfg.MTU), "")

	// Enable TCP SACK
	sackOpt := tcpip.TCPSACKEnabled(true)
	if tcpipErr := m.gvStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); tcpipErr != nil {
		return fmt.Errorf("enable TCP SACK: %v", tcpipErr)
	}

	// Create NIC
	if tcpipErr := m.gvStack.CreateNIC(1, m.ep); tcpipErr != nil {
		return fmt.Errorf("create NIC: %v", tcpipErr)
	}

	// Add local address
	var protoNum tcpip.NetworkProtocolNumber
	if localAddr.Is4() {
		protoNum = ipv4.ProtocolNumber
	} else {
		protoNum = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          protoNum,
		AddressWithPrefix: tcpip.AddrFromSlice(localAddr.AsSlice()).WithPrefix(),
	}
	if tcpipErr := m.gvStack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		return fmt.Errorf("add address %v: %v", localAddr, tcpipErr)
	}

	// Add default routes
	if localAddr.Is4() {
		m.gvStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if localAddr.Is6() {
		m.gvStack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	// Register TCP/UDP forwarders before creating the WireGuard device.
	// Pass the local VPN address so traffic to our own IP is rewritten to 127.0.0.1.
	m.forwarder = startForwarder(m.gvStack, localAddr.String())

	// Create the netTun-compatible tun.Device backed by the channel endpoint
	tunDev := &netstackTun{
		ep:             m.ep,
		stack:          m.gvStack,
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            cfg.MTU,
	}
	tunDev.notifyHandle = m.ep.AddNotify(tunDev)
	tunDev.events <- tun.EventUp

	// Create wireguard-go device
	logger := device.NewLogger(device.LogLevelSilent, "(netstack) ")
	m.dev = device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	// Configure via IPC
	ipcConf, err := buildIpcConfig(cfg)
	if err != nil {
		m.dev.Close()
		return fmt.Errorf("build ipc config: %w", err)
	}
	if err := m.dev.IpcSet(ipcConf); err != nil {
		m.dev.Close()
		return fmt.Errorf("ipc set config: %w", err)
	}

	// Bring device up
	m.dev.Up()

	if cfg.PostUp != "" {
		slog.Warn("netstack: PostUp scripts are not supported in netstack mode (no kernel interface)")
	}

	slog.Info("wireguard netstack interface started",
		"address", cfg.Address,
		"port", cfg.ListenPort,
		"dns", dnsAddrs)
	return nil
}

func (m *NetstackManager) AddPeer(p *domain.Peer) error {
	if m.dev == nil {
		return fmt.Errorf("wireguard interface not started")
	}
	ipcPeer, err := buildIpcPeer(p)
	if err != nil {
		return fmt.Errorf("build ipc peer: %w", err)
	}
	if err := m.dev.IpcSet(ipcPeer); err != nil {
		return fmt.Errorf("ipc set peer: %w", err)
	}
	slog.Info("wireguard netstack: peer added", "name", p.Name, "public_key", p.PublicKey)
	return nil
}

func (m *NetstackManager) RemovePeer(publicKey string) error {
	if m.dev == nil {
		return fmt.Errorf("wireguard interface not started")
	}
	ipcRemove, err := buildIpcRemovePeer(publicKey)
	if err != nil {
		return fmt.Errorf("build ipc remove peer: %w", err)
	}
	if err := m.dev.IpcSet(ipcRemove); err != nil {
		return fmt.Errorf("ipc remove peer: %w", err)
	}
	slog.Info("wireguard netstack: peer removed", "public_key", publicKey)
	return nil
}

func (m *NetstackManager) GetStats() ([]domain.PeerStats, error) {
	if m.dev == nil {
		return []domain.PeerStats{}, nil
	}
	ipcOutput, err := m.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("ipc get: %w", err)
	}
	return parseIpcStats(ipcOutput)
}

func (m *NetstackManager) Close() error {
	if m.forwarder != nil {
		m.forwarder.stop()
	}
	if m.dev != nil {
		m.dev.Close()
	}
	return nil
}

var _ Manager = (*NetstackManager)(nil)
