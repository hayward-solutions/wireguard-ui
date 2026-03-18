package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TunnelDialer provides a way to dial through a tunnel's network stack.
type TunnelDialer interface {
	// TunnelID returns the unique identifier for this tunnel.
	TunnelID() string
	// Subnets returns the CIDRs this tunnel routes.
	Subnets() []netip.Prefix
	// DialTCP dials a TCP connection through the tunnel.
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	// DialUDP dials a UDP connection through the tunnel.
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

// tunnelDialerRegistry manages a set of tunnel dialers for the netstack forwarder.
type tunnelDialerRegistry struct {
	mu      sync.RWMutex
	dialers []TunnelDialer
}

func (r *tunnelDialerRegistry) register(td TunnelDialer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dialers = append(r.dialers, td)
}

func (r *tunnelDialerRegistry) unregister(tunnelID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, td := range r.dialers {
		if td.TunnelID() == tunnelID {
			r.dialers = append(r.dialers[:i], r.dialers[i+1:]...)
			return
		}
	}
}

// find returns the TunnelDialer that routes the given destination IP, or nil.
func (r *tunnelDialerRegistry) find(dstIP netip.Addr) TunnelDialer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, td := range r.dialers {
		for _, subnet := range td.Subnets() {
			if subnet.Contains(dstIP) {
				return td
			}
		}
	}
	return nil
}

// netstackTunnelDialer implements TunnelDialer using a tunnel's gVisor network stack.
type netstackTunnelDialer struct {
	id      string
	gvStack *stack.Stack
	subnets []netip.Prefix
}

// newNetstackTunnelDialer creates a TunnelDialer for a netstack-based tunnel.
func newNetstackTunnelDialer(tunnelID string, nm *NetstackManager, peerAllowedIPs string) *netstackTunnelDialer {
	var subnets []netip.Prefix
	for _, s := range strings.Split(peerAllowedIPs, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		subnets = append(subnets, prefix)
	}
	return &netstackTunnelDialer{
		id:      tunnelID,
		gvStack: nm.gvStack,
		subnets: subnets,
	}
}

func (d *netstackTunnelDialer) TunnelID() string      { return d.id }
func (d *netstackTunnelDialer) Subnets() []netip.Prefix { return d.subnets }

func (d *netstackTunnelDialer) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse addr %q: %w", addr, err)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("parse IP %q: %w", host, err)
	}

	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("parse port %q: %w", port, err)
	}

	fullAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(portNum),
	}

	conn, err := gonet.DialTCPWithBind(ctx, d.gvStack, tcpip.FullAddress{NIC: 1}, fullAddr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("dial tcp through tunnel %s: %w", d.id, err)
	}
	return conn, nil
}

func (d *netstackTunnelDialer) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse addr %q: %w", addr, err)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("parse IP %q: %w", host, err)
	}

	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, fmt.Errorf("parse port %q: %w", port, err)
	}

	fullAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(ip.AsSlice()),
		Port: uint16(portNum),
	}

	conn, err := gonet.DialUDP(d.gvStack, nil, &fullAddr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("dial udp through tunnel %s: %w", d.id, err)
	}
	return conn, nil
}
