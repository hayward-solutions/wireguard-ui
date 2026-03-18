package wireguard

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/hayward-solutions/wireguard-ui/internal/acl"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	udpNATTimeout  = 30 * time.Second
	udpBufSize     = 65535
	tcpDialTimeout = 5 * time.Second
)

// netstackForwarder forwards TCP and UDP traffic from a gVisor stack to the host network.
// If tunnel dialers are registered, traffic matching a tunnel's subnets is routed through
// the tunnel's gVisor stack instead of the host network.
type netstackForwarder struct {
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	localAddr  string             // the server's VPN address (e.g., "10.0.0.1")
	forwardAll bool               // if true, rewrite ALL destinations to 127.0.0.1 (tunnel mode)
	acl        *acl.PolicyEngine  // nil means allow-all (backwards compatible)
	tunnels    tunnelDialerRegistry
}

// startForwarder registers TCP and UDP forwarding handlers on the gVisor stack
// and returns a forwarder that can be stopped.
// localAddr is the server's VPN IP — traffic to this address is rewritten to 127.0.0.1.
// policyEngine is optional — if nil, all traffic is forwarded (no ACL enforcement).
func startForwarder(s *stack.Stack, localAddr string, policyEngine *acl.PolicyEngine) *netstackForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	f := &netstackForwarder{ctx: ctx, cancel: cancel, localAddr: localAddr, acl: policyEngine}

	// TCP forwarder: intercept all incoming TCP connections and proxy to host network.
	tcpFwd := tcp.NewForwarder(s, 0, 65535, func(r *tcp.ForwarderRequest) {
		f.handleTCP(r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP forwarder: intercept all incoming UDP packets and proxy to host network.
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		f.handleUDP(r)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return f
}

func (f *netstackForwarder) stop() {
	f.cancel()
	f.wg.Wait()
}

// resolveHostAddr rewrites the destination address so that traffic destined for the
// server's own VPN IP is sent to 127.0.0.1 instead (the VPN IP only exists in gVisor).
// In forwardAll mode (tunnel interfaces), ALL destinations are rewritten to 127.0.0.1
// because the tunnel's gVisor stack is purely a transport layer — traffic arriving on
// it is destined for services on the local host.
func (f *netstackForwarder) resolveHostAddr(gvisorIP string, port int) string {
	host := gvisorIP
	if f.forwardAll || host == f.localAddr {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (f *netstackForwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

	// ACL check: deny traffic not explicitly allowed
	if f.acl != nil {
		dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
		if ok {
			srcIP := id.RemoteAddress.String()
			if !f.acl.Check(srcIP, "tcp", dstIP, id.LocalPort) {
				slog.Debug("netstack tcp: acl denied", "src", srcIP, "dst_ip", dstIP, "dst_port", id.LocalPort)
				r.Complete(true) // RST
				return
			}
		}
	}

	dstAddr := f.resolveHostAddr(id.LocalAddress.String(), int(id.LocalPort))

	// Check if destination matches a tunnel subnet — if so, route through the tunnel.
	var outConn net.Conn
	dstIP, dstOk := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	td := func() TunnelDialer {
		if dstOk {
			return f.tunnels.find(dstIP)
		}
		return nil
	}()

	if td != nil {
		ctx, cancel := context.WithTimeout(f.ctx, tcpDialTimeout)
		defer cancel()
		var err error
		outConn, err = td.DialTCP(ctx, dstAddr)
		if err != nil {
			slog.Warn("netstack tcp: tunnel dial failed", "dst", dstAddr, "tunnel", td.TunnelID(), "error", err)
			r.Complete(true)
			return
		}
	} else {
		// Dial the real destination on the host network.
		var err error
		outConn, err = net.DialTimeout("tcp", dstAddr, tcpDialTimeout)
		if err != nil {
			slog.Warn("netstack tcp: dial failed", "dst", dstAddr, "error", err)
			r.Complete(true) // send RST
			return
		}
	}

	// Accept on the gVisor side.
	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		slog.Warn("netstack tcp: create endpoint failed", "dst", dstAddr, "error", epErr)
		r.Complete(true)
		outConn.Close()
		return
	}
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		relay(inConn, outConn)
	}()
}

// relay copies data bidirectionally between two connections until one side closes or errors.
func relay(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		close(done)
	}()
	io.Copy(a, b)
	<-done
}

func (f *netstackForwarder) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()

	// ACL check: deny traffic not explicitly allowed
	if f.acl != nil {
		dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
		if ok {
			srcIP := id.RemoteAddress.String()
			if !f.acl.Check(srcIP, "udp", dstIP, id.LocalPort) {
				slog.Debug("netstack udp: acl denied", "src", srcIP, "dst_ip", dstIP, "dst_port", id.LocalPort)
				return
			}
		}
	}

	dstAddr := f.resolveHostAddr(id.LocalAddress.String(), int(id.LocalPort))

	// Create gVisor-side UDP endpoint.
	var wq waiter.Queue
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		slog.Warn("netstack udp: create endpoint failed", "dst", dstAddr, "error", epErr)
		return
	}

	inConn := gonet.NewUDPConn(&wq, ep)

	// Check if destination matches a tunnel subnet.
	dstIP, dstOk := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	td := func() TunnelDialer {
		if dstOk {
			return f.tunnels.find(dstIP)
		}
		return nil
	}()

	var outConn net.Conn
	if td != nil {
		ctx, cancel := context.WithTimeout(f.ctx, tcpDialTimeout)
		defer cancel()
		var err error
		outConn, err = td.DialUDP(ctx, dstAddr)
		if err != nil {
			slog.Warn("netstack udp: tunnel dial failed", "dst", dstAddr, "tunnel", td.TunnelID(), "error", err)
			inConn.Close()
			return
		}
	} else {
		// Dial real destination on the host network.
		hostAddr, err := net.ResolveUDPAddr("udp", dstAddr)
		if err != nil {
			slog.Warn("netstack udp: resolve failed", "dst", dstAddr, "error", err)
			inConn.Close()
			return
		}

		var dialErr error
		outConn, dialErr = net.DialUDP("udp", nil, hostAddr)
		if dialErr != nil {
			slog.Warn("netstack udp: dial failed", "dst", dstAddr, "error", dialErr)
			inConn.Close()
			return
		}
	}

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		relayUDP(f.ctx, inConn, outConn)
	}()
}

// relayUDP copies UDP packets bidirectionally with an idle timeout.
func relayUDP(ctx context.Context, gvisorConn net.Conn, hostConn net.Conn) {
	defer gvisorConn.Close()
	defer hostConn.Close()

	done := make(chan struct{}, 2)

	// gVisor → host
	go func() {
		buf := make([]byte, udpBufSize)
		for {
			gvisorConn.SetReadDeadline(time.Now().Add(udpNATTimeout))
			n, err := gvisorConn.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			hostConn.SetWriteDeadline(time.Now().Add(udpNATTimeout))
			if _, err := hostConn.Write(buf[:n]); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	// host → gVisor
	go func() {
		buf := make([]byte, udpBufSize)
		for {
			hostConn.SetReadDeadline(time.Now().Add(udpNATTimeout))
			n, err := hostConn.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			gvisorConn.SetWriteDeadline(time.Now().Add(udpNATTimeout))
			if _, err := gvisorConn.Write(buf[:n]); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
