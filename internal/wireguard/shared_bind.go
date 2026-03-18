package wireguard

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// sharedBindHub manages a single UDP socket shared across multiple WireGuard devices.
// The main device uses a fanOutBind (wrapping StdNetBind) so incoming packets are
// copied to all registered tunnel clients. This allows tunnels to share port 51820.
type sharedBindHub struct {
	mu      sync.RWMutex
	clients []*sharedBindClient
	foBind  *fanOutBind // the fan-out bind wrapping the real StdNetBind
}

// newSharedBindHub creates a hub wrapping a fan-out bind.
func newSharedBindHub(foBind *fanOutBind) *sharedBindHub {
	return &sharedBindHub{foBind: foBind}
}

// newClient creates a new conn.Bind for a tunnel device that shares this hub's socket.
func (h *sharedBindHub) newClient() *sharedBindClient {
	c := &sharedBindClient{
		hub:     h,
		packets: make(chan sharedPacket, 256),
		closed:  make(chan struct{}),
	}
	h.mu.Lock()
	h.clients = append(h.clients, c)
	h.mu.Unlock()
	slog.Debug("shared bind: registered new tunnel client", "total_clients", len(h.clients))
	return c
}

// removeClient removes a client from the hub.
func (h *sharedBindHub) removeClient(c *sharedBindClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, cl := range h.clients {
		if cl == c {
			h.clients = append(h.clients[:i], h.clients[i+1:]...)
			slog.Debug("shared bind: removed tunnel client", "remaining_clients", len(h.clients))
			return
		}
	}
}

// fanOut delivers a received packet to all registered tunnel clients.
func (h *sharedBindHub) fanOut(data []byte, ep conn.Endpoint) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.clients {
		c.mu.RLock()
		open := c.open
		c.mu.RUnlock()
		if !open {
			continue
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		select {
		case c.packets <- sharedPacket{data: buf, endpoint: ep}:
		default:
			slog.Debug("shared bind: dropped packet (client buffer full)")
		}
	}
}

// fanOutBind wraps a real conn.Bind (StdNetBind) and copies received packets
// to registered tunnel clients. Used as the main WireGuard device's bind.
type fanOutBind struct {
	hub   *sharedBindHub
	inner conn.Bind
	port  uint16 // actual bound port
}

func (b *fanOutBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.port = actualPort
	slog.Info("shared bind: main device opened", "port", actualPort)

	// Wrap each receive function to fan out packets to tunnel clients
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		origFn := fn
		wrapped[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := origFn(bufs, sizes, eps)
			if err != nil {
				return n, err
			}
			// Fan out received packets to all tunnel clients
			if b.hub != nil {
				for j := 0; j < n; j++ {
					if sizes[j] > 0 {
						b.hub.fanOut(bufs[j][:sizes[j]], eps[j])
					}
				}
			}
			return n, nil
		}
	}
	return wrapped, actualPort, nil
}

func (b *fanOutBind) Close() error               { return b.inner.Close() }
func (b *fanOutBind) SetMark(mark uint32) error   { return b.inner.SetMark(mark) }
func (b *fanOutBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	return b.inner.Send(bufs, ep)
}
func (b *fanOutBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}
func (b *fanOutBind) BatchSize() int { return b.inner.BatchSize() }

var _ conn.Bind = (*fanOutBind)(nil)

type sharedPacket struct {
	data     []byte
	endpoint conn.Endpoint
}

// sharedBindClient implements conn.Bind for a tunnel device sharing the hub's socket.
type sharedBindClient struct {
	hub     *sharedBindHub
	mu      sync.RWMutex
	packets chan sharedPacket
	closed  chan struct{}
	open    bool
}

func (c *sharedBindClient) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	// Reset state for re-opens (WireGuard calls Close+Open during IPC config changes)
	c.closed = make(chan struct{})
	c.open = true
	closed := c.closed
	c.mu.Unlock()

	actualPort := c.hub.foBind.port
	slog.Info("shared bind client: opened", "main_port", actualPort, "requested_port", port)

	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-c.packets:
			if len(bufs) > 0 && len(bufs[0]) >= len(pkt.data) {
				copy(bufs[0], pkt.data)
				sizes[0] = len(pkt.data)
				eps[0] = pkt.endpoint
				return 1, nil
			}
			return 0, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{recv}, actualPort, nil
}

func (c *sharedBindClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open {
		c.open = false
		close(c.closed)
		// Drain the packet channel
		for len(c.packets) > 0 {
			<-c.packets
		}
	}
	slog.Debug("shared bind client: closed")
	return nil
}

func (c *sharedBindClient) SetMark(mark uint32) error { return nil }

func (c *sharedBindClient) Send(bufs [][]byte, ep conn.Endpoint) error {
	// Delegate sends to the real underlying bind
	return c.hub.foBind.inner.Send(bufs, ep)
}

func (c *sharedBindClient) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: e}, nil
}

func (c *sharedBindClient) BatchSize() int { return 1 }

var _ conn.Bind = (*sharedBindClient)(nil)
