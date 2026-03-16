package wireguard

import (
	"os"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// netstackTun implements tun.Device backed by a gVisor channel endpoint.
// This is equivalent to the unexported netTun in golang.zx2c4.com/wireguard/tun/netstack.
type netstackTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
}

func (t *netstackTun) Name() (string, error) {
	return "netstack", nil
}

func (t *netstackTun) File() *os.File {
	return nil
}

func (t *netstackTun) Events() <-chan tun.Event {
	return t.events
}

func (t *netstackTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-t.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *netstackTun) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

// WriteNotify is called by the channel endpoint when a packet is ready to be read.
func (t *netstackTun) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	t.incomingPacket <- view
}

func (t *netstackTun) Close() error {
	t.stack.RemoveNIC(1)
	t.stack.Close()
	t.ep.RemoveNotify(t.notifyHandle)
	t.ep.Close()
	if t.events != nil {
		close(t.events)
	}
	if t.incomingPacket != nil {
		close(t.incomingPacket)
	}
	return nil
}

func (t *netstackTun) MTU() (int, error) {
	return t.mtu, nil
}

func (t *netstackTun) BatchSize() int {
	return 1
}
