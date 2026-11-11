//go:build with_gvisor && freebsd

package tun

import (
	"sync"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"

	"golang.org/x/sys/unix"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	var packetHeader [PacketOffset]byte
	if pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber {
		packetHeader[3] = unix.AF_INET6
	} else {
		packetHeader[3] = unix.AF_INET
	}
	views := pkt.AsSlices()
	packet := make([]byte, 0, PacketOffset+pkt.Size())
	packet = append(packet, packetHeader[:]...)
	for _, view := range views {
		packet = append(packet, view...)
	}
	_, err := t.tunFile.Write(packet)
	if err != nil {
		return 0, err
	}
	return pkt.Size(), nil
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return &FreeBSDEndpoint{tun: t}, stack.NICOptions{}, nil
}

var _ stack.LinkEndpoint = (*FreeBSDEndpoint)(nil)

type FreeBSDEndpoint struct {
	tun        *NativeTun
	mu         sync.RWMutex // mu guards dispatcher
	dispatcher stack.NetworkDispatcher
}

func (e *FreeBSDEndpoint) MTU() uint32 {
	return e.tun.options.MTU
}

func (e *FreeBSDEndpoint) SetMTU(mtu uint32) {
}

func (e *FreeBSDEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *FreeBSDEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *FreeBSDEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
}

func (e *FreeBSDEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *FreeBSDEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if dispatcher == nil && e.dispatcher != nil {
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		go e.dispatchLoop()
	}
}

func (e *FreeBSDEndpoint) dispatchLoop() {
	mtu := int(e.tun.options.MTU)
	for {
		readBuffer := make([]byte, PacketOffset+mtu)
		n, err := e.tun.tunFile.Read(readBuffer)
		if err != nil {
			break
		}
		if n <= PacketOffset {
			continue
		}
		packetBuffer := buffer.MakeWithData(readBuffer[PacketOffset:n])
		ihl, ok := packetBuffer.PullUp(0, 1)
		if !ok {
			packetBuffer.Release()
			continue
		}
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(ihl.AsSlice()) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		default:
			packetBuffer.Release()
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           packetBuffer,
			IsForwardedPacket: true,
		})
		e.mu.RLock()
		dispatcher := e.dispatcher
		e.mu.RUnlock()
		if dispatcher == nil {
			pkt.DecRef()
			return
		}
		dispatcher.DeliverNetworkPacket(networkProtocol, pkt)
		pkt.DecRef()
	}
}

func (e *FreeBSDEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *FreeBSDEndpoint) Wait() {
}

func (e *FreeBSDEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *FreeBSDEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (e *FreeBSDEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (e *FreeBSDEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, packet := range packetBufferList.AsSlice() {
		_, err := e.tun.WritePacket(packet)
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

func (e *FreeBSDEndpoint) Close() {
}

func (e *FreeBSDEndpoint) SetOnCloseAction(f func()) {
}
