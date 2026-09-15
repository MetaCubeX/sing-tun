package tun

import (
	"context"
	"net/netip"
	"time"

	"github.com/metacubex/mipstack"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
)

type Mipstack struct {
	ctx                  context.Context
	tun                  Tun
	mtu                  uint32
	recvMsgX             bool
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	broadcastAddr        netip.Addr
	icmpMapping          *DirectRouteMapping
	handler              Handler
	logger               logger.Logger
	stack                *mipstack.Stack
	icmpSlots            chan struct{}
}

func NewMipstack(options StackOptions) (Stack, error) {
	var (
		inet4Address netip.Addr
		inet6Address netip.Addr
	)
	if len(options.TunOptions.Inet4Address) > 0 {
		inet4Address = options.TunOptions.Inet4Address[0].Addr()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		inet6Address = options.TunOptions.Inet6Address[0].Addr()
	}

	s := &Mipstack{
		ctx:                  options.Context,
		tun:                  options.Tun,
		mtu:                  options.TunOptions.MTU,
		recvMsgX:             options.TunOptions.EXP_RecvMsgX,
		inet4Address:         inet4Address,
		inet6Address:         inet6Address,
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		icmpMapping:          NewDirectRouteMapping(options.ICMPTimeout),
		icmpSlots:            make(chan struct{}, 16),
		handler:              options.Handler,
		logger:               options.Logger,
	}
	return s, nil
}

func (s *Mipstack) config() mipstack.Config {
	// With no local addresses, mipstack's default IPv6 route rejects IPv4-only
	// links whose MTU is below IPv6's minimum, so install an IPv4 default route.
	var routes []mipstack.Route
	if s.mtu != 0 && s.mtu < 1280 && !s.inet6Address.IsValid() {
		routes = []mipstack.Route{{Destination: netip.MustParsePrefix("0.0.0.0/0")}}
	}
	return mipstack.Config{
		Routes:      routes,
		Promiscuous: true,
		MTU:         s.mtu,
		TCP: mipstack.TCPSocketDefaults{
			KeepAlive: true,
			KeepAliveConfig: mipstack.KeepAliveConfig{
				Idle:     15 * time.Second,
				Interval: 15 * time.Second,
			},
		},
	}
}

func (s *Mipstack) Start() error {
	stack, err := mipstack.New(s.config())
	if err != nil {
		return err
	}
	defer func() {
		if s.stack == nil {
			_ = stack.Close()
		}
	}()
	_, err = mipstack.NewTCPForwarder(stack, mipstack.TCPForwarderOptions{}, s.forwardTCP)
	if err != nil {
		return err
	}
	_, err = mipstack.NewUDPForwarder(stack, mipstack.UDPForwarderOptions{}, s.forwardUDP)
	if err != nil {
		return err
	}
	_, err = mipstack.NewICMPForwarder(stack, mipstack.ICMPForwarderOptions{}, s.forwardICMP)
	if err != nil {
		return err
	}
	_, err = mipstack.NewIPForwarder(stack, mipstack.IPForwarderOptions{}, func(request *mipstack.IPForwarderRequest) {
		_ = request.Reject()
	})
	if err != nil {
		return err
	}
	err = stack.Start()
	if err != nil {
		return err
	}
	s.stack = stack
	go s.readLoop()
	go s.writeLoop()
	return nil
}

// Start and Close are called sequentially by the owner, like the other stacks.
func (s *Mipstack) Close() error {
	// The listener owns TUN.Close. Do not wait for its blocking Read here.
	if s.stack != nil {
		return s.stack.Close()
	}
	return nil
}

func (s *Mipstack) readLoop() {
	device := s.tun
	if linuxTUN, isLinuxTUN := device.(LinuxTUN); isLinuxTUN && linuxTUN.FrontHeadroom() > 0 {
		s.batchLoopLinux(linuxTUN, linuxTUN.BatchSize())
		return
	}
	if winTun, isWinTun := device.(WinTun); isWinTun {
		s.wintunLoop(winTun)
		return
	}
	offset := 0
	if darwinTUN, isDarwinTUN := device.(DarwinTUN); isDarwinTUN {
		if s.recvMsgX {
			s.batchLoopDarwin(darwinTUN)
			return
		}
		offset = 4
	}
	buffer := make([]byte, int(s.mtu)+offset)
	for {
		n, err := device.Read(buffer)
		if n > offset {
			s.processPacket(buffer[:n], offset)
		}
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "read packet"))
		}
	}
}

func (s *Mipstack) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if len(packet) > 0 {
			s.processPacket(packet, 0)
		}
		if release != nil {
			release()
		}
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read packet"))
			}
			return
		}
	}
}

func (s *Mipstack) batchLoopLinux(linuxTUN LinuxTUN, batchSize int) {
	offset := linuxTUN.FrontHeadroom()
	buffers := make([][]byte, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, int(s.mtu)+offset)
	}
	sizes := make([]int, len(buffers))
	for {
		n, err := linuxTUN.BatchRead(buffers, offset, sizes)
		for i := 0; i < n; i++ {
			s.processPacket(buffers[i][:offset+sizes[i]], offset)
		}
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
	}
}

func (s *Mipstack) batchLoopDarwin(darwinTUN DarwinTUN) {
	for {
		buffers, err := darwinTUN.BatchRead()
		for _, buffer := range buffers {
			s.processPacket(buffer.Bytes(), 0)
			buffer.Release()
		}
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
	}
}

// processPacket processes an IP packet beginning at offset. The leading bytes
// are retained when handing the buffer to mipstack so callers can reuse their
// existing packet storage without first slicing away device metadata.
func (s *Mipstack) processPacket(packet []byte, offset int) {
	ipPacket := packet[offset:]
	destination, ok := mipsPacketDestination(ipPacket)
	if !ok {
		return
	}
	// Match sing-tun's LinkEndpointFilter, including reflecting non-unicast
	// packets unchanged rather than offering them to protocol forwarders.
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		if err := s.writePackets([][]byte{packet}, offset); err != nil {
			s.logger.Trace(E.Cause(err, "write packet"))
		}
		return
	}
	addresses := s.inet4LoopbackAddress
	if destination.Is6() {
		addresses = s.inet6LoopbackAddress
	}
	for _, address := range addresses {
		if address != destination {
			continue
		}
		parsed, err := mipstack.ParseIPPacket(ipPacket)
		if err != nil {
			return
		}
		if !mipsValidLoopbackPacket(parsed) {
			break
		}
		responseOffset := offset
		response := make([]byte, responseOffset+len(ipPacket))
		copy(response[responseOffset:], ipPacket)
		if destination.Is4() {
			ip := header.IPv4(response[responseOffset:])
			ip.SetSourceAddr(destination)
			ip.SetDestinationAddr(parsed.Source)
		} else {
			ip := header.IPv6(response[responseOffset:])
			ip.SetSourceAddr(destination)
			ip.SetDestinationAddr(parsed.Source)
		}
		// Swapping the addresses preserves both the IP checksum and the
		// TCP pseudo-header sum, also for fragments and extension headers.
		if err := s.writePackets([][]byte{response}, responseOffset); err != nil {
			s.logger.Trace(E.Cause(err, "write packet"))
		}
		return
	}
	// Invalid packet errors are local to the datagram, not fatal device errors.
	_, _ = s.stack.Write([][]byte{packet}, offset)
}

// Inspect only the base header before non-unicast reflection, just as
// LinkEndpointFilter does. Full protocol validation belongs to mipstack.
func mipsPacketDestination(packet []byte) (netip.Addr, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ip := header.IPv4(packet)
		if ip.IsValid(len(packet)) {
			return ip.DestinationAddr(), true
		}
	case header.IPv6Version:
		ip := header.IPv6(packet)
		if ip.IsValid(len(packet)) {
			return ip.DestinationAddr(), true
		}
	}
	return netip.Addr{}, false
}

// Validate complete packets before bypassing the stack. Fragment checksums
// cannot be verified independently; preserve valid IP fragments for the host
// to reassemble after reflection.
func mipsValidLoopbackPacket(parsed mipstack.IPPacket) bool {
	if fragment, ok := parsed.Fragment(); ok && !fragment.IsAtomic() {
		if fragment.Offset != 0 {
			return fragment.Protocol == mipstack.ProtocolTCP
		}
		// The first fragment can include extension headers before TCP.
		// Inspect those with mipstack, without checking a partial TCP checksum.
		parsed.Protocol, parsed.Payload = fragment.Protocol, fragment.Payload
		parsed.MoreFragments, parsed.FragmentOffset = false, 0
		protocol, _, err := parsed.UpperLayer()
		return err == nil && protocol == mipstack.ProtocolTCP
	}
	_, err := parsed.TCPSegment()
	return err == nil
}

func (s *Mipstack) writeLoop() {
	outputOffset := 0
	bufferSize := int(s.mtu)
	bufferCapacity := bufferSize
	// Output buffers include the device header space; Linux GSO buffers also
	// retain enough capacity for GRO to merge packets without another copy.
	if linux, ok := s.tun.(LinuxTUN); ok && linux.FrontHeadroom() > 0 {
		outputOffset = linux.FrontHeadroom()
		if bufferCapacity < int(gsoMaxSize) {
			bufferCapacity = int(gsoMaxSize)
		}
	} else if _, ok := s.tun.(DarwinTUN); ok {
		outputOffset = 4
	}
	buffers := make([][]byte, s.stack.BatchSize())
	for i := range buffers {
		buffers[i] = make([]byte, outputOffset+bufferSize, outputOffset+bufferCapacity)
	}
	sizes := make([]int, len(buffers))
	packets := make([][]byte, len(buffers))
	for {
		n, err := s.stack.Read(buffers, sizes, outputOffset)
		for i := 0; i < n; i++ {
			// Keep the full backing capacity so Linux GRO can append merged payloads.
			packets[i] = buffers[i][: outputOffset+sizes[i] : outputOffset+bufferCapacity]
		}
		if writeErr := s.writePackets(packets[:n], outputOffset); writeErr != nil {
			if E.IsClosed(writeErr) {
				return
			}
			s.logger.Trace(E.Cause(writeErr, "write packet"))
		}
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read stack packet"))
			}
			return
		}
	}
}

// writePackets writes packets to s.tun. In every packet, packet[offset:] is the
// IP packet and bytes before offset are available headroom.
//
// Platform-specific requirements:
//
//   - Linux TUN with VNET headers: offset must identify headroom at least as
//     large as the device's virtio header. If it is smaller, writePackets
//     creates framed copies. BatchWrite may run GRO for multiple packets in
//     this call; any packet can become the aggregate target (TCP may move the
//     target when prepending), so every possible target needs writable tailroom
//     if callers want merging. The capacity only needs to cover the aggregate
//     formed by this call; gsoMaxSize is an upper-bound preallocation, not a
//     strict requirement. Insufficient capacity skips that merge and writes the
//     packets separately. A one-packet call has no tailroom requirement.
//
//   - Darwin utun: four bytes immediately before the IP packet hold the
//     big-endian address-family header. If offset is smaller than four,
//     writePackets creates a framed copy; otherwise it writes the header in
//     place and sends from offset-4. Darwin does not perform GRO, so no extra
//     tailroom is needed.
//
//   - Other devices: packet[offset:] is written directly, with no extra
//     headroom or tailroom requirements.
//
// Direct Linux and Darwin paths may modify the supplied buffers. Callers must
// not modify them concurrently while this function is running.
func (s *Mipstack) writePackets(packets [][]byte, offset int) error {
	if len(packets) == 0 {
		return nil
	}
	// Only GSO devices initialize the GRO tables used by BatchWrite.
	if linux, ok := s.tun.(LinuxTUN); ok && linux.FrontHeadroom() > 0 {
		deviceOffset := linux.FrontHeadroom()
		if offset < deviceOffset {
			framed := make([][]byte, len(packets))
			for i, packet := range packets {
				packet = packet[offset:]
				framed[i] = make([]byte, deviceOffset+len(packet), deviceOffset+int(gsoMaxSize))
				copy(framed[i][deviceOffset:], packet)
			}
			packets = framed
			offset = deviceOffset
		}
		_, err := linux.BatchWrite(packets, offset)
		return err
	}
	if darwin, ok := s.tun.(DarwinTUN); ok {
		if offset < 4 {
			framed := make([][]byte, len(packets))
			for i, packet := range packets {
				packet = packet[offset:]
				framed[i] = make([]byte, 4+len(packet))
				copy(framed[i][4:], packet)
			}
			packets = framed
			offset = 4
		}
		for _, packet := range packets {
			ipPacket := packet[offset:]
			familyHeader := packet[offset-4 : offset]
			// Darwin utun requires a four-byte, big-endian address family header.
			familyHeader[0] = 0
			familyHeader[1] = 0
			familyHeader[2] = 0
			familyHeader[3] = 2 // AF_INET on Darwin.
			if header.IPVersion(ipPacket) == header.IPv6Version {
				familyHeader[3] = 30 // AF_INET6 on Darwin, even when tested on another OS.
			}
			if _, err := darwin.Write(packet[offset-4:]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, packet := range packets {
		_, err := s.tun.Write(packet[offset:])
		if err != nil {
			return err
		}
	}
	return nil
}
