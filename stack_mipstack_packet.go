package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/metacubex/mipstack"
	E "github.com/metacubex/sing/common/exceptions"
)

func (s *MIPStack) tunLoop() {
	defer s.Close()
	readCapacity := gsoMaxSize
	if _, darwin := s.tun.(DarwinTUN); darwin && s.recvMsgX {
		// Darwin batches can contain hundreds of packets. Reserve one MTU
		// per packet instead of a full GSO buffer (which utun does not need).
		readCapacity, _ = s.stack.MTU()
	}
	buffers := make([][]byte, s.batchSize)
	sizes := make([]int, len(buffers))
	for i := range buffers {
		// GSOSplit also accepts unsegmented packets larger than the MTU.
		buffers[i] = make([]byte, readCapacity+s.frontHeadroom)
	}
	inbound := make([][]byte, 0, len(buffers))
	reflected := make([][]byte, 0, len(buffers))
	for s.ctx.Err() == nil {
		var n int
		var err error
		if win, ok := s.tun.(WinTun); ok {
			packet, release, readErr := win.ReadPacket()
			if len(packet) > 0 {
				n = 1
				sizes[0] = copy(buffers[0][s.frontHeadroom:], packet)
			}
			if release != nil {
				release()
			}
			err = readErr
		} else if darwin, ok := s.tun.(DarwinTUN); ok && s.recvMsgX {
			packets, readErr := darwin.BatchRead()
			for len(buffers) < len(packets) {
				buffers = append(buffers, make([]byte, readCapacity+s.frontHeadroom))
				sizes = append(sizes, 0)
			}
			for i, packet := range packets {
				if len(buffers[i]) < packet.Len()+s.frontHeadroom {
					buffers[i] = make([]byte, packet.Len()+s.frontHeadroom)
				}
				sizes[i] = copy(buffers[i][s.frontHeadroom:], packet.Bytes())
				packet.Release()
			}
			n, err = len(packets), readErr
		} else if s.batchTun != nil {
			// The TUN consumes virtio metadata and returns complete IP packets,
			// including checksums completed by GSOSplit when NEEDS_CSUM is set.
			n, err = s.batchTun.BatchRead(buffers, s.frontHeadroom, sizes)
		} else {
			var size int
			size, err = s.tun.Read(buffers[0])
			if size > s.frontHeadroom {
				n, sizes[0] = 1, size-s.frontHeadroom
			}
		}
		if s.ctx.Err() != nil {
			return
		}
		inbound, reflected = inbound[:0], reflected[:0]
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 {
				continue
			}
			packet := buffers[i][s.frontHeadroom : s.frontHeadroom+sizes[i]]
			source, destination, ok := mipPacketAddresses(packet)
			if !ok || source.IsLoopback() {
				continue
			}
			_, broadcast := s.broadcastAddresses[destination]
			// Match the existing gVisor link filter and keep non-unicast
			// packets outside MIPS's private loopback address space.
			if broadcast || !destination.IsGlobalUnicast() || s.reflectLoopback(packet) {
				reflected = append(reflected, buffers[i][:s.frontHeadroom+sizes[i]])
			} else {
				inbound = append(inbound, packet)
			}
		}
		// Write reflected packets before the next read reuses their storage.
		if len(reflected) > 0 {
			if writeErr := s.writePackets(reflected); writeErr != nil {
				if s.ioFailed(writeErr, "reflect TCP loopback") {
					return
				}
			}
		}
		if len(inbound) > 0 {
			if _, writeErr := s.stack.Write(inbound, 0); writeErr != nil {
				if s.ioFailed(writeErr, "input packet") {
					return
				}
			}
		}
		if errors.Is(err, ErrTooManySegments) {
			// The successfully split prefix has already been consumed. One
			// oversized batch must not shut down the stack for later traffic.
			s.logError(err, "split TUN packet")
			continue
		}
		if err != nil {
			if s.ioFailed(err, "read TUN") {
				return
			}
			if _, win := s.tun.(WinTun); win {
				return
			}
		}
	}
}

func mipPacketAddresses(packet []byte) (netip.Addr, netip.Addr, bool) {
	if len(packet) > 0 {
		switch packet[0] >> 4 {
		case 4:
			if len(packet) >= 20 {
				source, _ := netip.AddrFromSlice(packet[12:16])
				destination, _ := netip.AddrFromSlice(packet[16:20])
				return source, destination, true
			}
		case 6:
			if len(packet) >= 40 {
				source, _ := netip.AddrFromSlice(packet[8:24])
				destination, _ := netip.AddrFromSlice(packet[24:40])
				return source, destination, true
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func (s *MIPStack) packetLoop() {
	defer s.Close()
	mtu, _ := s.stack.MTU()
	capacity := mtu
	if s.batchTun != nil {
		// BatchWrite may coalesce packets in place. Leave room for GRO rather
		// than limiting each backing buffer to one MTU-sized segment.
		capacity = gsoMaxSize
	}
	batchSize := s.stack.BatchSize()
	if s.batchTun != nil && s.batchSize < batchSize {
		batchSize = s.batchSize
	}
	packets := make([][]byte, batchSize)
	sizes := make([]int, len(packets))
	for i := range packets {
		packets[i] = make([]byte, capacity+s.frontHeadroom)
	}
	for {
		for i := range packets {
			packets[i] = packets[i][:cap(packets[i])]
		}
		n, err := s.stack.Read(packets, sizes, s.frontHeadroom)
		for i := 0; i < n; i++ {
			packets[i] = packets[i][:s.frontHeadroom+sizes[i]]
		}
		if n > 0 {
			if writeErr := s.writePackets(packets[:n]); writeErr != nil {
				if s.ioFailed(writeErr, "write TUN") {
					return
				}
			}
		}
		if err != nil {
			s.logError(err, "output packet")
			return
		}
	}
}

// Serialize stack output and loopback reflection, including the mutable GRO
// state of batch devices. Every input packet has a complete checksum even when
// TXChecksumOffload is enabled; BatchWrite owns any conversion to partial sums.
func (s *MIPStack) writePackets(packets [][]byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.batchTun != nil {
		// Native BatchWrite reports bytes (possibly after coalescing), not a
		// packet count. Do not compare its return value with len(packets).
		_, err := s.batchTun.BatchWrite(packets, s.frontHeadroom)
		return err
	}
	var result error
	for _, packet := range packets {
		if s.frontHeadroom == 4 {
			family := uint32(2) // Darwin AF_INET / AF_INET6, network byte order.
			if packet[s.frontHeadroom]>>4 == 6 {
				family = 30
			}
			binary.BigEndian.PutUint32(packet, family)
		}
		n, err := s.tun.Write(packet)
		if err != nil {
			if E.IsClosed(err) {
				return err
			}
			result = errors.Join(result, err)
			continue
		}
		if n == 0 {
			if _, win := s.tun.(WinTun); win {
				continue
			}
		}
		if n != len(packet) {
			result = errors.Join(result, io.ErrShortWrite)
		}
	}
	return result
}

// reflectLoopback preserves the existing stack behavior: swap IP addresses
// for TCP sent to a configured loopback address, keeping ports and payload.
// Address swapping preserves the one's-complement sum of both the IPv4
// header and TCP pseudo-header, so it also works on individual IP fragments
// without reassembling them or rewriting a partial transport header.
func (s *MIPStack) reflectLoopback(packet []byte) bool {
	if len(s.loopback) == 0 || len(packet) == 0 {
		return false
	}
	source, destination, ok := mipPacketAddresses(packet)
	if !ok {
		return false
	}
	if _, match := s.loopback[destination]; !match || !source.IsGlobalUnicast() || !destination.IsGlobalUnicast() {
		return false
	}
	parsed, err := mipstack.ParseIPPacket(packet)
	if err != nil || !mipValidLoopback(parsed) {
		return false
	}
	sourceOffset, addressSize := 12, 4
	if destination.Is6() {
		sourceOffset, addressSize = 8, 16
	}
	copy(packet[sourceOffset:sourceOffset+addressSize], destination.AsSlice())
	copy(packet[sourceOffset+addressSize:sourceOffset+2*addressSize], source.AsSlice())
	return true
}

// The complete transport checksum is unavailable on non-atomic fragments.
func mipValidLoopback(parsed mipstack.IPPacket) bool {
	if fragment, ok := parsed.Fragment(); ok && !fragment.IsAtomic() {
		if fragment.Offset != 0 {
			return fragment.Protocol == mipstack.ProtocolTCP
		}
		parsed.Protocol, parsed.Payload = fragment.Protocol, fragment.Payload
		parsed.MoreFragments, parsed.FragmentOffset = false, 0
		protocol, _, err := parsed.UpperLayer()
		return err == nil && protocol == mipstack.ProtocolTCP
	}
	_, err := parsed.TCPSegment()
	return err == nil
}

// Packet loss or a transient device failure is not a stack shutdown.
func (s *MIPStack) ioFailed(err error, operation string) bool {
	s.logError(err, operation)
	return s.ctx.Err() != nil || E.IsClosed(err) || errors.Is(err, io.EOF)
}
