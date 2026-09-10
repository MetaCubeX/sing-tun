//go:build with_mipstack

package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

func (s *MIPStack) tunLoop() {
	defer s.Close()
	buffers := make([][]byte, s.batchSize)
	sizes := make([]int, len(buffers))
	for i := range buffers {
		// GSOSplit also accepts unsegmented packets larger than the MTU.
		buffers[i] = make([]byte, gsoMaxSize+s.frontHeadroom)
	}
	inbound := make([][]byte, 0, len(buffers))
	reflected := make([][]byte, 0, len(buffers))
	for s.ctx.Err() == nil {
		var n int
		var err error
		if s.batchTun != nil {
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
				s.logError(writeErr, "reflect TCP loopback")
				return
			}
		}
		if len(inbound) > 0 {
			if _, writeErr := s.stack.Write(inbound, 0); writeErr != nil {
				s.logError(writeErr, "input packet")
				return
			}
		}
		if errors.Is(err, ErrTooManySegments) {
			// The successfully split prefix has already been consumed. One
			// oversized batch must not shut down the stack for later traffic.
			s.logError(err, "split TUN packet")
			continue
		}
		if err != nil {
			s.logError(err, "read TUN")
			return
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
				s.logError(writeErr, "write TUN")
				return
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
	for _, packet := range packets {
		if PacketOffset != 0 {
			family := uint32(2) // Darwin AF_INET / AF_INET6, network byte order.
			if packet[PacketOffset]>>4 == 6 {
				family = 30
			}
			binary.BigEndian.PutUint32(packet, family)
		}
		n, err := s.tun.Write(packet)
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
	}
	return nil
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
	var source, destination netip.Addr
	var sourceOffset, addressSize int
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return false
		}
		headerLen := int(packet[0]&15) * 4
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLen < 20 || totalLen < headerLen || totalLen > len(packet) || packet[9] != 6 {
			return false
		}
		source, _ = netip.AddrFromSlice(packet[12:16])
		destination, _ = netip.AddrFromSlice(packet[16:20])
		sourceOffset, addressSize = 12, 4
	case 6:
		if len(packet) < 40 {
			return false
		}
		totalLen := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if totalLen > len(packet) || !mipIPv6TCP(packet[:totalLen]) {
			return false
		}
		source, _ = netip.AddrFromSlice(packet[8:24])
		destination, _ = netip.AddrFromSlice(packet[24:40])
		sourceOffset, addressSize = 8, 16
	default:
		return false
	}
	if _, ok := s.loopback[destination]; !ok || !source.IsGlobalUnicast() || !destination.IsGlobalUnicast() {
		return false
	}
	copy(packet[sourceOffset:sourceOffset+addressSize], destination.AsSlice())
	copy(packet[sourceOffset+addressSize:sourceOffset+2*addressSize], source.AsSlice())
	return true
}

func mipIPv6TCP(packet []byte) bool {
	next, offset := packet[6], 40
	for {
		switch next {
		case 6:
			return true
		case 0, 60: // Hop-by-Hop / Destination Options.
			if offset+2 > len(packet) {
				return false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if offset+length > len(packet) {
				return false
			}
			next, offset = packet[offset], offset+length
		case 44: // Non-initial fragments do not contain a transport header.
			if offset+8 > len(packet) {
				return false
			}
			if binary.BigEndian.Uint16(packet[offset+2:offset+4])&0xfff8 != 0 {
				return packet[offset] == 6
			}
			next, offset = packet[offset], offset+8
		default:
			return false
		}
	}
}
