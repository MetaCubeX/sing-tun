//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/exp/slices"
)

type calicoFlowAction uint8

const (
	calicoUnclassified calicoFlowAction = iota
	calicoTunnel
	calicoNativeReply
)

type calicoServiceFlow struct {
	family                      byte
	source, destination         netip.Addr
	sourcePort, destinationPort uint16
	protocol                    byte
	mark, input                 uint32
}

func parseCalicoUntrackedTCP(data []byte, family byte) (flow calicoServiceFlow, ok bool) {
	flow.family = family
	var offset int
	var protocol byte
	switch family {
	case unix.AF_INET:
		if len(data) < 20 || data[0]>>4 != 4 || binary.BigEndian.Uint16(data[6:8])&0x1fff != 0 {
			return flow, false
		}
		offset = int(data[0]&15) * 4
		if offset < 20 {
			return flow, false
		}
		flow.source, _ = netip.AddrFromSlice(data[12:16])
		flow.destination, _ = netip.AddrFromSlice(data[16:20])
		protocol = data[9]
	case unix.AF_INET6:
		if len(data) < 40 || data[0]>>4 != 6 {
			return flow, false
		}
		flow.source, _ = netip.AddrFromSlice(data[8:24])
		flow.destination, _ = netip.AddrFromSlice(data[24:40])
		offset, protocol = 40, data[6]
		for protocol != unix.IPPROTO_TCP {
			if offset+8 > len(data) {
				return flow, false
			}
			var length int
			switch protocol {
			case unix.IPPROTO_HOPOPTS, unix.IPPROTO_ROUTING, unix.IPPROTO_DSTOPTS:
				length = (int(data[offset+1]) + 1) * 8
			case unix.IPPROTO_AH:
				length = (int(data[offset+1]) + 2) * 4
			case unix.IPPROTO_FRAGMENT:
				if binary.BigEndian.Uint16(data[offset+2:offset+4])&0xfff8 != 0 {
					return flow, false
				}
				length = 8
			default:
				return flow, false
			}
			protocol = data[offset]
			offset += length
		}
	default:
		return flow, false
	}
	// NFQUEUE can truncate options or payload. The map key needs only the
	// ports, but reject a known malformed length if the field was copied.
	if protocol != unix.IPPROTO_TCP || offset+4 > len(data) {
		return flow, false
	}
	if offset+12 < len(data) && data[offset+12]>>4 < 5 {
		return flow, false
	}
	flow.protocol = protocol
	flow.sourcePort = binary.BigEndian.Uint16(data[offset : offset+2])
	flow.destinationPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	return flow, true
}

func parseCalicoServiceFlow(data []byte, reply bool) (flow calicoServiceFlow, err error) {
	if len(data) < 4 {
		return flow, unix.EINVAL
	}
	flow.family = data[0]
	attrs, err := nl.ParseRouteAttr(data[4:])
	if err != nil {
		return flow, err
	}
	tupleType := uint16(nl.CTA_TUPLE_ORIG)
	if reply {
		tupleType = nl.CTA_TUPLE_REPLY
	}
	for _, attr := range attrs {
		typ := attr.Attr.Type & 0x3fff
		if typ == nl.CTA_MARK && len(attr.Value) == 4 {
			flow.mark = binary.BigEndian.Uint32(attr.Value)
		}
		if typ != tupleType {
			continue
		}
		parts, e := nl.ParseRouteAttr(attr.Value)
		if e != nil {
			return flow, e
		}
		for _, part := range parts {
			if part.Attr.Type&0x3fff != nl.CTA_TUPLE_IP && part.Attr.Type&0x3fff != nl.CTA_TUPLE_PROTO {
				continue
			}
			fields, e := nl.ParseRouteAttr(part.Value)
			if e != nil {
				return flow, e
			}
			for _, field := range fields {
				if part.Attr.Type&0x3fff == nl.CTA_TUPLE_IP {
					switch field.Attr.Type & 0x3fff {
					case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
						flow.source, _ = netip.AddrFromSlice(field.Value)
					case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
						flow.destination, _ = netip.AddrFromSlice(field.Value)
					}
				} else {
					switch field.Attr.Type & 0x3fff {
					case nl.CTA_PROTO_NUM:
						if len(field.Value) == 1 {
							flow.protocol = field.Value[0]
						}
					case nl.CTA_PROTO_SRC_PORT:
						if len(field.Value) == 2 {
							flow.sourcePort = binary.BigEndian.Uint16(field.Value)
						}
					case nl.CTA_PROTO_DST_PORT:
						if len(field.Value) == 2 {
							flow.destinationPort = binary.BigEndian.Uint16(field.Value)
						}
					}
				}
			}
		}
	}
	return flow, nil
}

// Calico's pinned CT v4 ABI is shared by its IPv4 and IPv6 maps. Open it
// read-only and verify its layout before interpreting any NAT state.
func openCalicoConntrack(ipv6 bool) (int, error) {
	name, keySize, valueSize := "cali_v4_ct4", uint32(16), uint32(88)
	if ipv6 {
		name, keySize, valueSize = "cali_v6_ct4", 40, 128
	}
	path, err := unix.BytePtrFromString("/sys/fs/bpf/tc/globals/" + name)
	if err != nil {
		return -1, err
	}
	attr := struct {
		Path      uint64
		FD, Flags uint32
	}{Path: uint64(uintptr(unsafe.Pointer(path))), Flags: unix.BPF_F_RDONLY}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(path)
	if errno != 0 {
		return -1, errno
	}
	var info [40]byte
	query := struct {
		FD, Size uint32
		Info     uint64
	}{uint32(fd), uint32(len(info)), uint64(uintptr(unsafe.Pointer(&info[0])))}
	_, _, errno = unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
	if errno != 0 || nl.NativeEndian().Uint32(info[0:4]) != unix.BPF_MAP_TYPE_LRU_HASH || nl.NativeEndian().Uint32(info[8:12]) != keySize || nl.NativeEndian().Uint32(info[12:16]) != valueSize || string(info[24:24+len(name)]) != name {
		unix.Close(int(fd))
		if errno != 0 {
			return -1, errno
		}
		return -1, fmt.Errorf("unsupported Calico conntrack map ABI: %s", name)
	}
	return int(fd), nil
}

func (f calicoServiceFlow) classifyCalicoFlow(fd int, scope serviceForwardScope) calicoFlowAction {
	if f.mark != 0 || (f.protocol != unix.IPPROTO_TCP && f.protocol != unix.IPPROTO_UDP) || !f.source.IsValid() || !f.destination.IsValid() {
		return calicoUnclassified
	}
	var backend bool
	for _, prefix := range scope.backends {
		backend = backend || prefix.Contains(f.source)
	}
	if !backend {
		return calicoUnclassified
	}
	length, valueSize := 4, 88
	if f.source.Is6() {
		length, valueSize = 16, 128
	}
	key, value := make([]byte, 8+2*length), make([]byte, valueSize)
	nl.NativeEndian().PutUint32(key[:4], uint32(f.protocol))
	for direction := 0; direction < 2; direction++ {
		a, b, pa, pb := f.source, f.destination, f.sourcePort, f.destinationPort
		if direction == 1 {
			a, b, pa, pb = b, a, pb, pa
		}
		copy(key[4:], a.AsSlice())
		copy(key[4+length:], b.AsSlice())
		nl.NativeEndian().PutUint16(key[4+2*length:], pa)
		nl.NativeEndian().PutUint16(key[6+2*length:], pb)
		attr := struct {
			FD, Pad           uint32
			Key, Value, Flags uint64
		}{FD: uint32(fd), Key: uint64(uintptr(unsafe.Pointer(&key[0]))), Value: uint64(uintptr(unsafe.Pointer(&value[0])))}
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_LOOKUP_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		runtime.KeepAlive(key)
		runtime.KeepAlive(value)
		if errno != 0 {
			continue
		}
		if value[16] == 0 || value[16] == 1 {
			return calicoTunnel
		}
		if value[16] != 2 {
			return calicoUnclassified
		}
		// The workload did not open this flow. Its peer did so at a real
		// uplink, and the pre-NAT Service address belongs to that uplink.
		workloadLeg, clientLeg := 24, 48
		if direction == 1 {
			workloadLeg, clientLeg = clientLeg, workloadLeg
		}
		wf, cf := nl.NativeEndian().Uint32(value[workloadLeg+16:]), nl.NativeEndian().Uint32(value[clientLeg+16:])
		if wf&0x70 == 0x70 {
			return calicoTunnel
		}
		if wf&0x70 != 0x50 || cf&0x70 != 0x30 {
			return calicoUnclassified
		}
		wi, ci := nl.NativeEndian().Uint32(value[workloadLeg+20:]), nl.NativeEndian().Uint32(value[clientLeg+20:])
		if f.input == 0 || wi != f.input {
			return calicoUnclassified
		}
		original := 72 + length
		originalIP, _ := netip.AddrFromSlice(value[original : original+length])
		originalSource, _ := netip.AddrFromSlice(value[original+length+4 : original+2*length+4])
		if originalSource != f.destination || nl.NativeEndian().Uint16(value[original+length:]) == 0 {
			return calicoUnclassified
		}
		if scope.matchesCalicoInterfaces(int(wi), int(ci), originalIP) {
			return calicoNativeReply
		}
		return calicoUnclassified
	}
	return calicoUnclassified
}

// The interface snapshot shares the route refresh lifecycle. A topology
// notification invalidates the snapshot even while firewall updates are blocked.
type calicoTopology struct {
	generation uint64
	version    *atomic.Uint64
	workloads  map[int]string
	uplinks    map[int][]netip.Addr
}

func (s serviceForwardScope) matchesCalicoInterfaces(workloadIndex, clientIndex int, originalIP netip.Addr) bool {
	if topology := s.calico; topology != nil && topology.version.Load() == topology.generation {
		return topology.workloads[workloadIndex] != "" && slices.Contains(topology.uplinks[clientIndex], originalIP)
	}
	// Preserve classification while the route worker refreshes a stale snapshot.
	workload, err := net.InterfaceByIndex(workloadIndex)
	if err != nil || len(workload.Name) < 4 || workload.Name[:4] != "cali" {
		return false
	}
	client, err := net.InterfaceByIndex(clientIndex)
	if err != nil || !slices.Contains(s.uplinks, client.Name) {
		return false
	}
	addresses, err := client.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr() == originalIP {
			return true
		}
	}
	return false
}
