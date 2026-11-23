//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

var errUnsupportedCalicoCTABI = errors.New("unsupported Calico conntrack map ABI")

const (
	// Calico v3.32+ conntrack v4 map layout (felix/bpf/conntrack/v4/map{,6}.go).
	calicoCT4PathV4    = "/sys/fs/bpf/tc/globals/cali_v4_ct4"
	calicoCT4PathV6    = "/sys/fs/bpf/tc/globals/cali_v6_ct4"
	calicoCT4NameV4    = "cali_v4_ct4"
	calicoCT4NameV6    = "cali_v6_ct4"
	calicoCT4KeySizeV4 = 16
	calicoCT4ValSizeV4 = 88
	calicoCT4KeySizeV6 = 40
	calicoCT4ValSizeV6 = 128

	calicoCTTypeOffset     = 16
	calicoCTTypeNormal     = 0
	calicoCTTypeNATForward = 1
	calicoCTTypeNATReverse = 2

	calicoCTLegAOffset     = 24
	calicoCTLegBOffset     = 48
	calicoCTLegFlagsOffset = 16
	calicoCTLegIfidxOffset = 20

	calicoCTLegFlagMask     = 0x70
	calicoCTLegFlagPodOpen  = 0x70
	calicoCTLegFlagWorkload = 0x50
	calicoCTLegFlagPeerOpen = 0x30

	calicoCTOrigBaseOffset = 72
	calicoBPFMapInfoSize   = 40
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

func calicoConntrackPath(ipv6 bool) string {
	if ipv6 {
		return calicoCT4PathV6
	}
	return calicoCT4PathV4
}

// Calico's pinned CT v4 ABI is shared by its IPv4 and IPv6 maps. Open it
// read-only and verify its layout before interpreting any NAT state.
func openCalicoConntrack(ipv6 bool) (int, error) {
	name, keySize, valueSize := calicoCT4NameV4, uint32(calicoCT4KeySizeV4), uint32(calicoCT4ValSizeV4)
	if ipv6 {
		name, keySize, valueSize = calicoCT4NameV6, calicoCT4KeySizeV6, calicoCT4ValSizeV6
	}
	path, err := unix.BytePtrFromString(calicoConntrackPath(ipv6))
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
	var info [calicoBPFMapInfoSize]byte
	query := struct {
		FD, Size uint32
		Info     uint64
	}{uint32(fd), uint32(len(info)), uint64(uintptr(unsafe.Pointer(&info[0])))}
	_, _, errno = unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&query)), unsafe.Sizeof(query))
	runtime.KeepAlive(&info)
	if errno != 0 ||
		nl.NativeEndian().Uint32(info[0:4]) != unix.BPF_MAP_TYPE_LRU_HASH ||
		nl.NativeEndian().Uint32(info[8:12]) != keySize ||
		nl.NativeEndian().Uint32(info[12:16]) != valueSize ||
		string(info[24:24+len(name)]) != name ||
		(24+len(name) < len(info) && info[24+len(name)] != 0) {
		unix.Close(int(fd))
		if errno != 0 {
			return -1, errno
		}
		return -1, fmt.Errorf("%w: %s", errUnsupportedCalicoCTABI, name)
	}
	return int(fd), nil
}

type calicoLookupBuffers struct {
	key   [calicoCT4KeySizeV6]byte
	value [calicoCT4ValSizeV6]byte
}

func (f calicoServiceFlow) classifyCalicoFlow(fd int, scope serviceForwardScope) calicoFlowAction {
	return f.classifyCalicoFlowWithBuf(fd, scope, nil)
}

func (f calicoServiceFlow) classifyCalicoFlowWithBuf(fd int, scope serviceForwardScope, buf *calicoLookupBuffers) calicoFlowAction {
	if f.mark != 0 || (f.protocol != unix.IPPROTO_TCP && f.protocol != unix.IPPROTO_UDP) || !f.source.IsValid() || !f.destination.IsValid() {
		return calicoUnclassified
	}
	if !scope.hasBackend(f.source) {
		return calicoUnclassified
	}
	length, valueSize := 4, calicoCT4ValSizeV4
	if f.source.Is6() {
		length, valueSize = 16, calicoCT4ValSizeV6
	}
	var key, value []byte
	if buf != nil {
		key = buf.key[:8+2*length]
		value = buf.value[:valueSize]
	} else {
		key = make([]byte, 8+2*length)
		value = make([]byte, valueSize)
	}
	nl.NativeEndian().PutUint32(key[:4], uint32(f.protocol))
	for direction := 0; direction < 2; direction++ {
		a, b, pa, pb := f.source, f.destination, f.sourcePort, f.destinationPort
		if direction == 1 {
			a, b, pa, pb = b, a, pb, pa
		}
		if length == 4 {
			a4, b4 := a.As4(), b.As4()
			copy(key[4:8], a4[:])
			copy(key[8:12], b4[:])
		} else {
			a16, b16 := a.As16(), b.As16()
			copy(key[4:20], a16[:])
			copy(key[20:36], b16[:])
		}
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
		if value[calicoCTTypeOffset] == calicoCTTypeNormal || value[calicoCTTypeOffset] == calicoCTTypeNATForward {
			return calicoTunnel
		}
		if value[calicoCTTypeOffset] != calicoCTTypeNATReverse {
			return calicoUnclassified
		}
		// The workload did not open this flow. Its peer did so at a real
		// uplink, and the pre-NAT Service address belongs to that uplink.
		workloadLeg, clientLeg := calicoCTLegAOffset, calicoCTLegBOffset
		if direction == 1 {
			workloadLeg, clientLeg = clientLeg, workloadLeg
		}
		wf := nl.NativeEndian().Uint32(value[workloadLeg+calicoCTLegFlagsOffset:])
		cf := nl.NativeEndian().Uint32(value[clientLeg+calicoCTLegFlagsOffset:])
		if wf&calicoCTLegFlagMask == calicoCTLegFlagPodOpen {
			return calicoTunnel
		}
		if wf&calicoCTLegFlagMask != calicoCTLegFlagWorkload || cf&calicoCTLegFlagMask != calicoCTLegFlagPeerOpen {
			return calicoUnclassified
		}
		wi := nl.NativeEndian().Uint32(value[workloadLeg+calicoCTLegIfidxOffset:])
		ci := nl.NativeEndian().Uint32(value[clientLeg+calicoCTLegIfidxOffset:])
		if f.input == 0 || wi != f.input {
			return calicoUnclassified
		}
		original := calicoCTOrigBaseOffset + length
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

	fallbackMu        sync.Mutex
	fallbackGen       uint64
	fallbackWorkloads map[int]bool
	fallbackUplinks   map[int][]netip.Addr
}

func (s serviceForwardScope) matchesCalicoInterfaces(workloadIndex, clientIndex int, originalIP netip.Addr) bool {
	if topology := s.calico; topology != nil {
		current := topology.version.Load()
		if current == topology.generation {
			return topology.workloads[workloadIndex] != "" && slices.Contains(topology.uplinks[clientIndex], originalIP)
		}
		// Cache fallback interface queries per topology version so a packet burst
		// during a route refresh does not issue repeated netlink dumps per packet.
		return topology.matchFallback(current, s.uplinks, workloadIndex, clientIndex, originalIP)
	}
	return matchCalicoInterfacesLive(s.uplinks, workloadIndex, clientIndex, originalIP)
}

func (t *calicoTopology) matchFallback(current uint64, uplinks []string, workloadIndex, clientIndex int, originalIP netip.Addr) bool {
	t.fallbackMu.Lock()
	defer t.fallbackMu.Unlock()
	if t.fallbackGen != current || t.fallbackWorkloads == nil {
		t.fallbackGen = current
		t.fallbackWorkloads = make(map[int]bool)
		t.fallbackUplinks = make(map[int][]netip.Addr)
	}
	isWorkload, ok := t.fallbackWorkloads[workloadIndex]
	if !ok {
		workload, err := net.InterfaceByIndex(workloadIndex)
		isWorkload = err == nil && len(workload.Name) >= 4 && workload.Name[:4] == "cali"
		t.fallbackWorkloads[workloadIndex] = isWorkload
	}
	if !isWorkload {
		return false
	}
	addrs, ok := t.fallbackUplinks[clientIndex]
	if !ok {
		client, err := net.InterfaceByIndex(clientIndex)
		if err == nil && slices.Contains(uplinks, client.Name) {
			if rawAddrs, err := client.Addrs(); err == nil {
				for _, address := range rawAddrs {
					if prefix, err := netip.ParsePrefix(address.String()); err == nil {
						addrs = append(addrs, prefix.Addr().Unmap())
					}
				}
			}
		}
		t.fallbackUplinks[clientIndex] = addrs
	}
	return slices.Contains(addrs, originalIP)
}

func matchCalicoInterfacesLive(uplinks []string, workloadIndex, clientIndex int, originalIP netip.Addr) bool {
	workload, err := net.InterfaceByIndex(workloadIndex)
	if err != nil || len(workload.Name) < 4 || workload.Name[:4] != "cali" {
		return false
	}
	client, err := net.InterfaceByIndex(clientIndex)
	if err != nil || !slices.Contains(uplinks, client.Name) {
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
