package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/exp/slices"
)

// Frozen helper from e454d9c (unchanged since a128d0c); both paths share the unchanged GRO implementation.
func controlHandleGRO(bufs [][]byte, offset int, tcpTable *tcpGROTable, udpTable *udpGROTable, gro groDisablementFlags, skipChecksumValidation bool, toWrite *[]int) error {
	for i := range bufs {
		if offset < virtioNetHdrLen || offset > len(bufs[i])-1 {
			return errors.New("invalid offset")
		}
		var result groResult
		switch packetIsGROCandidate(bufs[i][offset:], gro) {
		case tcp4GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, false, skipChecksumValidation)
		case tcp6GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, true, skipChecksumValidation)
		case udp4GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, false, skipChecksumValidation)
		case udp6GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, true, skipChecksumValidation)
		}
		switch result {
		case groResultNoop:
			hdr := virtioNetHdr{}
			err := hdr.encode(bufs[i][offset-virtioNetHdrLen:])
			if err != nil {
				return err
			}
			fallthrough
		case groResultTableInsert:
			*toWrite = append(*toWrite, i)
		}
	}
	errTCP := applyTCPCoalesceAccounting(bufs, offset, tcpTable)
	errUDP := applyUDPCoalesceAccounting(bufs, offset, udpTable)
	return errors.Join(errTCP, errUDP)
}

func groPackets(ipv6, udp bool, n, payload int) [][]byte {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")
	if ipv6 {
		src, dst = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	}
	out := make([][]byte, n)
	for i := range out {
		data := bytes.Repeat([]byte{byte(i + 1)}, payload)
		if udp {
			out[i] = udpPacket(src, dst, 53, data)
		} else {
			flags := byte(tcpFlagACK)
			if i == n-1 {
				flags |= tcpFlagPSH
			}
			out[i] = tcpPacket(src, dst, 100+uint32(i*payload), 1, flags, data)
		}
	}
	return out
}
func groBuffers(packets [][]byte) [][]byte {
	out := make([][]byte, len(packets))
	for i, p := range packets {
		out[i] = make([]byte, virtioNetHdrLen+len(p), 65536+virtioNetHdrLen)
		for j := 0; j < virtioNetHdrLen; j++ {
			out[i][j] = 0xa5
		}
		copy(out[i][virtioNetHdrLen:], p)
	}
	return out
}
func TestSingleGROEquivalence(t *testing.T) {
	tcpA, tcpB, udpA, udpB := newTCPGROTable(), newTCPGROTable(), newUDPGROTable(), newUDPGROTable()
	cases := 0
	check := func(packets [][]byte, offset int, flags groDisablementFlags, skip bool) {
		t.Helper()
		a, b := groBuffers(packets), groBuffers(packets)
		var wa, wb []int
		ea := controlHandleGRO(a, offset, tcpA, udpA, flags, skip, &wa)
		eb := handleGRO(b, offset, tcpB, udpB, flags, skip, &wb)
		if fmt.Sprint(ea) != fmt.Sprint(eb) || !slices.Equal(wa, wb) {
			t.Fatalf("offset=%d count=%d errors=%v/%v indices=%v/%v", offset, len(packets), ea, eb, wa, wb)
		}
		for i := range a {
			if !bytes.Equal(a[i], b[i]) {
				t.Fatalf("packet %d differs", i)
			}
		}
		tcpA.reset()
		tcpB.reset()
		udpA.reset()
		udpB.reset()
		cases++
	}
	for _, ipv6 := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			for _, n := range []int{1, 2, 3, 64, 1} { // reset/reuse after a coalesced batch
				for _, payload := range []int{0, 1, 64, 512} {
					for flags := groDisablementFlags(0); flags < 4; flags++ {
						for _, skip := range []bool{false, true} {
							check(groPackets(ipv6, udp, n, payload), virtioNetHdrLen, flags, skip)
						}
					}
				}
			}
			p := groPackets(ipv6, udp, 1, 64)[0]
			for _, offset := range []int{-1, 0, 9, 10, 13, 10 + len(p), 11 + len(p)} {
				check([][]byte{p}, offset, 0, false)
			}
			for i := range p {
				m := append([]byte(nil), p...)
				m[i] ^= 0xff
				check([][]byte{m}, 10, 0, false)
			}
			// IPv4 fragment/options and IPv6 extension header cases are noops,
			// with unchanged data and an explicitly cleared virtio header.
			m := append([]byte(nil), p...)
			if ipv6 {
				m[6] = 0
			} else {
				m[6] |= 0x20
			}
			check([][]byte{m}, 10, 0, false)
			if !ipv6 {
				m[0] = 0x46
				check([][]byte{m}, 10, 0, false)
			}
			if !udp {
				off := 20
				if ipv6 {
					off = 40
				}
				for _, f := range []byte{0x02, 0x12, 0x01, 0x04, 0x10, 0x18} {
					m = append([]byte(nil), p...)
					m[off+13] = f
					check([][]byte{m}, 10, 0, false)
				}
			}
		}
	}
	check(nil, 10, 0, false)
	for n := 0; n < 80; n++ {
		check([][]byte{bytes.Repeat([]byte{byte(n)}, n)}, 10, 0, false)
	}
	// Confirm a valid single packet clears stale GSO flags from earlier use.
	p := groBuffers(groPackets(false, false, 1, 64))
	var indices []int
	if err := handleGRO(p, 10, tcpB, udpB, 0, false, &indices); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[0][:10], make([]byte, 10)) || !slices.Equal(indices, []int{0}) {
		t.Fatal("stale virtio header")
	}
	t.Logf("GRO differential cases: %d", cases)
}
func BenchmarkGROPaths(b *testing.B) { benchmarkGROPaths(b, false) }

func BenchmarkGRONativePaths(b *testing.B) { benchmarkGROPaths(b, true) }

func benchmarkGROPaths(b *testing.B, skipChecksumValidation bool) {
	for _, n := range []int{1, 2, 64} {
		for _, udp := range []bool{false, true} {
			for _, candidate := range []bool{false, true} {
				b.Run(fmt.Sprintf("n%d_udp%v_candidate%v", n, udp, candidate), func(b *testing.B) {
					packets := groPackets(false, udp, n, 512)
					bufs := groBuffers(packets)
					tcp, ut := newTCPGROTable(), newUDPGROTable()
					indices := make([]int, 0, n)
					fn := controlHandleGRO
					if candidate {
						fn = handleGRO
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if n > 1 {
							for j, p := range packets {
								bufs[j] = bufs[j][:10+len(p)]
								copy(bufs[j][10:], p)
							}
						}
						indices = indices[:0]
						if err := fn(bufs, 10, tcp, ut, 0, skipChecksumValidation, &indices); err != nil {
							b.Fatal(err)
						}
						tcp.reset()
						ut.reset()
					}
				})
			}
		}
	}
}
