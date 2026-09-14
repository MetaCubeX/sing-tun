package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type mipOffloadInput struct {
	packet  []byte
	options GSOOptions
}

// Model the LinuxTUN boundary on every host: GSOSplit is the same platform-
// independent implementation called by NativeTun after decoding virtio headers.
type mipBatchTestTun struct {
	*mipTestTun
	input    chan mipOffloadInput
	headroom int
	batch    int
	reads    atomic.Int32
	writes   atomic.Int32
}

func newMIPBatchTestTun(headroom int) *mipBatchTestTun {
	return &mipBatchTestTun{mipTestTun: newMIPTestTun(), input: make(chan mipOffloadInput, 8), headroom: headroom, batch: 8}
}

func (tun *mipBatchTestTun) FrontHeadroom() int      { return tun.headroom }
func (tun *mipBatchTestTun) BatchSize() int          { return tun.batch }
func (tun *mipBatchTestTun) TXChecksumOffload() bool { return true }
func (tun *mipBatchTestTun) Read([]byte) (int, error) {
	return 0, errors.New("offload TUN used plain Read")
}
func (tun *mipBatchTestTun) Write([]byte) (int, error) {
	return 0, errors.New("offload TUN used plain Write")
}

func (tun *mipBatchTestTun) BatchRead(packets [][]byte, offset int, sizes []int) (int, error) {
	if offset != tun.headroom || len(packets) != tun.batch {
		return 0, errors.New("incorrect batch read layout")
	}
	select {
	case input := <-tun.input:
		tun.reads.Add(1)
		return GSOSplit(input.packet, input.options, packets, sizes, offset)
	case <-tun.done:
		return 0, net.ErrClosed
	}
}

func (tun *mipBatchTestTun) BatchWrite(packets [][]byte, offset int) (int, error) {
	if offset != tun.headroom || len(packets) > tun.batch {
		return 0, errors.New("incorrect batch write layout")
	}
	tun.writes.Add(1)
	total := 0
	for i, p := range packets {
		if len(p) <= offset {
			return total, io.ErrShortBuffer
		}
		select {
		case tun.out <- append([]byte(nil), p[offset:]...):
		case <-tun.done:
			return total, net.ErrClosed
		}
		total += len(p)
		// Native GRO mutates both bytes and slice lengths. The next stack
		// read must restore capacity instead of using these shortened slices.
		for j := range p {
			p[j] = 0xa5
		}
		packets[i] = p[:offset]
	}
	return total, nil // Linux returns bytes, not packets.
}

func mipTestPseudo(src, dst netip.Addr, protocol byte, length int) []byte {
	p := append(append([]byte(nil), src.AsSlice()...), dst.AsSlice()...)
	if src.Is4() {
		return append(p, 0, protocol, byte(length>>8), byte(length))
	}
	return append(p, 0, 0, byte(length>>8), byte(length), 0, 0, 0, protocol)
}

func mipTestTCPPacket(src, dst netip.Addr, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp, 12345)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 100)
	tcp[12], tcp[13] = 0x50, 0x18
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:], mipChecksum(append(mipTestPseudo(src, dst, 6, len(tcp)), tcp...)))
	// mipTestPacket's transport checksum helper handles UDP/ICMP; replace
	// its transport bytes with the independently checksummed TCP segment.
	p := mipTestPacket(src, dst, 6, tcp)
	copy(p[len(p)-len(tcp):], tcp)
	return p
}

func mipCheckTCP(t *testing.T, p []byte) {
	t.Helper()
	offset := 20
	src, _ := netip.AddrFromSlice(p[12:16])
	dst, _ := netip.AddrFromSlice(p[16:20])
	if p[0]>>4 == 6 {
		offset = 40
		src, _ = netip.AddrFromSlice(p[8:24])
		dst, _ = netip.AddrFromSlice(p[24:40])
	} else if mipChecksum(p[:20]) != 0 {
		t.Fatal("invalid IPv4 checksum")
	}
	if mipChecksum(append(mipTestPseudo(src, dst, 6, len(p)-offset), p[offset:]...)) != 0 {
		t.Fatal("invalid TCP checksum")
	}
}

func TestMIPStackBatchUDP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, headroom := range []int{0, 10} {
			t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6]+map[int]string{0: "/batch", 10: "/virtio"}[headroom], func(t *testing.T) {
				src, dst := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("198.51.100.10")
				ipLen := 20
				if ipv6 {
					src, dst = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::10")
					ipLen = 40
				}
				tun := newMIPBatchTestTun(headroom)
				payloads := make(chan string, 8)
				h := &mipTestHandler{udp: func(_ context.Context, _ netip.AddrPort, p *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
					defer p.Release()
					payloads <- string(p.Bytes())
					if err := init(nil).WritePacket(buf.As(p.Bytes()).ToOwned(), m.Destination); err != nil {
						t.Error(err)
					}
				}}
				o := mipTestOptions(tun, h)
				o.TunOptions.GSO = true
				o.TunOptions._TXChecksumOffload = true
				s, err := NewMIPStack(o)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { tun.Close(); s.Close() })
				if err = s.Start(); err != nil {
					t.Fatal(err)
				}
				udp := append([]byte{0x30, 0x39, 0, 53, 0, 18, 0, 0}, []byte("abcdefghij")...)
				tun.input <- mipOffloadInput{packet: mipTestPacket(src, dst, 17, udp), options: GSOOptions{GSOType: GSOUDPL4, HdrLen: uint16(ipLen + 8), CsumStart: uint16(ipLen), CsumOffset: 6, GSOSize: 4, NeedsCsum: true}}
				for _, want := range []string{"abcd", "efgh", "ij"} {
					if got := mipReceive(t, payloads); got != want {
						t.Fatalf("split payload %q, want %q", got, want)
					}
					p := mipReceive(t, tun.out)
					if string(p[ipLen+8:]) != want {
						t.Fatalf("bad batch reply: %x", p)
					}
					if mipChecksum(append(mipTestPseudo(dst, src, 17, len(p)-ipLen), p[ipLen:]...)) != 0 {
						t.Fatal("invalid UDP reply checksum")
					}
				}
				// NEEDS_CSUM without segmentation must be completed before mipstack
				// sees it. Send a larger second datagram to exercise buffer restoration.
				udp = append([]byte{0x30, 0x39, 0, 53, 0, 40, 0, 0}, bytes.Repeat([]byte{'z'}, 32)...)
				p := mipTestPacket(src, dst, 17, udp)
				binary.BigEndian.PutUint16(p[ipLen+6:], ^mipChecksum(mipTestPseudo(src, dst, 17, len(udp))))
				tun.input <- mipOffloadInput{packet: p, options: GSOOptions{GSOType: GSONone, CsumStart: uint16(ipLen), CsumOffset: 6, NeedsCsum: true}}
				if got := mipReceive(t, payloads); got != string(udp[8:]) {
					t.Fatalf("partial checksum packet: %q", got)
				}
				if p = mipReceive(t, tun.out); !bytes.Equal(p[ipLen+8:], udp[8:]) {
					t.Fatal("reused output buffer truncated UDP")
				}
				if tun.reads.Load() != 2 || tun.writes.Load() == 0 {
					t.Fatal("batch path was not exercised")
				}
			})
		}
	}
}

func TestMIPStackGSOLoopback(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			src, dst := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("10.0.0.1")
			ipLen, kind := 20, GSOTCPv4
			if ipv6 {
				src, dst = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::9")
				ipLen, kind = 40, GSOTCPv6
			}
			tun := newMIPBatchTestTun(10)
			o := mipTestOptions(tun, &mipTestHandler{tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
				c.Close()
				t.Error("loopback reached TCP handler")
				return nil
			}})
			o.TunOptions.GSO = true
			o.TunOptions._TXChecksumOffload = true
			if ipv6 {
				o.TunOptions.Inet6LoopbackAddress = []netip.Addr{dst}
			} else {
				o.TunOptions.Inet4LoopbackAddress = []netip.Addr{dst}
			}
			s, err := NewMIPStack(o)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tun.Close(); s.Close() })
			if err = s.Start(); err != nil {
				t.Fatal(err)
			}
			tun.input <- mipOffloadInput{packet: mipTestTCPPacket(src, dst, []byte("abcdefghij")), options: GSOOptions{GSOType: kind, HdrLen: uint16(ipLen + 20), CsumStart: uint16(ipLen), CsumOffset: 16, GSOSize: 4, NeedsCsum: true}}
			for i, want := range []string{"abcd", "efgh", "ij"} {
				p := mipReceive(t, tun.out)
				mipCheckTCP(t, p)
				expected := mipTestTCPPacket(dst, src, []byte(want))
				srcOffset, addrLen := 12, 4
				if ipv6 {
					srcOffset, addrLen = 8, 16
				}
				if !bytes.Equal(p[srcOffset:srcOffset+2*addrLen], expected[srcOffset:srcOffset+2*addrLen]) {
					t.Fatal("loopback IP addresses were not swapped")
				}
				if binary.BigEndian.Uint16(p[ipLen:]) != 12345 || binary.BigEndian.Uint16(p[ipLen+2:]) != 443 {
					t.Fatal("loopback changed TCP ports")
				}
				if string(p[ipLen+20:]) != want || binary.BigEndian.Uint32(p[ipLen+4:]) != 100+uint32(i*4) {
					t.Fatal("incorrect TCP segmentation")
				}
				if i < 2 && p[ipLen+13]&8 != 0 {
					t.Fatal("PSH retained on intermediate segment")
				}
			}
		})
	}
}

func TestMIPStackLoopbackPackets(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			src, dst := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("10.0.0.1")
			if ipv6 {
				src, dst = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::9")
			}
			s := &MIPStack{loopback: map[netip.Addr]struct{}{dst: {}}}
			packet := mipTestTCPPacket(src, dst, []byte("data"))
			original := append([]byte(nil), packet...)
			if !s.reflectLoopback(packet) {
				t.Fatal("TCP loopback not intercepted")
			}
			mipCheckTCP(t, packet)
			offset := 20
			if ipv6 {
				offset = 40
			}
			if !bytes.Equal(packet[offset:], original[offset:]) {
				t.Fatal("loopback changed TCP bytes")
			}
			if ipv6 {
				// Hop-by-Hop options followed by a non-initial TCP fragment.
				packet = append(append(append([]byte(nil), original[:40]...), []byte{44, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 8, 0, 0, 0, 1}...), []byte("fragment")...)
				packet[6] = 0
				binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
			} else {
				packet = append(append([]byte(nil), original[:20]...), []byte("fragment")...)
				binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
				binary.BigEndian.PutUint16(packet[6:], 1)
				packet[10], packet[11] = 0, 0
				binary.BigEndian.PutUint16(packet[10:], mipChecksum(packet[:20]))
			}
			if !s.reflectLoopback(packet) {
				t.Fatal("non-initial TCP fragment not reflected")
			}
			for i := 0; i < len(original); i++ {
				p := append([]byte(nil), original[:i]...)
				if s.reflectLoopback(p) {
					t.Fatalf("truncated packet length %d was reflected", i)
				}
			}
			udp := mipTestPacket(src, dst, 17, []byte{0, 1, 0, 2, 0, 8, 0, 0})
			if s.reflectLoopback(udp) {
				t.Fatal("UDP treated as TCP loopback")
			}
		})
	}
}

// A plain NativeTun implements LinuxTUN too, but its BatchRead is only usable
// after virtio offload has been enabled. TX checksum offload alone is not a
// reason to select that path.
type mipPlainLinuxTestTun struct{ *mipTestTun }

func (*mipPlainLinuxTestTun) FrontHeadroom() int      { return 0 }
func (*mipPlainLinuxTestTun) BatchSize() int          { return 1 }
func (*mipPlainLinuxTestTun) TXChecksumOffload() bool { return true }
func (*mipPlainLinuxTestTun) BatchRead([][]byte, int, []int) (int, error) {
	return 0, errors.New("plain TUN used BatchRead")
}
func (*mipPlainLinuxTestTun) BatchWrite([][]byte, int) (int, error) {
	return 0, errors.New("plain TUN used BatchWrite")
}

func TestMIPStackPlainLoopback(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			src, dst := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("10.0.0.1")
			if ipv6 {
				src, dst = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::9")
			}
			tun := &mipPlainLinuxTestTun{newMIPTestTun()}
			o := mipTestOptions(tun, &mipTestHandler{})
			o.TunOptions._TXChecksumOffload = true
			if ipv6 {
				o.TunOptions.Inet6LoopbackAddress = []netip.Addr{dst}
			} else {
				o.TunOptions.Inet4LoopbackAddress = []netip.Addr{dst}
			}
			s, err := NewMIPStack(o)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { tun.Close(); s.Close() })
			if err = s.Start(); err != nil {
				t.Fatal(err)
			}
			tun.in <- mipTestTCPPacket(src, dst, []byte("loopback"))
			p := mipReceive(t, tun.out)
			if !bytes.Equal(p, mipTestTCPPacket(dst, src, []byte("loopback"))) {
				t.Fatal("incorrect plain loopback packet")
			}
		})
	}
}

func TestMIPStackSegmentOverflow(t *testing.T) {
	tun := newMIPBatchTestTun(10)
	tun.batch = 2
	src, dst := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("198.51.100.10")
	payloads := make(chan string, 4)
	h := &mipTestHandler{udp: func(_ context.Context, _ netip.AddrPort, p *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
		defer p.Release()
		payloads <- string(p.Bytes())
	}}
	s, err := NewMIPStack(mipTestOptions(tun, h))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tun.Close(); s.Close() })
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	udp := append([]byte{0x30, 0x39, 0, 53, 0, 18, 0, 0}, []byte("abcdefghij")...)
	tun.input <- mipOffloadInput{packet: mipTestPacket(src, dst, 17, udp), options: GSOOptions{GSOType: GSOUDPL4, HdrLen: 28, CsumStart: 20, CsumOffset: 6, GSOSize: 4, NeedsCsum: true}}
	if got := mipReceive(t, payloads); got != "abcd" {
		t.Fatalf("split prefix: %q", got)
	}
	udp = append([]byte{0x30, 0x39, 0, 53, 0, 12, 0, 0}, []byte("next")...)
	tun.input <- mipOffloadInput{packet: mipTestPacket(src, dst, 17, udp)}
	if got := mipReceive(t, payloads); got != "next" {
		t.Fatalf("traffic after segment overflow: %q", got)
	}
}

func (t *mipPlainLinuxTestTun) Read(p []byte) (int, error) {
	select {
	case packet := <-t.in:
		return copy(p, packet), nil
	case <-t.done:
		return 0, net.ErrClosed
	}
}
func (t *mipPlainLinuxTestTun) Write(p []byte) (int, error) {
	select {
	case t.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-t.done:
		return 0, net.ErrClosed
	}
}
