//go:build darwin && with_mipstack

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"golang.org/x/sys/unix"
)

// Use NativeTun's actual os.File I/O with a nonblocking packet descriptor,
// including utun's four-byte framing, without changing the host's routes.
func TestMIPStackDarwinInterfaceSourceFD(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, fd := range fds {
				if err = unix.SetNonblock(fd, true); err != nil {
					unix.Close(fds[0])
					unix.Close(fds[1])
					t.Fatal(err)
				}
			}
			device := os.NewFile(uintptr(fds[0]), "mipstack-utun-test")
			peer := os.NewFile(uintptr(fds[1]), "mipstack-host-test")
			defer device.Close()
			defer peer.Close()
			if err = peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			source, destination := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10")
			if ipv6 {
				source, destination = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::10")
			}
			h := &mipTestHandler{
				udp: func(_ context.Context, _ netip.AddrPort, p *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
					defer p.Release()
					if metadata.Source.Addr != source {
						t.Error("host source address changed")
					}
					if err := init(nil).WritePacket(buf.As(p.Bytes()).ToOwned(), metadata.Destination); err != nil {
						t.Error(err)
					}
				},
				icmp: func(string, M.Socksaddr, M.Socksaddr, DirectRouteContext, time.Duration) (DirectRouteDestination, error) {
					t.Error("interface echo should not enter route handler")
					return nil, ErrDrop
				},
			}
			options := mipTestOptions(&NativeTun{tunFd: fds[0], tunFile: device}, h)
			options.TunOptions.FileDescriptor = fds[0]
			options.TunOptions.Inet4Address, options.TunOptions.Inet6Address = nil, nil
			prefix := netip.PrefixFrom(source, source.BitLen())
			if ipv6 {
				options.TunOptions.Inet6Address = []netip.Prefix{prefix}
			} else {
				options.TunOptions.Inet4Address = []netip.Prefix{prefix}
			}
			stack, err := NewMIPStack(options)
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			readPacket := func() []byte {
				p := make([]byte, 65539)
				n, err := peer.Read(p)
				if err != nil {
					t.Fatal(err)
				}
				family := uint32(unix.AF_INET)
				if ipv6 {
					family = unix.AF_INET6
				}
				if n < 4 || binary.BigEndian.Uint32(p[:4]) != family {
					t.Fatal("invalid utun framing")
				}
				return p[4:n]
			}
			udp := []byte{0x30, 0x39, 0, 53, 0, 12, 0, 0, 't', 'e', 's', 't'}
			if _, err = peer.Write(mipTestFrame(mipTestPacket(source, destination, 17, udp))); err != nil {
				t.Fatal(err)
			}
			p := readPacket()
			src, dst, ok := mipPacketAddresses(p)
			if !ok || src != destination || dst != source {
				t.Fatalf("wrong UDP reply addresses: %v -> %v", src, dst)
			}
			offset := 20
			if ipv6 {
				offset = 40
			}
			if !bytes.Equal(p[offset+8:], []byte("test")) {
				t.Fatal("wrong UDP payload")
			}
			protocol, requestType, replyType := byte(1), byte(8), byte(0)
			if ipv6 {
				protocol, requestType, replyType = 58, 128, 129
			}
			// The /32 or /128 interface must still answer echo without being
			// classified as a directed broadcast or as MIPS local delivery.
			echo := []byte{requestType, 0, 0, 0, 0, 1, 0, 2}
			if _, err = peer.Write(mipTestFrame(mipTestPacket(source, source, protocol, echo))); err != nil {
				t.Fatal(err)
			}
			p = readPacket()
			if p[offset] != replyType {
				t.Fatalf("interface echo type: %d", p[offset])
			}
			if n := stack.(*MIPStack).stack.Stats().LoopbackPackets; n != 0 {
				t.Fatalf("host replies leaked into internal loopback: %d", n)
			}
		})
	}
}
