//go:build linux

package tun

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"golang.org/x/sys/unix"
)

// Exercise NativeTun's actual virtio decoder, GSOSplit and GRO writer without
// creating a privileged kernel TUN. Datagram sockets preserve packet boundaries.
func TestMIPStackNativeLinuxOffload(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	device := os.NewFile(uintptr(fds[0]), "mipstack-device")
	peer := os.NewFile(uintptr(fds[1]), "mipstack-peer")
	defer device.Close()
	defer peer.Close()
	if err = peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	tun := &NativeTun{tunFile: device, vnetHdr: true, txChecksumOffload: true,
		writeBuffer: make([]byte, gsoMaxSize+virtioNetHdrLen), tcpGROTable: newTCPGROTable(), udpGROTable: newUDPGROTable()}
	src, dst := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("198.51.100.10")
	h := &mipTestHandler{udp: func(_ context.Context, _ netip.AddrPort, p *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
		defer p.Release()
		if err := init(nil).WritePacket(buf.As(p.Bytes()).ToOwned(), m.Destination); err != nil {
			t.Error(err)
		}
	}}
	options := mipTestOptions(tun, h)
	options.TunOptions.GSO = true
	options.TunOptions._TXChecksumOffload = true
	stack, err := NewMIPStack(options)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	udp := append([]byte{0x30, 0x39, 0, 53, 0, 18, 0, 0}, []byte("abcdefghij")...)
	packet := mipTestPacket(src, dst, 17, udp)
	frame := make([]byte, virtioNetHdrLen+len(packet))
	hdr := virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, gsoType: unix.VIRTIO_NET_HDR_GSO_UDP_L4, hdrLen: 28, gsoSize: 4, csumStart: 20, csumOffset: 6}
	if err = hdr.encode(frame); err != nil {
		t.Fatal(err)
	}
	copy(frame[virtioNetHdrLen:], packet)
	if _, err = peer.Write(frame); err != nil {
		t.Fatal(err)
	}
	frames := make([]byte, gsoMaxSize+virtioNetHdrLen)
	packets := make([][]byte, idealBatchSize)
	sizes := make([]int, len(packets))
	for i := range packets {
		packets[i] = make([]byte, gsoMaxSize)
	}
	var got []byte
	for len(got) < 10 {
		n, err := peer.Read(frames)
		if err != nil {
			t.Fatal(err)
		}
		count, err := handleVirtioRead(frames[:n], packets, sizes, 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			p := packets[i][:sizes[i]]
			if mipChecksum(append(mipTestPseudo(dst, src, 17, len(p)-20), p[20:]...)) != 0 {
				t.Fatal("invalid native offload UDP checksum")
			}
			got = append(got, p[28:]...)
		}
	}
	if !bytes.Equal(got, []byte("abcdefghij")) {
		t.Fatalf("native offload round trip: %q", got)
	}
}
