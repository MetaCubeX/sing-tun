package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// Raw packet devices must remain unframed even when tests run on Darwin.
type mipRawDevice struct {
	device              *mipTestTun
	failRead, failWrite atomic.Bool
	writes              chan struct{}
}

func newMIPRawDevice() *mipRawDevice {
	return &mipRawDevice{device: newMIPTestTun(), writes: make(chan struct{}, 16)}
}

func (d *mipRawDevice) Read(p []byte) (int, error) {
	if d.failRead.Swap(false) {
		return 0, errors.New("temporary read failure")
	}
	select {
	case packet := <-d.device.in:
		return copy(p, packet), nil
	case <-d.device.done:
		return 0, net.ErrClosed
	}
}
func (d *mipRawDevice) Write(p []byte) (int, error) {
	d.writes <- struct{}{}
	if d.failWrite.Swap(false) {
		return 0, errors.New("temporary write failure")
	}
	select {
	case d.device.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.device.done:
		return 0, net.ErrClosed
	}
}
func (d *mipRawDevice) Close() error { return d.device.Close() }

type mipWindowsDevice struct {
	*mipRawDevice
	ringFull atomic.Bool
	released atomic.Int32
}

func (d *mipWindowsDevice) Read([]byte) (int, error) {
	return 0, errors.New("Windows must use ReadPacket")
}
func (d *mipWindowsDevice) ReadPacket() ([]byte, func(), error) {
	select {
	case p := <-d.device.in:
		return p, func() {
			d.released.Add(1)
			for i := range p {
				p[i] = 0xa5
			}
		}, nil
	case <-d.device.done:
		return nil, nil, net.ErrClosed
	}
}
func (d *mipWindowsDevice) Write(p []byte) (int, error) {
	if d.ringFull.Swap(false) {
		d.writes <- struct{}{}
		return 0, nil
	}
	return d.mipRawDevice.Write(p)
}

type mipDarwinDevice struct {
	*mipRawDevice
	batchReads atomic.Int32
}

func (d *mipDarwinDevice) Read([]byte) (int, error) {
	return 0, errors.New("Darwin must use BatchRead")
}
func (d *mipDarwinDevice) BatchRead() ([]*buf.Buffer, error) {
	select {
	case p := <-d.device.in:
		d.batchReads.Add(1)
		return []*buf.Buffer{buf.As(p).ToOwned()}, nil
	case <-d.device.done:
		return nil, net.ErrClosed
	}
}
func (d *mipDarwinDevice) BatchWrite([]*buf.Buffer) error {
	return errors.New("shared Darwin batch descriptors must not be used")
}
func (d *mipDarwinDevice) Write(p []byte) (int, error) {
	if len(p) < 5 {
		return 0, errors.New("missing utun header")
	}
	family := uint32(2)
	if p[4]>>4 == 6 {
		family = 30
	}
	if binary.BigEndian.Uint32(p[:4]) != family {
		return 0, errors.New("wrong utun family")
	}
	n, err := d.mipRawDevice.Write(p[4:])
	if err != nil {
		return n, err
	}
	return n + 4, nil
}

func mipEchoHandler(t *testing.T) *mipTestHandler {
	return &mipTestHandler{udp: func(_ context.Context, _ netip.AddrPort, p *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
		defer p.Release()
		if err := init(nil).WritePacket(buf.As(p.Bytes()).ToOwned(), m.Destination); err != nil {
			t.Error(err)
		}
	}}
}

func TestMIPStackPlatformRecovery(t *testing.T) {
	for _, kind := range []string{"raw", "windows", "darwin"} {
		t.Run(kind, func(t *testing.T) {
			raw := newMIPRawDevice()
			var device Tun = raw
			var win *mipWindowsDevice
			var darwin *mipDarwinDevice
			if kind == "windows" {
				win = &mipWindowsDevice{mipRawDevice: raw}
				win.ringFull.Store(true)
				device = win
			} else {
				raw.failWrite.Store(true)
			}
			if kind == "darwin" {
				darwin = &mipDarwinDevice{mipRawDevice: raw}
				device = darwin
			}
			if kind == "raw" {
				raw.failRead.Store(true)
			}
			o := mipTestOptions(device, mipEchoHandler(t))
			o.TunOptions.EXP_RecvMsgX = true
			s, err := NewStack("mipstack", o)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { device.Close(); s.Close() })
			if err = s.Start(); err != nil {
				t.Fatal(err)
			}
			src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10")
			packet := mipTestPacket(src, dst, 17, []byte{0x30, 0x39, 0, 53, 0, 12, 0, 0, 't', 'e', 's', 't'})
			raw.device.in <- append([]byte(nil), packet...)
			mipReceive(t, raw.writes)
			raw.device.in <- append([]byte(nil), packet...)
			reply := mipReceive(t, raw.device.out)
			if !bytes.Equal(reply[28:], []byte("test")) {
				t.Fatal("invalid recovered reply")
			}
			if win != nil && win.released.Load() != 2 {
				t.Fatal("Windows receive buffers not released")
			}
			if darwin != nil && darwin.batchReads.Load() != 2 {
				t.Fatal("Darwin batch path not used")
			}
			device.Close()
			select {
			case <-s.(*MIPStack).ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("device close did not stop stack")
			}
		})
	}
}

func TestMIPStackExternalAddressConfiguration(t *testing.T) {
	for _, configuration := range []string{"none", "ipv4", "ipv6"} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(configuration+map[bool]string{false: "/IPv4", true: "/IPv6"}[ipv6], func(t *testing.T) {
				d := newMIPRawDevice()
				o := mipTestOptions(d, mipEchoHandler(t))
				if configuration == "none" {
					o.TunOptions.MTU = 0
				}
				if configuration != "ipv4" {
					o.TunOptions.Inet4Address = nil
				}
				if configuration != "ipv6" {
					o.TunOptions.Inet6Address = nil
				}
				s, err := NewStack("mipstack", o)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { d.Close(); s.Close() })
				if err = s.Start(); err != nil {
					t.Fatal(err)
				}
				src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10")
				offset := 20
				if ipv6 {
					src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::10")
					offset = 40
				}
				d.device.in <- mipTestPacket(src, dst, 17, []byte{0x30, 0x39, 0, 53, 0, 12, 0, 0, 't', 'e', 's', 't'})
				p := mipReceive(t, d.device.out)
				if string(p[offset+8:]) != "test" {
					t.Fatal("family not available")
				}
			})
		}
	}
}

func TestMIPStackLoopbackChecksumValidation(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		src, dst := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("10.0.0.1")
		if ipv6 {
			src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::9")
		}
		s := &MIPStack{loopback: map[netip.Addr]struct{}{dst: {}}}
		p := mipTestTCPPacket(src, dst, []byte("payload"))
		p[len(p)-1] ^= 1
		before := append([]byte(nil), p...)
		if s.reflectLoopback(p) || !bytes.Equal(p, before) {
			t.Fatal("corrupt TCP packet reflected or modified")
		}
	}
}

func TestMIPStackMTUAndUnknownProtocol(t *testing.T) {
	d := newMIPRawDevice()
	o := mipTestOptions(d, &mipTestHandler{})
	o.TunOptions.Inet4Address = nil
	o.TunOptions.Inet6Address = nil
	o.TunOptions.MTU = 576
	stack, err := NewMIPStack(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close(); stack.Close() })
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	d.device.in <- mipTestPacket(netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10"), 253, make([]byte, 8))
	p := mipReceive(t, d.device.out)
	if p[20] != 3 || p[21] != 2 {
		t.Fatal("unknown protocol did not return protocol unreachable")
	}
	o.TunOptions.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}
	if s, err := NewMIPStack(o); err == nil {
		s.Close()
		t.Fatal("IPv6 below minimum MTU accepted")
	}
}

func TestMIPStackICMPFailedRouteCleanup(t *testing.T) {
	route := &mipTestRoute{packets: make(chan *buf.Buffer, 1)}
	h := &mipTestHandler{icmp: func(string, M.Socksaddr, M.Socksaddr, DirectRouteContext, time.Duration) (DirectRouteDestination, error) {
		return route, ErrDrop
	}}
	d := newMIPRawDevice()
	stack, err := NewMIPStack(mipTestOptions(d, h))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	packet := mipTestPacket(netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10"), 1, []byte{8, 0, 0, 0, 0, 1, 0, 2})
	if _, err = stack.(*MIPStack).stack.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	if !route.IsClosed() {
		t.Fatal("failed PrepareConnection leaked route")
	}
}
