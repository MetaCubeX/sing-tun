//go:build with_mipstack

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mipstack"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type mipTestTun struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func newMIPTestTun() *mipTestTun {
	return &mipTestTun{in: make(chan []byte, 64), out: make(chan []byte, 64), done: make(chan struct{})}
}

func mipTestFrame(packet []byte) []byte {
	frame := make([]byte, PacketOffset+len(packet))
	copy(frame[PacketOffset:], packet)
	if PacketOffset > 0 {
		family := uint32(2)
		if packet[0]>>4 == 6 {
			family = 30
		}
		binary.BigEndian.PutUint32(frame, family)
	}
	return frame
}

func (tun *mipTestTun) Read(p []byte) (int, error) {
	select {
	case packet := <-tun.in:
		return copy(p, mipTestFrame(packet)), nil
	case <-tun.done:
		return 0, net.ErrClosed
	}
}

func (tun *mipTestTun) Write(p []byte) (int, error) {
	if len(p) <= PacketOffset {
		return 0, io.ErrShortBuffer
	}
	if PacketOffset > 0 {
		family := uint32(2)
		if p[PacketOffset]>>4 == 6 {
			family = 30
		}
		if binary.BigEndian.Uint32(p[:PacketOffset]) != family {
			return 0, errors.New("invalid utun header")
		}
	}
	select {
	case tun.out <- append([]byte(nil), p[PacketOffset:]...):
		return len(p), nil
	case <-tun.done:
		return 0, net.ErrClosed
	}
}

func (tun *mipTestTun) Close() error { tun.once.Do(func() { close(tun.done) }); return nil }

type mipTestHandler struct {
	Handler
	tcp  func(context.Context, net.Conn, M.Metadata) error
	udp  func(context.Context, netip.AddrPort, *buf.Buffer, M.Metadata, func(N.PacketConn) N.PacketWriter)
	icmp func(string, M.Socksaddr, M.Socksaddr, DirectRouteContext, time.Duration) (DirectRouteDestination, error)
}

func (h *mipTestHandler) NewConnection(ctx context.Context, c net.Conn, m M.Metadata) error {
	return h.tcp(ctx, c, m)
}
func (h *mipTestHandler) NewPacket(ctx context.Context, key netip.AddrPort, p *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	h.udp(ctx, key, p, m, init)
}
func (h *mipTestHandler) PrepareConnection(n string, src, dst M.Socksaddr, w DirectRouteContext, timeout time.Duration) (DirectRouteDestination, error) {
	return h.icmp(n, src, dst, w, timeout)
}

func mipTestOptions(tun Tun, h Handler) StackOptions {
	return StackOptions{Context: context.Background(), Tun: tun, Handler: h, ICMPTimeout: time.Minute,
		TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/64")}}}
}

func startMIPTestStack(t *testing.T, h Handler) (*MIPStack, *mipTestTun) {
	t.Helper()
	tun := newMIPTestTun()
	stack, err := NewStack("mipstack", mipTestOptions(tun, h))
	if err != nil {
		t.Fatal(err)
	}
	s := stack.(*MIPStack)
	t.Cleanup(func() { tun.Close(); s.Close() })
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	return s, tun
}

func mipReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for packet or handler")
		var zero T
		return zero
	}
}

func mipChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) != 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + sum>>16
	}
	return ^uint16(sum)
}

// Build independent wire packets so adapter tests also exercise validation
// and checksums rather than calling the forwarders directly.
func mipTestPacket(src, dst netip.Addr, protocol byte, payload []byte) []byte {
	payload = append([]byte(nil), payload...)
	checksumOffset := 2
	if protocol == 17 {
		checksumOffset = 6
	}
	if protocol == 17 || protocol == 58 {
		pseudo := append(append([]byte(nil), src.AsSlice()...), dst.AsSlice()...)
		if src.Is4() {
			pseudo = append(pseudo, 0, protocol, byte(len(payload)>>8), byte(len(payload)))
		} else {
			pseudo = append(pseudo, 0, 0, byte(len(payload)>>8), byte(len(payload)), 0, 0, 0, protocol)
		}
		sum := mipChecksum(append(pseudo, payload...))
		if sum == 0 {
			sum = 65535
		}
		binary.BigEndian.PutUint16(payload[checksumOffset:], sum)
	} else {
		binary.BigEndian.PutUint16(payload[checksumOffset:], mipChecksum(payload))
	}
	if src.Is4() {
		p := make([]byte, 20+len(payload))
		p[0] = 0x45
		p[8] = 64
		p[9] = protocol
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		copy(p[12:16], src.AsSlice())
		copy(p[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(p[10:], mipChecksum(p[:20]))
		copy(p[20:], payload)
		return p
	}
	p := make([]byte, 40+len(payload))
	p[0] = 0x60
	p[6] = protocol
	p[7] = 64
	binary.BigEndian.PutUint16(p[4:], uint16(len(payload)))
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	copy(p[40:], payload)
	return p
}

func TestMIPStackUDP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			src, dst, reply := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("203.0.113.20")
			if ipv6 {
				src, dst, reply = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::20")
			}
			type received struct {
				packet   *buf.Buffer
				metadata M.Metadata
				writer   N.PacketWriter
				key      netip.AddrPort
			}
			packets := make(chan received, 2)
			s, tun := startMIPTestStack(t, &mipTestHandler{udp: func(_ context.Context, key netip.AddrPort, p *buf.Buffer, m M.Metadata, init func(N.PacketConn) N.PacketWriter) {
				packets <- received{p, m, init(nil), key}
			}})
			udp := []byte{0x30, 0x39, 0, 53, 0, 12, 0, 0, 't', 'e', 's', 't'}
			tun.in <- mipTestPacket(src, dst, 17, udp)
			r := mipReceive(t, packets)
			defer r.packet.Release()
			if r.key != netip.AddrPortFrom(src, 12345) || r.metadata.Source.AddrPort() != r.key || r.metadata.Destination.AddrPort() != netip.AddrPortFrom(dst, 53) {
				t.Fatalf("wrong metadata: %+v", r)
			}
			// A second input reuses the TUN read buffer; the retained payload and
			// asynchronous writer from the first callback must remain valid.
			udp[8] = 'n'
			tun.in <- mipTestPacket(src, dst, 17, udp)
			second := mipReceive(t, packets)
			second.packet.Release()
			if string(r.packet.Bytes()) != "test" {
				t.Fatal("borrowed UDP payload escaped callback")
			}
			if err := r.writer.WritePacket(buf.As([]byte("reply")).ToOwned(), M.SocksaddrFrom(reply, 5353)); err != nil {
				t.Fatal(err)
			}
			wire := mipReceive(t, tun.out)
			header := 20
			if ipv6 {
				header = 40
			}
			expected := mipTestPacket(reply, src, 17, []byte{0x14, 0xe9, 0x30, 0x39, 0, 13, 0, 0, 'r', 'e', 'p', 'l', 'y'})
			if !bytes.Equal(wire[header:], expected[header:]) {
				t.Fatalf("incorrect UDP reply: %x", wire)
			}
			if ipv6 {
				if !bytes.Equal(wire[8:40], expected[8:40]) {
					t.Fatal("incorrect IPv6 addresses")
				}
			} else if !bytes.Equal(wire[12:20], expected[12:20]) {
				t.Fatal("incorrect IPv4 addresses")
			}
			s.Close()
			if err := r.writer.WritePacket(buf.As([]byte("late")).ToOwned(), M.SocksaddrFrom(reply, 5353)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after close: %v", err)
			}
		})
	}
}

func TestMIPStackTCP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, batch := range []bool{false, true} {
			t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6]+map[bool]string{false: "/plain", true: "/GSO"}[batch], func(t *testing.T) {
				src, dst, network := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10"), "tcp4"
				if ipv6 {
					src, dst, network = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::10"), "tcp6"
				}
				metadata := make(chan M.Metadata, 1)
				h := &mipTestHandler{tcp: func(_ context.Context, c net.Conn, m M.Metadata) error {
					defer c.Close()
					metadata <- m
					_, err := io.Copy(c, c)
					return err
				}}
				var tun *mipTestTun
				var batchTun *mipBatchTestTun
				if batch {
					batchTun = newMIPBatchTestTun(10)
					tun = batchTun.mipTestTun
					options := mipTestOptions(batchTun, h)
					options.TunOptions.GSO = true
					options.TunOptions._TXChecksumOffload = true
					stack, err := NewMIPStack(options)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { tun.Close(); stack.Close() })
					if err = stack.Start(); err != nil {
						t.Fatal(err)
					}
				} else {
					_, tun = startMIPTestStack(t, h)
				}
				client, err := mipstack.New(mipstack.Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(src, src.BitLen())}, MTU: 1500})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				if err = client.Start(); err != nil {
					t.Fatal(err)
				}
				go func() {
					p := make([]byte, 65535)
					sizes := []int{0}
					for {
						n, err := client.Read([][]byte{p}, sizes, 0)
						if err != nil {
							return
						}
						if n > 0 {
							if batchTun != nil {
								packet := append([]byte(nil), p[:sizes[0]]...)
								ipLen, kind := 20, GSOTCPv4
								if ipv6 {
									ipLen, kind = 40, GSOTCPv6
								}
								tcpLen := int(packet[ipLen+12]>>4) * 4
								options := GSOOptions{CsumStart: uint16(ipLen), CsumOffset: 16, NeedsCsum: true}
								binary.BigEndian.PutUint16(packet[ipLen+16:], ^mipChecksum(mipTestPseudo(src, dst, 6, len(packet)-ipLen)))
								if len(packet) > ipLen+tcpLen {
									options.GSOType, options.HdrLen, options.GSOSize = kind, uint16(ipLen+tcpLen), 2
								}
								select {
								case batchTun.input <- mipOffloadInput{packet, options}:
								case <-tun.done:
									return
								}
								continue
							}
							select {
							case tun.in <- append([]byte(nil), p[:sizes[0]]...):
							case <-tun.done:
								return
							}
						}
					}
				}()
				go func() {
					for {
						select {
						case p := <-tun.out:
							if _, err := client.Write([][]byte{p}, 0); err != nil {
								return
							}
						case <-tun.done:
							return
						}
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := client.DialTCP(ctx, network, netip.AddrPortFrom(src, 12345), netip.AddrPortFrom(dst, 443))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = conn.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				p := make([]byte, 5)
				if _, err = io.ReadFull(conn, p); err != nil {
					t.Fatal(err)
				}
				if string(p) != "hello" {
					t.Fatal("incorrect TCP data")
				}
				m := mipReceive(t, metadata)
				if m.Source.AddrPort() != netip.AddrPortFrom(src, 12345) || m.Destination.AddrPort() != netip.AddrPortFrom(dst, 443) {
					t.Fatalf("incorrect metadata: %+v", m)
				}
			})
		}
	}
}

func TestMIPStackICMP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			for _, policy := range []string{"echo", "drop", "reset"} {
				t.Run(policy, func(t *testing.T) {
					src, dst, protocol, echoType := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("198.51.100.10"), byte(1), byte(8)
					if ipv6 {
						src, dst, protocol, echoType = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::10"), 58, 128
					}
					called := make(chan struct{}, 1)
					_, tun := startMIPTestStack(t, &mipTestHandler{icmp: func(network string, source, destination M.Socksaddr, _ DirectRouteContext, _ time.Duration) (DirectRouteDestination, error) {
						if network != N.NetworkICMP || source.Addr != src || destination.Addr != dst {
							t.Error("incorrect ICMP metadata")
						}
						called <- struct{}{}
						if policy == "drop" {
							return nil, ErrDrop
						}
						if policy == "reset" {
							return nil, ErrReset
						}
						return nil, nil
					}})
					tun.in <- mipTestPacket(src, dst, protocol, []byte{echoType, 0, 0, 0, 0, 1, 0, 2, 'p', 'i', 'n', 'g'})
					mipReceive(t, called)
					if policy == "drop" {
						select {
						case <-tun.out:
							t.Fatal("drop produced a response")
						case <-time.After(50 * time.Millisecond):
						}
						return
					}
					wire := mipReceive(t, tun.out)
					offset := 20
					if ipv6 {
						offset = 40
					}
					want := byte(0)
					if ipv6 {
						want = 129
					}
					if policy == "reset" {
						want = 3
						if ipv6 {
							want = 1
						}
					}
					if wire[offset] != want {
						t.Fatalf("unexpected ICMP type: %d", wire[offset])
					}
					if policy == "echo" && !bytes.Equal(wire[offset+4:], []byte{0, 1, 0, 2, 'p', 'i', 'n', 'g'}) {
						t.Fatal("echo did not preserve identifier, sequence and payload")
					}
				})
			}
		})
	}
}

func TestMIPStackLifecycleAndOptions(t *testing.T) {
	tun := newMIPTestTun()
	defer tun.Close()
	base := mipTestOptions(tun, &mipTestHandler{})
	for name, modify := range map[string]func(*StackOptions){
		"addresses": func(o *StackOptions) { o.TunOptions.Inet4Address = nil; o.TunOptions.Inet6Address = nil },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			modify(&o)
			s, err := NewMIPStack(o)
			if err == nil {
				s.Close()
				t.Fatal("unsupported configuration accepted")
			}
		})
	}
	base.IncludeAllNetworks = true
	s, err := NewMIPStack(base)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("start after close: %v", err)
	}
	s, err = NewMIPStack(base)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tun.done:
		t.Fatal("stack closed caller-owned TUN")
	default:
	}
}

type mipTestRoute struct {
	packets chan *buf.Buffer
	closed  atomic.Bool
}

func (r *mipTestRoute) WritePacket(p *buf.Buffer) error {
	r.packets <- p
	return nil
}

func (r *mipTestRoute) Close() error {
	r.closed.Store(true)
	return nil
}

func (r *mipTestRoute) IsClosed() bool { return r.closed.Load() }

func TestMIPStackICMPDirectRoute(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			src, dst, protocol, echoType := netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("198.51.100.10"), byte(1), byte(8)
			if ipv6 {
				src, dst, protocol, echoType = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::10"), 58, 128
			}
			route := &mipTestRoute{packets: make(chan *buf.Buffer, 2)}
			writers := make(chan DirectRouteContext, 2)
			var calls atomic.Int32
			s, tun := startMIPTestStack(t, &mipTestHandler{icmp: func(_ string, _, _ M.Socksaddr, writer DirectRouteContext, timeout time.Duration) (DirectRouteDestination, error) {
				if timeout != time.Minute {
					t.Error("ICMP timeout was not passed to route")
				}
				calls.Add(1)
				writers <- writer
				return route, nil
			}})
			request := mipTestPacket(src, dst, protocol, []byte{echoType, 0, 0, 0, 0, 1, 0, 2, 'a'})
			tun.in <- request
			writer := mipReceive(t, writers)
			packet := mipReceive(t, route.packets)
			defer packet.Release()
			// Reuse the route and overwrite the input buffer, retaining the first
			// packet and back writer beyond the original forwarder callback.
			tun.in <- mipTestPacket(src, dst, protocol, []byte{echoType, 0, 0, 0, 0, 1, 0, 3, 'b'})
			second := mipReceive(t, route.packets)
			second.Release()
			if calls.Load() != 1 {
				t.Fatal("ICMP route was not cached")
			}
			if !bytes.Equal(packet.Bytes(), request) {
				t.Fatal("forwarded ICMP packet was not independently owned")
			}
			replyType := byte(0)
			if ipv6 {
				replyType = 129
			}
			reply := mipTestPacket(dst, src, protocol, []byte{replyType, 0, 0, 0, 0, 1, 0, 2, 'a'})
			if err := writer.WritePacket(reply); err != nil {
				t.Fatal(err)
			}
			wire := mipReceive(t, tun.out)
			if !ipv6 {
				// MIPS assigns an IPv4 identification value on output. Check
				// its checksum, then normalize those two fields for comparison.
				if mipChecksum(wire[:20]) != 0 {
					t.Fatal("invalid IPv4 header checksum")
				}
				copy(reply[4:6], wire[4:6])
				reply[10], reply[11] = 0, 0
				binary.BigEndian.PutUint16(reply[10:], mipChecksum(reply[:20]))
			}
			if !bytes.Equal(wire, reply) {
				t.Fatalf("incorrect direct ICMP reply: %x", wire)
			}
			s.Close()
			if !route.IsClosed() {
				t.Fatal("stack close did not release cached route")
			}
			if err := writer.WritePacket(reply); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("late ICMP write: %v", err)
			}
		})
	}
}

func TestMIPStackContextCancellation(t *testing.T) {
	tun := newMIPTestTun()
	defer tun.Close()
	options := mipTestOptions(tun, &mipTestHandler{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options.Context = ctx
	stack, err := NewMIPStack(options)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := stack.(*MIPStack).stack.Read([][]byte{make([]byte, 1500)}, []int{0}, 0)
		result <- err
	}()
	cancel()
	if err := mipReceive(t, result); !E.IsClosed(err) {
		t.Fatalf("packet read after cancellation: %v", err)
	}
	select {
	case <-tun.done:
		t.Fatal("context cancellation closed caller-owned TUN")
	default:
	}
}
