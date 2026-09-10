package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mipstack"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// MIPStack adapts the MIPS userspace IP stack to a TUN and the sing handlers.
// The caller owns the TUN and must close it to release a blocked TUN read.
type MIPStack struct {
	ctx                context.Context
	cancel             context.CancelFunc
	tun                Tun
	stack              *mipstack.Stack
	handler            Handler
	logger             logger.Logger
	mapping            *DirectRouteMapping
	mu                 sync.Mutex
	started            bool
	closed             bool
	icmpMu             sync.Mutex
	writeMu            sync.Mutex
	batchTun           LinuxTUN
	frontHeadroom      int
	batchSize          int
	loopback           map[netip.Addr]struct{}
	interfaceAddresses map[netip.Addr]struct{}
	broadcastAddresses map[netip.Addr]struct{}
	recvMsgX           bool
}

func NewMIPStack(options StackOptions) (Stack, error) {
	if options.Tun == nil || options.Handler == nil {
		return nil, E.New("mipstack: TUN and handler are required")
	}
	var batchTun LinuxTUN
	frontHeadroom, batchSize := 0, 1
	if _, ok := options.Tun.(DarwinTUN); ok {
		frontHeadroom = 4
	}
	if _, ok := options.Tun.(WinTun); ok {
		frontHeadroom = 0
	}
	if tun, ok := options.Tun.(LinuxTUN); ok {
		if tun.BatchSize() < 1 || tun.FrontHeadroom() < 0 {
			return nil, E.New("mipstack: invalid TUN batch size or headroom")
		}
		// Native Linux BatchRead expects a virtio header; a plain TUN must
		// continue to use Read even though it implements LinuxTUN.
		if tun.BatchSize() > 1 || tun.FrontHeadroom() > 0 {
			batchTun, frontHeadroom, batchSize = tun, tun.FrontHeadroom(), tun.BatchSize()
		}
	}
	addresses := append([]netip.Prefix(nil), options.TunOptions.Inet4Address...)
	addresses = append(addresses, options.TunOptions.Inet6Address...)
	config := mipstack.Config{
		LocalAddresses: addresses,
		MTU:            options.TunOptions.MTU,
		Promiscuous:    true,
		TCP: mipstack.TCPSocketDefaults{
			KeepAlive:       true,
			KeepAliveConfig: mipstack.KeepAliveConfig{Idle: 15 * time.Second, Interval: 15 * time.Second},
		},
	}
	// Interface addresses belong to the host. MIPS owns only private loopback
	// addresses, so replies to host-originated traffic return through the TUN.
	interfaceAddresses := make(map[netip.Addr]struct{}, len(addresses))
	broadcastAddresses := make(map[netip.Addr]struct{})
	have6 := len(options.TunOptions.Inet6Address) > 0
	for _, prefix := range addresses {
		if !prefix.IsValid() {
			return nil, E.New("mipstack: invalid interface prefix")
		}
		address := prefix.Addr().Unmap()
		interfaceAddresses[address] = struct{}{}
		if address.Is4() {
			if prefix.Addr().Is4() && prefix.Bits() <= 30 {
				broadcastAddresses[BroadcastAddr([]netip.Prefix{prefix})] = struct{}{}
			}
		} else {
			have6 = true
		}
	}
	config.LocalAddresses = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	if have6 || config.MTU == 0 || config.MTU >= 1280 {
		config.LocalAddresses = append(config.LocalAddresses, netip.MustParsePrefix("::1/128"))
	}
	ipStack, err := mipstack.New(config)
	if err != nil {
		return nil, err
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &MIPStack{ctx: ctx, cancel: cancel, tun: options.Tun, stack: ipStack,
		handler: options.Handler, logger: options.Logger, mapping: NewDirectRouteMapping(options.ICMPTimeout),
		batchTun: batchTun, frontHeadroom: frontHeadroom, batchSize: batchSize,
		loopback:           make(map[netip.Addr]struct{}),
		interfaceAddresses: interfaceAddresses, broadcastAddresses: broadcastAddresses, recvMsgX: options.TunOptions.EXP_RecvMsgX}
	for _, address := range options.TunOptions.Inet4LoopbackAddress {
		s.loopback[address.Unmap()] = struct{}{}
	}
	for _, address := range options.TunOptions.Inet6LoopbackAddress {
		s.loopback[address] = struct{}{}
	}
	if _, err = mipstack.NewTCPForwarder(ipStack, mipstack.TCPForwarderOptions{MaxInFlight: 1024}, s.forwardTCP); err == nil {
		_, err = mipstack.NewUDPForwarder(ipStack, mipstack.UDPForwarderOptions{}, s.forwardUDP)
	}
	if err == nil {
		_, err = mipstack.NewICMPForwarder(ipStack, mipstack.ICMPForwarderOptions{}, s.forwardICMP)
	}
	if err == nil {
		_, err = mipstack.NewIPForwarder(ipStack, mipstack.IPForwarderOptions{}, func(r *mipstack.IPForwarderRequest) { _ = r.Reject() })
	}
	if err != nil {
		cancel()
		ipStack.Close()
		return nil, err
	}
	return s, nil
}

func (s *MIPStack) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.started {
		return nil
	}
	if err := s.stack.Start(); err != nil {
		return err
	}
	s.started = true
	go s.tunLoop()
	go s.packetLoop()
	go func() { <-s.ctx.Done(); s.Close() }()
	return nil
}

func (s *MIPStack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	err := s.stack.Close()
	s.mu.Unlock()
	s.icmpMu.Lock()
	s.mapping.status.Clear()
	s.icmpMu.Unlock()
	return err
}

func (s *MIPStack) logError(err error, operation string) {
	if err != nil && !E.IsClosed(err) && s.ctx.Err() == nil && s.logger != nil {
		s.logger.Error(E.Cause(err, "mipstack: ", operation))
	}
}

func (s *MIPStack) forwardTCP(request *mipstack.TCPForwarderRequest) {
	flow := request.Flow()
	conn, err := request.Accept(s.ctx)
	if err != nil {
		return
	}
	// Accept must finish within the forwarder callback; the connection may then
	// be handed to the application independently of the request lifetime.
	go func() {
		if err := s.handler.NewConnection(s.ctx, conn, M.Metadata{
			Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination),
		}); err != nil {
			conn.SetLinger(0)
			conn.Close()
		}
	}()
}

func (s *MIPStack) forwardUDP(request *mipstack.UDPForwarderRequest) {
	flow := request.Flow()
	// Requests and their payloads are borrowed only until the callback returns.
	payload := buf.As(request.Payload()).ToOwned()
	responder, err := request.DetachForReplies()
	if err != nil {
		payload.Release()
		return
	}
	s.handler.NewPacket(s.ctx, flow.Source, payload, M.Metadata{
		Source: M.SocksaddrFromNetIP(flow.Source), Destination: M.SocksaddrFromNetIP(flow.Destination),
	}, func(N.PacketConn) N.PacketWriter { return &mipUDPBackWriter{responder} })
}

type mipUDPBackWriter struct {
	responder *mipstack.UDPForwarderResponder
}

func (w *mipUDPBackWriter) WritePacket(packet *buf.Buffer, destination M.Socksaddr) error {
	defer packet.Release()
	if !destination.IsIP() {
		return E.New("mipstack: invalid UDP reply address")
	}
	_, err := w.responder.ReplyFrom(packet.Bytes(), destination.AddrPort())
	return err
}

func (s *MIPStack) forwardICMP(request *mipstack.ICMPForwarderRequest) {
	message := request.Message()
	if !message.IsEchoRequest() {
		request.Drop()
		return
	}
	if _, local := s.interfaceAddresses[message.Destination]; local {
		// Interface addresses are no longer owned by MIPS, so preserve their
		// local echo behavior here without consulting the routing handler.
		s.logError(request.ReplyEcho(), "reply interface ICMP")
		return
	}
	// The route may retain its back writer after this callback has returned.
	packet := request.IPPacket()
	responder, err := request.DetachForReplies()
	if err != nil {
		return
	}
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	action, err := s.mapping.Lookup(DirectRouteSession{Source: message.Source, Destination: message.Destination}, func(timeout time.Duration) (DirectRouteDestination, error) {
		destination, err := s.handler.PrepareConnection(N.NetworkICMP,
			M.SocksaddrFrom(message.Source, 0), M.SocksaddrFrom(message.Destination, 0),
			&mipICMPBackWriter{responder}, timeout)
		if err != nil && destination != nil {
			_ = destination.Close()
			destination = nil
		}
		return destination, err
	})
	switch {
	case errors.Is(err, ErrReset):
		s.replyICMPReset(responder, message, packet)
	case errors.Is(err, ErrDrop):
		return
	case action != nil:
		owned := buf.As(packet).ToOwned()
		s.logError(action.WritePacket(owned), "forward ICMP")
	default:
		reply, err := (mipstack.ICMPMessage{Source: message.Source, Destination: message.Destination, Type: message.Type, Code: message.Code, Body: message.Payload[4:]}).EchoReply(message.Destination)
		if err != nil {
			return
		}
		payload, err := reply.MarshalBinary()
		if err == nil {
			s.logError(responder.Reply(payload), "reply ICMP")
		}
	}
}

type mipICMPBackWriter struct {
	responder *mipstack.ICMPForwarderResponder
}

func (w *mipICMPBackWriter) WritePacket(packet []byte) error {
	return w.responder.ReplyIPPacket(packet)
}

// Match gVisor's ErrReset response rather than MIPS's administrative rejection.
func (s *MIPStack) replyICMPReset(r *mipstack.ICMPForwarderResponder, m mipstack.ICMPForwarderMessage, quote []byte) {
	mtu, _ := s.stack.MTU()
	limit, overhead, kind, code := 576, 28, byte(3), byte(3)
	if m.Source.Is6() {
		limit, overhead, kind, code = 1280, 48, 1, 4
	}
	if mtu < limit {
		limit = mtu
	}
	if len(quote) > limit-overhead {
		quote = quote[:limit-overhead]
	}
	reply, err := (mipstack.ICMPError{Reporter: m.Destination, Type: kind, Code: code, QuotedPacket: quote}).ICMPMessage(m.Source)
	if err != nil {
		return
	}
	payload, err := reply.MarshalBinary()
	if err == nil {
		s.logError(r.Reply(payload), "reject ICMP")
	}
}
