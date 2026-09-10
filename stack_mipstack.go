//go:build with_mipstack

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

const WithMIPStack = true

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
}

func NewMIPStack(options StackOptions) (Stack, error) {
	if options.Tun == nil || options.Handler == nil {
		return nil, E.New("mipstack: TUN and handler are required")
	}
	var batchTun LinuxTUN
	frontHeadroom, batchSize := PacketOffset, 1
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
	ipStack, err := mipstack.New(config)
	if err != nil {
		return nil, err
	}
	// TUN interface addresses belong to the host, not this transparent
	// endpoint. Registering them as MIPS local addresses sends replies to
	// host-originated traffic into MIPS's internal loopback instead of Read.
	// MIPS requires a local address per enabled family. Give it only internal
	// loopback addresses; forwarders still reply from the intercepted target.
	// New above validates the original address/MTU configuration first.
	interfaceAddresses := make(map[netip.Addr]struct{}, len(addresses))
	broadcastAddresses := make(map[netip.Addr]struct{})
	var have4, have6 bool
	for _, prefix := range addresses {
		address := prefix.Addr().Unmap()
		interfaceAddresses[address] = struct{}{}
		if address.Is4() {
			have4 = true
			if prefix.Addr().Is4() && prefix.Bits() <= 30 {
				broadcastAddresses[BroadcastAddr([]netip.Prefix{prefix})] = struct{}{}
			}
		} else {
			have6 = true
		}
	}
	config.LocalAddresses = nil
	if have4 {
		config.LocalAddresses = append(config.LocalAddresses, netip.MustParsePrefix("127.0.0.1/32"))
	}
	if have6 {
		config.LocalAddresses = append(config.LocalAddresses, netip.MustParsePrefix("::1/128"))
	}
	if err = ipStack.UpdateConfig(config); err != nil {
		ipStack.Close()
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
		interfaceAddresses: interfaceAddresses, broadcastAddresses: broadcastAddresses}
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
	responder, err := request.Detach()
	if err != nil {
		return
	}
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	action, err := s.mapping.Lookup(DirectRouteSession{Source: message.Source, Destination: message.Destination}, func(timeout time.Duration) (DirectRouteDestination, error) {
		return s.handler.PrepareConnection(N.NetworkICMP,
			M.SocksaddrFrom(message.Source, 0), M.SocksaddrFrom(message.Destination, 0),
			&mipICMPBackWriter{responder}, timeout)
	})
	switch {
	case errors.Is(err, ErrReset):
		s.logError(responder.Reject(), "reject ICMP")
	case errors.Is(err, ErrDrop):
		responder.Drop()
	case action != nil:
		packet := buf.As(responder.IPPacket()).ToOwned()
		s.logError(action.WritePacket(packet), "forward ICMP")
	default:
		s.logError(responder.ReplyEcho(), "reply ICMP")
	}
}

type mipICMPBackWriter struct {
	responder *mipstack.ICMPForwarderResponder
}

func (w *mipICMPBackWriter) WritePacket(packet []byte) error {
	return w.responder.ReplyIPPacket(packet)
}
