package tun

import (
	"errors"
	"time"

	mips "github.com/metacubex/mipstack"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (s *Mipstack) forwardICMP(request *mips.ICMPForwarderRequest) {
	message := request.Message()
	if !message.IsEchoRequest() {
		_ = request.Drop()
		return
	}
	if message.Destination == s.inet4Address || message.Destination == s.inet6Address {
		_ = request.ReplyEcho()
		_ = request.Drop()
		return
	}
	// Borrow input only within this callback. The asynchronous writer retains
	// metadata only, so publishing it requires no later state transition.
	packet := request.IPPacket()
	responder, err := request.DetachForReplies()
	if err != nil {
		return
	}
	writer := &mipsICMPWriter{responder: responder}
	action, err := s.icmpMapping.Lookup(DirectRouteSession{Source: message.Source, Destination: message.Destination}, func(timeout time.Duration) (DirectRouteDestination, error) {
		destination, err := s.handler.PrepareConnection(
			N.NetworkICMP,
			M.SocksaddrFrom(message.Source, 0),
			M.SocksaddrFrom(message.Destination, 0),
			writer,
			timeout,
		)
		if err != nil {
			if destination != nil {
				_ = destination.Close()
			}
			return nil, err
		}
		return destination, nil
	})
	if errors.Is(err, ErrReset) {
		s.replyPortUnreachable(responder, message, packet)
		return
	} else if errors.Is(err, ErrDrop) {
		return
	}
	if action != nil {
		buffer := buf.NewSize(len(packet))
		_, _ = buffer.Write(packet)
		_ = action.WritePacket(buffer)
		return
	}
	reply, err := (mips.ICMPMessage{
		Source: message.Source, Destination: message.Destination,
		Type: message.Type, Code: message.Code, Body: message.Payload[4:],
	}).EchoReply(message.Destination)
	if err != nil {
		return
	}
	payload, err := reply.MarshalBinary()
	if err != nil {
		return
	}
	_ = responder.Reply(payload)
}

type mipsICMPWriter struct {
	responder *mips.ICMPForwarderResponder
}

func (w *mipsICMPWriter) WritePacket(packet []byte) error {
	return w.responder.ReplyIPPacket(packet)
}

// Reply with port unreachable for ErrReset, matching the gVisor adapter.
// mipstack's Reject replies with administratively prohibited instead.
// Only validated unicast Echo Requests reach this path; never reject an error.
func (s *Mipstack) replyPortUnreachable(responder *mips.ICMPForwarderResponder, message mips.ICMPForwarderMessage, quote []byte) {
	if !message.Source.IsGlobalUnicast() || message.Source == s.broadcastAddr {
		return
	}
	limit, ipHeader := header.IPv4MinimumProcessableDatagramSize, header.IPv4MinimumSize
	icmpHeader := header.ICMPv4MinimumSize
	kind, code := byte(mips.ICMPv4TypeDestinationUnreachable), byte(mips.ICMPv4DestinationUnreachableCodePort)
	if message.Source.Is6() {
		limit, ipHeader = header.IPv6MinimumMTU, header.IPv6MinimumSize
		icmpHeader = header.ICMPv6DstUnreachableMinimumSize
		kind, code = mips.ICMPv6TypeDestinationUnreachable, mips.ICMPv6DestinationUnreachableCodePort
	}
	if int(s.mtu) < limit {
		limit = int(s.mtu)
	}
	if len(quote) > limit-ipHeader-icmpHeader {
		quote = quote[:limit-ipHeader-icmpHeader]
	}
	reply, err := (mips.ICMPError{
		Reporter:     message.Destination,
		Type:         kind,
		Code:         code,
		QuotedPacket: quote,
	}).ICMPMessage(message.Source)
	if err != nil {
		return
	}
	payload, err := reply.MarshalBinary()
	if err != nil {
		return
	}
	_ = responder.Reply(payload)
}
