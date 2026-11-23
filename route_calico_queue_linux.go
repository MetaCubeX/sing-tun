//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	nfqMessagePacket     = 0
	nfqMessageVerdict    = 1
	nfqMessageConfig     = 2
	nfqPacketHeader      = 1
	nfqVerdictHeader     = 2
	nfqMark              = 3
	nfqInputInterface    = 5
	nfqPayload           = 10
	nfqConntrack         = 11
	nfqConntrackInfo     = 12
	nfqCfgCmd            = 1
	nfqCfgParams         = 2
	nfqCfgFlags          = 4
	nfqCfgMask           = 5
	nfqCfgCmdBind        = 1
	nfqCopyPacket        = 2
	nfqCopyRange         = 2048 // room for IPv6 extension headers without copying a full GSO skb
	nfqFlagFailOpen      = 1 << 0
	nfqFlagConntrack     = 1 << 1
	nfqFlagGSO           = 1 << 2
	nfqVerdictAccept     = 1
	ctaMarkMask          = 21
	calicoQueueRecvBuf   = 4 << 20
	calicoQueueInventory = "/proc/net/netfilter/nfnetlink_queue"
)

type calicoConntrackCache struct {
	valid bool
	fd    int
	dev   uint64
	ino   uint64
}

// Classify workload packets before routing. The skb stays in the kernel,
// including its GSO, checksum and any conntrack state.
type calicoServiceQueue struct {
	socket    *nl.NetlinkSocket
	reader    *os.File
	number    uint16
	done      chan struct{}
	closeOnce sync.Once
	bypass    *autoRouteDNATBypass
	access    sync.RWMutex
	scopes    [2]serviceForwardScope
	ctCache   [2]calicoConntrackCache
	lookupBuf calicoLookupBuffers
}

func newCalicoServiceQueue(b *autoRouteDNATBypass) (*calicoServiceQueue, error) {
	socket, err := subscribeAutoRouteNetlink(unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	_ = unix.SetsockoptInt(socket.GetFd(), unix.SOL_SOCKET, unix.SO_RCVBUF, calicoQueueRecvBuf)
	q := &calicoServiceQueue{
		socket:  socket,
		number:  uint16(b.options.IPRoute2TableIndex),
		done:    make(chan struct{}),
		bypass:  b,
		scopes:  b.forwardScopes,
		ctCache: [2]calicoConntrackCache{{fd: -1}, {fd: -1}},
	}
	handle := map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: {Socket: socket}}
	config := func(attrs ...*nl.RtAttr) error {
		req := q.request(nfqMessageConfig, unix.NLM_F_ACK, unix.AF_UNSPEC)
		req.Sockets = handle
		for _, attr := range attrs {
			req.AddData(attr)
		}
		_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
		return err
	}
	bind := nl.NewRtAttr(nfqCfgCmd, []byte{nfqCfgCmdBind, 0, 0, 0})
	err = config(bind)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EBUSY) {
		// Route table IDs are wider than NFQUEUE IDs. The kernel also
		// refuses to bind a number owned by another netlink socket.
		number, inventoryErr := availableCalicoQueue(q.number)
		if inventoryErr == nil {
			q.number = number
			err = config(bind)
		} else {
			err = errors.Join(err, inventoryErr)
		}
	}
	if err == nil {
		// TCP replies can lack CT after BPF delivers peer ACKs directly.
		var params [5]byte
		binary.BigEndian.PutUint32(params[:4], nfqCopyRange)
		params[4] = nfqCopyPacket
		var flags [4]byte
		binary.BigEndian.PutUint32(flags[:], nfqFlagFailOpen|nfqFlagConntrack|nfqFlagGSO)
		err = config(nl.NewRtAttr(nfqCfgParams, params[:]), nl.NewRtAttr(nfqCfgFlags, flags[:]), nl.NewRtAttr(nfqCfgMask, flags[:]))
	}
	if err != nil {
		socket.Close()
		return nil, fmt.Errorf("configure Calico service queue %d: %w", q.number, err)
	}
	fd, err := unix.FcntlInt(uintptr(socket.GetFd()), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		socket.Close()
		return nil, err
	}
	q.reader = os.NewFile(uintptr(fd), "calico-service-queue")
	go q.run()
	return q, nil
}

func availableCalicoQueue(preferred uint16) (uint16, error) {
	data, err := os.ReadFile(calicoQueueInventory)
	if err != nil {
		return 0, err
	}
	var occupied [1 << 16]bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		number, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return 0, err
		}
		occupied[number] = true
	}
	for offset := 0; offset < len(occupied); offset++ {
		number := preferred + uint16(offset)
		if !occupied[number] {
			return number, nil
		}
	}
	return 0, errors.New("all NFQUEUE numbers are in use")
}

func (q *calicoServiceQueue) request(operation, flags int, family byte) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(unix.NFNL_SUBSYS_QUEUE<<8|operation, flags)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: family, ResId: nl.Swap16(q.number)})
	return req
}

func (q *calicoServiceQueue) Close() {
	q.closeOnce.Do(func() {
		q.reader.Close()
		<-q.done
	})
}

func (q *calicoServiceQueue) running() bool {
	if q == nil {
		return false
	}
	select {
	case <-q.done:
		return false
	default:
		return true
	}
}

func (q *calicoServiceQueue) conntrackFD(ipv6 bool) int {
	index := 0
	if ipv6 {
		index = 1
	}
	cache := &q.ctCache[index]
	var st unix.Stat_t
	if err := unix.Stat(calicoConntrackPath(ipv6), &st); err != nil {
		if cache.fd >= 0 {
			_ = unix.Close(cache.fd)
		}
		*cache = calicoConntrackCache{fd: -1}
		return -1
	}
	if cache.valid && cache.dev == st.Dev && cache.ino == st.Ino {
		return cache.fd
	}
	if cache.fd >= 0 {
		_ = unix.Close(cache.fd)
	}
	fd, err := openCalicoConntrack(ipv6)
	if err != nil {
		if errors.Is(err, errUnsupportedCalicoCTABI) {
			// Negative-cache deterministic ABI mismatches until the pinned map inode changes.
			*cache = calicoConntrackCache{valid: true, fd: -1, dev: st.Dev, ino: st.Ino}
		} else {
			*cache = calicoConntrackCache{fd: -1}
		}
		return -1
	}
	*cache = calicoConntrackCache{valid: true, fd: fd, dev: st.Dev, ino: st.Ino}
	return fd
}

func (q *calicoServiceQueue) closeConntrack() {
	for i := range q.ctCache {
		if q.ctCache[i].fd >= 0 {
			_ = unix.Close(q.ctCache[i].fd)
			q.ctCache[i] = calicoConntrackCache{fd: -1}
		}
	}
}

func (q *calicoServiceQueue) run() {
	interrupted := true
	defer func() {
		close(q.done)
		if interrupted {
			select {
			case q.bypass.serviceEvents <- struct{}{}:
			default:
			}
		}
	}()
	defer q.closeConntrack()
	defer q.socket.Close()
	defer q.reader.Close()
	conn, err := q.reader.SyscallConn()
	if err != nil {
		interrupted = !errors.Is(err, os.ErrClosed)
		if interrupted && q.bypass.options.Logger != nil {
			q.bypass.options.Logger.Warn("Calico service queue stopped: ", err)
		}
		return
	}
	var data [65536]byte
	for {
		messages, from, err := q.receive(conn, data[:])
		if err != nil {
			if errors.Is(err, unix.ENOBUFS) {
				continue
			}
			interrupted = !errors.Is(err, os.ErrClosed)
			if interrupted && q.bypass.options.Logger != nil {
				q.bypass.options.Logger.Warn("Calico service queue stopped: ", err)
			}
			return
		}
		if from.Pid != nl.PidKernel {
			continue
		}
		for _, message := range messages {
			if message.Header.Type == unix.NLMSG_ERROR && len(message.Data) >= 4 {
				errno := int32(nl.NativeEndian().Uint32(message.Data))
				if errno == -int32(unix.ENOENT) {
					// The queued packet may have expired or its device may be down.
					continue
				}
				if errno != 0 {
					if q.bypass.options.Logger != nil {
						q.bypass.options.Logger.Warn("Calico service queue verdict: ", unix.Errno(-errno))
					}
					return
				}
			}
			if message.Header.Type != unix.NFNL_SUBSYS_QUEUE<<8|nfqMessagePacket || len(message.Data) < 4 {
				continue
			}
			if err := q.verdict(message.Data); err != nil {
				if q.bypass.options.Logger != nil {
					q.bypass.options.Logger.Warn("classify Calico service packet: ", err)
				}
				return
			}
		}
	}
}

func (q *calicoServiceQueue) receive(conn syscall.RawConn, data []byte) ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	var size int
	var from unix.Sockaddr
	var receiveErr error
	err := conn.Read(func(fd uintptr) bool {
		for {
			size, from, receiveErr = unix.Recvfrom(int(fd), data, unix.MSG_TRUNC)
			if receiveErr != unix.EINTR {
				return receiveErr != unix.EAGAIN
			}
		}
	})
	if err != nil {
		return nil, nil, err
	}
	if receiveErr != nil {
		return nil, nil, receiveErr
	}
	if size > len(data) {
		return nil, nil, unix.EMSGSIZE
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok {
		return nil, nil, unix.EINVAL
	}
	messages, err := parseCalicoQueueMessages(data[:size])
	return messages, sender, err
}

func parseCalicoQueueMessages(data []byte) ([]syscall.NetlinkMessage, error) {
	for offset := 0; offset < len(data); {
		if len(data)-offset < unix.NLMSG_HDRLEN {
			return nil, unix.EINVAL
		}
		length := int(nl.NativeEndian().Uint32(data[offset:]))
		if length < unix.NLMSG_HDRLEN || length > len(data)-offset {
			return nil, unix.EINVAL
		}
		next := offset + ((length + 3) &^ 3)
		if next > len(data) {
			if offset+length != len(data) {
				return nil, unix.EINVAL
			}
			// NFQUEUE can omit alignment bytes after its final packet payload.
			data = append(data, make([]byte, next-len(data))...)
		}
		offset = next
	}
	return syscall.ParseNetlinkMessage(data)
}

func parseCalicoQueueAttributes(data []byte) ([]syscall.NetlinkRouteAttr, error) {
	var attrs []syscall.NetlinkRouteAttr
	for len(data) > 0 {
		if len(data) < unix.SizeofRtAttr {
			return nil, unix.EINVAL
		}
		length := int(nl.NativeEndian().Uint16(data))
		if length < unix.SizeofRtAttr || length > len(data) {
			return nil, unix.EINVAL
		}
		attrs = append(attrs, syscall.NetlinkRouteAttr{
			Attr:  syscall.RtAttr{Len: uint16(length), Type: nl.NativeEndian().Uint16(data[2:])},
			Value: data[unix.SizeofRtAttr:length],
		})
		next := (length + 3) &^ 3
		if next > len(data) {
			if length != len(data) {
				return nil, unix.EINVAL
			}
			break
		}
		data = data[next:]
	}
	return attrs, nil
}

func (q *calicoServiceQueue) verdict(data []byte) error {
	attrs, err := parseCalicoQueueAttributes(data[4:])
	if err != nil {
		return err
	}
	var id, mark, input, ctinfo uint32
	var ct, payload []byte
	for _, attr := range attrs {
		switch attr.Attr.Type & 0x3fff {
		case nfqPacketHeader:
			if len(attr.Value) >= 4 {
				id = binary.BigEndian.Uint32(attr.Value)
			}
		case nfqMark:
			if len(attr.Value) == 4 {
				mark = binary.BigEndian.Uint32(attr.Value)
			}
		case nfqInputInterface:
			if len(attr.Value) == 4 {
				input = binary.BigEndian.Uint32(attr.Value)
			}
		case nfqConntrack:
			ct = attr.Value
		case nfqPayload:
			payload = attr.Value
		case nfqConntrackInfo:
			if len(attr.Value) == 4 {
				ctinfo = binary.BigEndian.Uint32(attr.Value)
			}
		}
	}
	req := q.request(nfqMessageVerdict, 0, data[0])
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[:4], nfqVerdictAccept)
	binary.BigEndian.PutUint32(header[4:], id)
	req.AddData(nl.NewRtAttr(nfqVerdictHeader, header))
	b := q.bypass
	routeMask := b.options.autoRouteDNATBypassMask()
	routeMark := mark
	if routeMark == 0 {
		routeMark = b.forwardedInputMark()
	}
	var flow calicoServiceFlow
	var parsed bool
	if len(ct) > 0 {
		flow, err = parseCalicoServiceFlow(append([]byte{data[0], 0, 0, 0}, ct...), ctinfo >= 3)
		if err != nil {
			return q.socket.Send(req)
		}
		parsed = true
	} else {
		flow, parsed = parseCalicoUntrackedTCP(payload, data[0])
	}
	if parsed {
		flow.input = input
		i := 0
		if data[0] == unix.AF_INET6 {
			i = 1
		}
		q.access.RLock()
		scope := q.scopes[i]
		q.access.RUnlock()
		action := calicoUnclassified
		if fd := q.conntrackFD(i == 1); fd >= 0 {
			action = flow.classifyCalicoFlowWithBuf(fd, scope, &q.lookupBuf)
		}
		if action == calicoNativeReply {
			routeMark = mark&^routeMask | b.options.autoRouteDNATBypassMark()
		}
		if len(ct) > 0 && flow.mark == 0 && action != calicoUnclassified {
			ctmark := b.forwardedInputMark()
			if action == calicoNativeReply {
				ctmark = b.options.autoRouteOutputMark()
			}
			// NFQA_CT updates the CT object held by this queued skb, rather
			// than finding a possibly replaced object by its tuple.
			value, mask := make([]byte, 4), make([]byte, 4)
			binary.BigEndian.PutUint32(value, ctmark)
			binary.BigEndian.PutUint32(mask, b.serviceConnmarkMask(ctmark))
			state := nl.NewRtAttr(nfqConntrack|unix.NLA_F_NESTED, nil)
			nl.NewRtAttrChild(state, nl.CTA_MARK, value)
			nl.NewRtAttrChild(state, ctaMarkMask, mask)
			req.AddData(state)
		}
	}
	packetMark := make([]byte, 4)
	binary.BigEndian.PutUint32(packetMark, routeMark)
	req.AddData(nl.NewRtAttr(nfqMark, packetMark))
	return q.socket.Send(req)
}
