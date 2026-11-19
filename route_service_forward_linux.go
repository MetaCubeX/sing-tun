//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	"go4.org/netipx"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

type serviceForwardScope struct {
	backends        []netip.Prefix
	uplinks         []string
	calicoWorkloads bool
	cilium          bool
	queueNumber     uint16
	calico          *calicoTopology
}

// With Cilium's MARK_MAGIC_IDENTITY the upper 16 and lower 8 bits hold
// the security identity. Its key index is zero. Borrow one key-index bit
// only for route lookup, then restore it before forward or input filtering.
const (
	ciliumMarkMask       = 0xff00
	ciliumIdentity       = 0x0f00
	ciliumRouteBit       = 0x1000
	ciliumRoutedIdentity = ciliumIdentity | ciliumRouteBit
)

func (b *autoRouteDNATBypass) prepareCalicoQueue(needed bool) error {
	if b.calicoQueue.running() {
		return nil
	}
	if b.calicoQueue != nil {
		b.calicoQueue.Close()
		b.calicoQueue = nil
	}
	if !needed {
		return nil
	}
	var err error
	b.calicoQueue, err = newCalicoServiceQueue(b)
	return err
}

func (b *autoRouteDNATBypass) calicoClassifierReady(i int) bool {
	scope := b.forwardScopes[i]
	return scope.calicoWorkloads && b.calicoQueue.running() && scope.queueNumber == b.calicoQueue.number
}

func (b *autoRouteDNATBypass) serviceClassifierReady(i int, path serviceRoute) bool {
	scope := b.forwardScopes[i]
	if !slices.Contains(scope.backends, path.prefix) {
		return false
	}
	if path.forward == ciliumReply {
		return scope.cilium
	}
	return b.calicoClassifierReady(i) && (path.forward != calicoUplinkProbe || slices.Contains(scope.uplinks, path.iif))
}

func (b *autoRouteDNATBypass) closeUnusedCalicoQueue() {
	if b.calicoQueue != nil && !b.calicoClassifierReady(0) && !b.calicoClassifierReady(1) {
		b.calicoQueue.Close()
		b.calicoQueue = nil
	}
}

func (b *autoRouteDNATBypass) syncServiceForward(i int, scope serviceForwardScope) error {
	sort.Strings(scope.uplinks)
	sort.Slice(scope.backends, func(i, j int) bool {
		a, b := scope.backends[i], scope.backends[j]
		if a.Addr() == b.Addr() {
			return a.Bits() < b.Bits()
		}
		return a.Addr().Less(b.Addr())
	})
	scope.backends = slices.Compact(scope.backends)
	old := b.forwardScopes[i]
	if old.queueNumber != scope.queueNumber || old.calicoWorkloads != scope.calicoWorkloads || old.cilium != scope.cilium ||
		!slices.Equal(old.backends, scope.backends) || !slices.Equal(old.uplinks, scope.uplinks) {
		var err error
		if b.useNFTables {
			err = b.replaceNFTServiceForward(i, scope)
		} else {
			err = b.replaceIPTablesServiceForward(i, scope)
		}
		if err != nil {
			return err
		}
	}
	// Keep serving the previous scope while an xtables lock delays commit.
	// Publish the replacement only after the kernel accepted the rules.
	if queue := b.calicoQueue; queue != nil {
		queue.access.Lock()
		queue.scopes[i] = scope
		queue.access.Unlock()
	}
	b.forwardScopes[i] = scope
	return nil
}

// A FIB probe runs before netfilter. Distinguish a real, as yet unmarked
// workload packet from that probe without granting it a native-route mark.
func (b *autoRouteDNATBypass) forwardedInputMark() uint32 {
	mark := uint32(DefaultAutoRedirectInputMark & autoRouteDNATBypassMarkFieldMask)
	mask := b.options.autoRouteDNATBypassMask()
	if mark&mask == b.options.autoRouteDNATBypassMark() {
		mark ^= mask & -mask
	}
	return mark
}

func (b *autoRouteDNATBypass) serviceConnmarkMask(mark uint32) uint32 {
	return b.options.autoRouteOutputMark() | b.options.autoRouteDNATBypassMask() | mark
}

// Only tag flows which arrived at the uplink and were already translated
// to a local workload. A new connection initiated by that workload is not
// a service reply, even when the socket is bound to a service port.
func (b *autoRouteDNATBypass) replaceNFTServiceForward(i int, scope serviceForwardScope) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	defer conn.CloseLasting()
	table := &nftables.Table{Name: b.tableName, Family: nftables.TableFamilyINet}
	suffix := []string{"4", "6"}[i]
	chain := &nftables.Chain{Name: "service_forward" + suffix, Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 3)}
	queue := &nftables.Chain{Name: "service_queue" + suffix, Table: table}
	set := &nftables.Set{Name: "service_backends" + suffix, Table: table, KeyType: nftables.TypeIPAddr, Interval: true}
	family := nftables.TableFamilyIPv4
	offset, length := uint32(16), uint32(4)
	if i == 1 {
		set.KeyType = nftables.TypeIP6Addr
		family = nftables.TableFamilyIPv6
		offset, length = 24, 16
	}
	var builder netipx.IPSetBuilder
	for _, prefix := range scope.backends {
		builder.AddPrefix(prefix)
	}
	backends, err := builder.IPSet()
	if err != nil {
		return err
	}
	elems := nftablesIntervalElements(backends, family)
	nativeMark := b.options.autoRouteOutputMark()
	ctmark := binaryutil.NativeEndian.PutUint32(nativeMark)
	ctmask := b.serviceConnmarkMask(nativeMark)
	nativeConnmarkMatch := []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(ctmask), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ctmark},
	}
	if scope.cilium || b.forwardScopes[i].cilium {
		for _, hook := range []struct {
			name string
			hook *nftables.ChainHook
		}{{"input", nftables.ChainHookInput}, {"forward", nftables.ChainHookForward}} {
			restore := &nftables.Chain{Name: "service_restore_" + hook.name + suffix, Table: table, Type: nftables.ChainTypeFilter, Hooknum: hook.hook, Priority: nftables.ChainPriorityFirst}
			if b.forwardScopes[i].cilium {
				conn.FlushChain(restore)
			} else {
				conn.AddChain(restore)
			}
			if !scope.cilium {
				conn.DelChain(restore)
				continue
			}
			match := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(family)}},
				&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			}
			match = append(match, nativeConnmarkMatch...)
			match = appendServiceMarkMatch(match, ciliumMarkMask, ciliumRoutedIdentity)
			conn.AddRule(&nftables.Rule{Table: table, Chain: restore, Exprs: appendRouteMark(match, ciliumRouteBit, 0)})
		}
	}
	// Release the policy routing discriminator before Calico's egress program
	// performs reverse NAT. Keep the rest of the skb mark untouched.
	if bit := b.options.autoRouteDNATDiscriminator(); bit != 0 && (scope.calicoWorkloads || b.forwardScopes[i].calicoWorkloads) {
		restore := &nftables.Chain{Name: "service_restore_post" + suffix, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityMangle}
		if b.forwardScopes[i].calicoWorkloads {
			conn.FlushChain(restore)
		} else {
			conn.AddChain(restore)
		}
		if !scope.calicoWorkloads {
			conn.DelChain(restore)
		}
		for _, uplink := range scope.uplinks {
			if !scope.calicoWorkloads {
				break
			}
			match := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(family)}},
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("cali")},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftablesIfname(uplink)},
			}
			match = appendServiceMarkMatch(match, b.options.autoRouteDNATBypassMask(), b.options.autoRouteDNATBypassMark())
			conn.AddRule(&nftables.Rule{Table: table, Chain: restore, Exprs: appendRouteMark(match, bit, 0)})
		}
	}
	if len(b.forwardScopes[i].backends) == 0 {
		conn.AddChain(chain)
		if err = conn.AddSet(set, nil); err != nil {
			return err
		}
	} else {
		conn.FlushChain(chain)
		if b.forwardScopes[i].calicoWorkloads && !scope.calicoWorkloads {
			conn.DelChain(queue)
		}
		if len(elems) == 0 {
			conn.DelChain(chain)
			conn.DelSet(set)
			return conn.Flush()
		}
		conn.FlushSet(set)
	}
	for len(elems) > 0 {
		count := len(elems)
		if count > 1000 {
			count = 1000
		}
		if err = conn.SetAddElements(set, elems[:count]); err != nil {
			return err
		}
		elems = elems[count:]
	}
	if scope.calicoWorkloads {
		if b.forwardScopes[i].calicoWorkloads {
			conn.FlushChain(queue)
		} else {
			conn.AddChain(queue)
		}
		// A queued packet resumes at the next netfilter hook on accept or
		// bypass. Distinguish unmarked packets from FIB probes before queueing.
		conn.AddRule(&nftables.Rule{Table: table, Chain: queue, Exprs: appendRouteMark(
			appendServiceMarkMatch(nil, ^uint32(0), 0), ^uint32(0), b.forwardedInputMark())})
		conn.AddRule(&nftables.Rule{Table: table, Chain: queue, Exprs: []expr.Any{
			&expr.Queue{Num: scope.queueNumber, Total: 1, Flag: expr.QueueFlagBypass},
		}})
	}
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{byte(family)}},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}})
	mask := b.options.autoRouteDNATBypassMask()
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		transport := []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}}
		if scope.calicoWorkloads {
			match := append(slices.Clone(transport),
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("cali")},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset - length, Len: length},
				&expr.Lookup{SourceRegister: 1, SetID: set.ID, SetName: set.Name})
			if proto == unix.IPPROTO_TCP {
				invalid := append(slices.Clone(match),
					&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
					&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID | expr.CtStateBitUNTRACKED), Xor: make([]byte, 4)},
					&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)})
				invalid = appendServiceMarkMatch(invalid, mask, 0)
				conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: append(invalid, &expr.Verdict{Kind: expr.VerdictJump, Chain: queue.Name})})
			}
			match = append(match,
				&expr.Ct{Key: expr.CtKeyMARK, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)})
			match = appendServiceMarkMatch(match, mask, 0)
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: append(match, &expr.Verdict{Kind: expr.VerdictJump, Chain: queue.Name})})
		}
		for _, up := range scope.uplinks {
			unclassified := []expr.Any{&expr.Ct{Key: expr.CtKeyMARK, Register: 1}}
			if scope.cilium {
				unclassified = append(unclassified, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(ctmask), Xor: make([]byte, 4)})
			}
			unclassified = append(unclassified, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)})
			last := append(slices.Clone(transport),
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftablesIfname(up)},
				&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
				&expr.Lookup{SourceRegister: 1, SetID: set.ID, SetName: set.Name})
			last = append(last, unclassified...)
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: append(last,
				&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(^ctmask), Xor: ctmark},
				&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
			)})
		}
		for direction := byte(0); direction <= 1; direction++ {
			backendOffset := offset
			iifOp, iif := expr.CmpOpNeq, nftablesIfname(b.options.Name)
			if direction == 1 {
				backendOffset -= length
				if scope.calicoWorkloads && !scope.cilium {
					iifOp, iif = expr.CmpOpEq, []byte("cali")
				}
			}
			// Direct BPF delivery can make conntrack see the workload's reply
			// first. Use the packet addresses after validating the uplink.
			native := append(transport,
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: iifOp, Register: 1, Data: iif},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: backendOffset, Len: length},
				&expr.Lookup{SourceRegister: 1, SetID: set.ID, SetName: set.Name},
			)
			native = append(native, nativeConnmarkMatch...)
			if !scope.calicoWorkloads || scope.cilium {
				native = append(native, &expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{direction}})
			}
			if direction == 1 && scope.cilium {
				match := appendServiceMarkMatch(slices.Clone(native), ciliumMarkMask, ciliumIdentity)
				marked := appendRouteMark(match, ciliumRouteBit, ciliumRouteBit)
				conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: append(marked, &expr.Verdict{Kind: expr.VerdictReturn})})
			}
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: appendRouteMark(appendServiceMarkMatch(native, mask, 0), mask, b.options.autoRouteDNATBypassMark())})
		}
	}
	if scope.calicoWorkloads {
		markUnmarkedInput := func(iface []byte, addrOffset uint32) {
			conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: iface},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: addrOffset, Len: length},
				&expr.Lookup{SourceRegister: 1, SetID: set.ID, SetName: set.Name},
				&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(b.forwardedInputMark())},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			}})
		}
		for _, up := range scope.uplinks {
			markUnmarkedInput(nftablesIfname(up), offset)
		}
		markUnmarkedInput([]byte("cali"), offset-length)
	}
	return conn.Flush()
}

func appendServiceMarkMatch(expressions []expr.Any, mask, mark uint32) []expr.Any {
	return append(expressions,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(mask), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
	)
}

func (b *autoRouteDNATBypass) replaceIPTablesServiceForward(i int, scope serviceForwardScope) error {
	path := []string{b.iptablesPath, b.ip6tablesPath}[i]
	chain := b.chainName + "-FWD"
	queue := b.chainName + "-QUEUE"
	nativeMark := b.options.autoRouteOutputMark()
	ctmark := fmt.Sprintf("%#x/%#x", nativeMark, b.serviceConnmarkMask(nativeMark))
	var buf bytes.Buffer
	buf.WriteString("*mangle\n")
	if len(scope.backends) == 0 {
		fmt.Fprintf(&buf, "-D PREROUTING -j %s\n-F %s\n-X %s\n", chain, chain, chain)
	} else {
		fmt.Fprintf(&buf, ":%s - [0:0]\n-F %s\n", chain, chain)
		if len(b.forwardScopes[i].backends) == 0 {
			fmt.Fprintf(&buf, "-I PREROUTING -j %s\n", chain)
		}
	}
	if scope.calicoWorkloads {
		fmt.Fprintf(&buf, ":%s - [0:0]\n-F %s\n", queue, queue)
		fmt.Fprintf(&buf, "-A %s -m mark --mark 0 -j MARK --set-mark %#x\n", queue, b.forwardedInputMark())
		fmt.Fprintf(&buf, "-A %s -j NFQUEUE --queue-num %d --queue-bypass\n", queue, scope.queueNumber)
	} else if b.forwardScopes[i].calicoWorkloads {
		fmt.Fprintf(&buf, "-F %s\n-X %s\n", queue, queue)
	}
	for _, hook := range []string{"INPUT", "FORWARD"} {
		restore := b.chainName + "-" + hook
		if scope.cilium {
			fmt.Fprintf(&buf, ":%s - [0:0]\n-F %s\n", restore, restore)
			if !b.forwardScopes[i].cilium {
				fmt.Fprintf(&buf, "-I %s -j %s\n", hook, restore)
			}
			fmt.Fprintf(&buf, "-A %s -m conntrack --ctdir REPLY -m connmark --mark %s -m mark --mark %#x/%#x -j MARK --set-xmark 0/%#x\n", restore, ctmark, ciliumRoutedIdentity, ciliumMarkMask, ciliumRouteBit)
			fmt.Fprintf(&buf, "-A %s -m conntrack --ctstate DNAT --ctdir REPLY -m mark --mark %#x/%#x -j MARK --set-xmark 0/%#x\n", restore, ciliumRoutedIdentity, ciliumMarkMask, ciliumRouteBit)
		} else if b.forwardScopes[i].cilium {
			fmt.Fprintf(&buf, "-D %s -j %s\n-F %s\n-X %s\n", hook, restore, restore, restore)
		}
	}
	if bit := b.options.autoRouteDNATDiscriminator(); bit != 0 {
		restore := b.chainName + "-POST"
		if scope.calicoWorkloads {
			fmt.Fprintf(&buf, ":%s - [0:0]\n-F %s\n", restore, restore)
			if !b.forwardScopes[i].calicoWorkloads {
				fmt.Fprintf(&buf, "-I POSTROUTING -j %s\n", restore)
			}
			for _, uplink := range scope.uplinks {
				fmt.Fprintf(&buf, "-A %s -i cali+ -o %s -m mark --mark %#x/%#x -j MARK --set-xmark 0/%#x\n",
					restore, strconv.Quote(uplink), b.options.autoRouteDNATBypassMark(), b.options.autoRouteDNATBypassMask(), bit)
			}
		} else if b.forwardScopes[i].calicoWorkloads {
			fmt.Fprintf(&buf, "-D POSTROUTING -j %s\n-F %s\n-X %s\n", restore, restore, restore)
		}
	}
	for _, addr := range scope.backends {
		for _, proto := range []string{"tcp", "udp"} {
			if scope.calicoWorkloads {
				if proto == "tcp" {
					fmt.Fprintf(&buf, "-A %s -i cali+ -s %s -p tcp -m conntrack --ctstate INVALID,UNTRACKED -m mark --mark 0/%#x -j %s\n", chain, addr, b.options.autoRouteDNATBypassMask(), queue)
				}
				fmt.Fprintf(&buf, "-A %s -i cali+ -s %s -p %s -m connmark --mark 0 -m mark --mark 0/%#x -j %s\n", chain, addr, proto, b.options.autoRouteDNATBypassMask(), queue)
			}
			for _, up := range scope.uplinks {
				unclassified := "0"
				if scope.cilium {
					unclassified = fmt.Sprintf("0/%#x", b.serviceConnmarkMask(nativeMark))
				}
				fmt.Fprintf(&buf, "-A %s -i %s -d %s -p %s -m conntrack --ctdir ORIGINAL -m connmark --mark %s -j CONNMARK --set-xmark %s\n", chain, strconv.Quote(up), addr, proto, unclassified, ctmark)
			}
			if scope.cilium {
				// Legacy PREROUTING cannot see the translated destination on
				// the original packet of a host DNAT connection.
				fmt.Fprintf(&buf, "-A %s -s %s -p %s -m conntrack --ctstate DNAT --ctdir REPLY -m mark --mark %#x/%#x -j MARK --set-xmark %#x/%#x\n", chain, addr, proto, ciliumIdentity, ciliumMarkMask, ciliumRouteBit, ciliumRouteBit)
				fmt.Fprintf(&buf, "-A %s ! -i %s -s %s -p %s -m conntrack --ctdir REPLY -m connmark --mark %s -m mark --mark %#x/%#x -j MARK --set-xmark %#x/%#x\n", chain, strconv.Quote(b.options.Name), addr, proto, ctmark, ciliumIdentity, ciliumMarkMask, ciliumRouteBit, ciliumRouteBit)
				fmt.Fprintf(&buf, "-A %s ! -i %s -s %s -p %s -m conntrack --ctdir REPLY -m connmark --mark %s -m mark --mark %#x/%#x -j RETURN\n", chain, strconv.Quote(b.options.Name), addr, proto, ctmark, ciliumRoutedIdentity, ciliumMarkMask)
			}
			nonTun := "! -i " + strconv.Quote(b.options.Name)
			workload := nonTun
			if scope.calicoWorkloads && !scope.cilium {
				workload = "-i cali+"
			}
			matches := []string{nonTun + " -d " + addr.String(), workload + " -s " + addr.String()}
			if !scope.calicoWorkloads || scope.cilium {
				matches[0] += " -m conntrack --ctdir ORIGINAL"
				matches[1] += " -m conntrack --ctdir REPLY"
			}
			for _, match := range matches {
				fmt.Fprintf(&buf, "-A %s -p %s %s -m connmark --mark %s -m mark --mark 0/%#x -j MARK --set-xmark %#x/%#x\n", chain, proto, match, ctmark, b.options.autoRouteDNATBypassMask(), b.options.autoRouteDNATBypassMark(), b.options.autoRouteDNATBypassMask())
			}
		}
		if scope.calicoWorkloads {
			for _, up := range scope.uplinks {
				fmt.Fprintf(&buf, "-A %s -i %s -d %s -m mark --mark 0 -j MARK --set-mark %#x\n", chain, strconv.Quote(up), addr, b.forwardedInputMark())
			}
			fmt.Fprintf(&buf, "-A %s -i cali+ -s %s -m mark --mark 0 -j MARK --set-mark %#x\n", chain, addr, b.forwardedInputMark())
		}
	}
	buf.WriteString("COMMIT\n")
	cmd := exec.Command(path+"-restore", "-w", "5", "--noflush")
	cmd.Stdin = &buf
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install %s: %w: %s", chain, err, output)
	}
	return nil
}
