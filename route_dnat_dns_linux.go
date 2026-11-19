//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

// Select a subset of the published-port mark, so unrelated socket marks
// retain their routing. One TUN mark bit distinguishes DNS from an explicit
// output mark, even for a socket bound to the TUN source address.
func (b *autoRouteDNATBypass) dnsRoutingMark() (uint32, uint32) {
	output := b.options.autoRouteOutputMark()
	mask := b.options.autoRouteDNATBypassMask()
	bits := output &^ mask
	if bits == 0 {
		bits = (b.options.AutoRedirectInputMark | DefaultAutoRedirectInputMark) &^ mask
	}
	if bits == 0 {
		bits = ^mask
	}
	bit := bits & -bits
	return b.options.autoRouteDNATBypassMark() | (bit &^ output), mask | bit
}

func (t *NativeTun) translatedDNSLookupRule(family, priority int) *netlink.Rule {
	rule := netlink.NewRule()
	mark, mask := t.options.translatedDNSRoutingMark()
	rule.Family, rule.Priority, rule.Table = family, priority, unix.RT_TABLE_MAIN
	rule.Mark, rule.Mask, rule.MarkSet = mark, int(mask), true
	rule.Dport = netlink.NewRulePortRange(53, 53)
	rule.SuppressPrefixlen = 0
	return rule
}

func (b *autoRouteDNATBypass) startDNS() {
	for i, addresses := range [][]netip.Prefix{b.options.Inet4Address, b.options.Inet6Address} {
		if len(addresses) == 0 {
			continue
		}
		if err := b.startDNSFamily(i, addresses); err != nil && b.options.Logger != nil {
			b.options.Logger.Warn(E.Cause(err, "install optional auto-route DNS rules for ", addresses[0].Addr().String()))
		}
	}
}

func (b *autoRouteDNATBypass) startDNSFamily(i int, addresses []netip.Prefix) error {
	// Mark-mode routing already consults the system routes for unmarked
	// traffic. Explicit redirection and bypass marks must keep their meaning.
	if b.options.AutoRedirectMarkMode {
		if !b.useNFTables {
			return cleanupIPTablesChain([]string{b.iptablesPath, b.ip6tablesPath}[i], "raw", "OUTPUT", b.chainName)
		}
		return nil
	}
	if b.useNFTables {
		err := b.installDNSFamily(i, addresses, false)
		if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOENT) {
			return err
		}
		// A filter hook can tag the original DNS request on kernels without
		// route-chain support. Only a subsequent DNAT will repeat the lookup.
		if len(b.dnsRules[i]) != 0 {
			return err
		}
	}
	return b.installDNSFamily(i, addresses, true)
}

func (b *autoRouteDNATBypass) installDNSFamily(i int, addresses []netip.Prefix, beforeNAT bool) error {
	family := []int{unix.AF_INET, unix.AF_INET6}[i]
	mark, mask := b.dnsRoutingMark()
	// A local request that selected this TUN already has a TUN source
	// address. Keep the existing mark for forwarded DNAT, but for this
	// source prefer a specific backend route and otherwise keep the TUN.
	for _, address := range addresses {
		for _, table := range []int{unix.RT_TABLE_MAIN, b.options.IPRoute2TableIndex} {
			rule := netlink.NewRule()
			rule.Family, rule.Priority, rule.IifName = family, b.options.IPRoute2RuleIndex, "lo"
			rule.Src = netip.PrefixFrom(address.Addr(), address.Addr().BitLen())
			rule.Mark, rule.Mask, rule.MarkSet = mark, int(mask), true
			if !beforeNAT {
				rule.Dport = netlink.NewRulePortRange(53, 53)
			}
			rule.Table = table
			if table == unix.RT_TABLE_MAIN {
				rule.SuppressPrefixlen = 0
			}
			if err := addAutoRouteRule(rule); err != nil {
				return errors.Join(err, b.removeDNSPolicy(i))
			}
			b.dnsRules[i] = append(b.dnsRules[i], rule)
		}
	}
	var err error
	if b.useNFTables {
		err = b.setupNFTablesDNS(nftables.TableFamily(family), addresses, beforeNAT)
	} else {
		path := []string{b.iptablesPath, b.ip6tablesPath}[i]
		if err = cleanupIPTablesChain(path, "raw", "OUTPUT", b.chainName); err != nil {
			// A previous classifier may still be active.
			return err
		}
		err = b.setupIPTablesDNS(path, family, addresses)
	}
	if err != nil {
		if b.useNFTables && (errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOENT)) {
			// The kernel rejected this atomic batch. Leave any pre-existing
			// chain in place so the filter fallback can use it.
			return errors.Join(err, b.removeDNSPolicy(i))
		}
		return errors.Join(err, b.closeDNSFamily(i))
	}
	return nil
}

func (b *autoRouteDNATBypass) cleanupDNS() error {
	return errors.Join(b.closeDNSFamily(0), b.closeDNSFamily(1))
}

func (b *autoRouteDNATBypass) closeDNSFamily(i int) error {
	// Retain the restrictive lookups until no classifier can set their
	// mark. This also covers a partially committed xtables restore.
	if b.useNFTables {
		family := []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6}[i]
		if err := deleteRouteNFTTable(family, b.tableName+"-dns"); err != nil {
			return err
		}
	} else if len(b.dnsRules[i]) != 0 {
		if err := cleanupIPTablesChain([]string{b.iptablesPath, b.ip6tablesPath}[i], "raw", "OUTPUT", b.chainName); err != nil {
			return err
		}
	}
	return b.removeDNSPolicy(i)
}

func (b *autoRouteDNATBypass) removeDNSPolicy(i int) error {
	var err error
	for _, rule := range b.dnsRules[i] {
		delErr := deleteAutoRouteRule(rule)
		if !errors.Is(delErr, unix.ENOENT) && !errors.Is(delErr, unix.ESRCH) {
			err = errors.Join(err, delErr)
		}
	}
	if err == nil {
		b.dnsRules[i] = nil
	}
	return err
}

// Port 53 applies to any destination. Before DNAT, custom DNS frontends
// must match the original destination and transport from DNSHijack.
func (b *autoRouteDNATBypass) dnsFrontends(ipv6 bool, proto byte, beforeNAT bool) []netip.AddrPort {
	anyAddr := netip.IPv4Unspecified()
	if ipv6 {
		anyAddr = netip.IPv6Unspecified()
	}
	frontends := []netip.AddrPort{netip.AddrPortFrom(anyAddr, 53)}
	if !beforeNAT {
		return frontends
	}
	network := "udp"
	if proto == unix.IPPROTO_TCP {
		network = "tcp"
	}
	for _, target := range b.options.DNSHijack {
		addr := target.Address.Addr()
		port := target.Address.Port()
		if !addr.IsValid() || port == 0 || port == 53 || (target.Network != "" && target.Network != network) {
			continue
		}
		if zone := addr.Zone(); zone != "" && zone != b.options.Name {
			index, err := strconv.Atoi(zone)
			if err != nil {
				continue
			}
			iface, err := net.InterfaceByIndex(index)
			if err != nil || iface.Name != b.options.Name {
				continue
			}
		}
		if addr.IsUnspecified() {
			addr = anyAddr
		} else if addr.Is6() != ipv6 {
			continue
		}
		// Both classifiers already require the output interface to be this TUN.
		frontend := netip.AddrPortFrom(addr.WithZone(""), port)
		wildcard := netip.AddrPortFrom(anyAddr, port)
		if slices.Contains(frontends, wildcard) || slices.Contains(frontends, frontend) {
			continue
		}
		if frontend == wildcard {
			frontends = slices.DeleteFunc(frontends, func(other netip.AddrPort) bool { return other.Port() == port })
		}
		frontends = append(frontends, frontend)
	}
	return frontends
}

func (b *autoRouteDNATBypass) setupNFTablesDNS(family nftables.TableFamily, addresses []netip.Prefix, beforeNAT bool) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	table := nft.AddTable(&nftables.Table{Name: b.tableName + "-dns", Family: family})
	output := &nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeRoute,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 2)}
	if beforeNAT {
		output.Type = nftables.ChainTypeFilter
		output.Priority = nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 1)
	}
	nft.AddChain(output)
	core := &nftables.Table{Name: b.tableName, Family: nftables.TableFamilyINet}
	pre := &nftables.Chain{Name: "prerouting", Table: core}
	mark, mask := b.dnsRoutingMark()
	sourceOffset, destOffset := uint32(12), uint32(16)
	if family == nftables.TableFamilyIPv6 {
		sourceOffset, destOffset = 8, 24
	}
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		selector := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nftablesIfname(b.options.Name)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(b.options.autoRouteDNATBypassMask()), Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(b.options.autoRouteDNATBypassMark())},
		}
		if !beforeNAT {
			selector = append(selector, &expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}})
			selector = append(selector, nftablesDNATStatusExpressions()...)
		}
		for _, frontend := range b.dnsFrontends(family == nftables.TableFamilyIPv6, proto, beforeNAT) {
			match := append(selector, &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1,
				Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(frontend.Port())})
			if addr := frontend.Addr(); !addr.IsUnspecified() {
				dst := addr.AsSlice()
				match = append(match, &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1,
					Base: expr.PayloadBaseNetworkHeader, Offset: destOffset, Len: uint32(len(dst))},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dst})
			}
			for _, address := range addresses {
				src := address.Addr().AsSlice()
				local := append(match, &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: sourceOffset, Len: uint32(len(src))},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: src})
				nft.AddRule(&nftables.Rule{Table: table, Chain: output, Exprs: appendRouteMark(local, mask, mark)})
			}
		}
		// A DNS reply injected by this TUN must pass reverse-path checking
		// using the TUN route, not the external published-port bypass.
		for _, address := range addresses {
			reply := b.nftDNSReply(family, proto, expr.CmpOpEq, address.Addr())
			for _, port := range []expr.Any{
				&expr.Ct{Key: expr.CtKeyPROTODST, Register: 1, Direction: 0},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			} {
				nft.InsertRule(&nftables.Rule{Table: core, Chain: pre, Exprs: append(reply, port,
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)}, &expr.Verdict{Kind: expr.VerdictReturn})})
			}
			// Preserve the physical return route for a locally bound IPv4
			// socket under strict rp_filter.
			if family == nftables.TableFamilyIPv4 {
				physical := b.nftDNSReply(family, proto, expr.CmpOpNeq, address.Addr())
				if !beforeNAT {
					physical = append(physical, &expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1,
						Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
						&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)})
				}
				nft.InsertRule(&nftables.Rule{Table: core, Chain: pre, Exprs: appendRouteMark(physical, mask, b.options.autoRouteOutputMark()&mask)})
			}
		}
	}
	return nft.Flush()
}

func (b *autoRouteDNATBypass) nftDNSReply(family nftables.TableFamily, proto byte, ifaceOp expr.CmpOp, source netip.Addr) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: ifaceOp, Register: 1, Data: nftablesIfname(b.options.Name)},
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(family)}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		&expr.Ct{Key: expr.CtKeySRC, Register: 1, Direction: 0},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: source.AsSlice()},
	}
}

func (b *autoRouteDNATBypass) setupIPTablesDNS(path string, family int, addresses []netip.Prefix) error {
	var rules strings.Builder
	dev := strconv.Quote(b.options.Name)
	mark, mask := b.dnsRoutingMark()
	fmt.Fprintf(&rules, "*raw\n:%s - [0:0]\n", b.chainName)
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		for _, frontend := range b.dnsFrontends(family == unix.AF_INET6, proto, true) {
			destination := ""
			if addr := frontend.Addr(); !addr.IsUnspecified() {
				destination = " -d " + addr.String()
			}
			for _, address := range addresses {
				fmt.Fprintf(&rules, "-A %s -o %s -s %s%s -p %d --dport %d -m mark ! --mark %#x/%#x -j MARK --set-xmark %#x/%#x\n",
					b.chainName, dev, address.Addr(), destination, proto, frontend.Port(), b.options.autoRouteDNATBypassMark(), b.options.autoRouteDNATBypassMask(), mark, mask)
			}
		}
	}
	fmt.Fprintf(&rules, "-A OUTPUT -j %s\nCOMMIT\n*mangle\n", b.chainName)
	for _, proto := range []string{"tcp", "udp"} {
		for _, addr := range addresses {
			if family == unix.AF_INET {
				fmt.Fprintf(&rules, "-I %s ! -i %s -p %s -m conntrack --ctdir REPLY --ctorigsrc %s -j MARK --set-xmark %#x/%#x\n",
					b.chainName, dev, proto, addr.Addr(), b.options.autoRouteOutputMark()&mask, mask)
			}
			fmt.Fprintf(&rules, "-I %s -i %s -p %s -m conntrack --ctdir REPLY --ctorigsrc %s --ctorigdstport 53 -j RETURN\n", b.chainName, dev, proto, addr.Addr())
			fmt.Fprintf(&rules, "-I %s -i %s -p %s --sport 53 -m conntrack --ctdir REPLY --ctorigsrc %s -j RETURN\n", b.chainName, dev, proto, addr.Addr())
		}
	}
	rules.WriteString("COMMIT\n")
	cmd := exec.Command(path+"-restore", "--wait", "5", "--noflush")
	cmd.Stdin = strings.NewReader(rules.String())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install %s DNS rules: %w: %s", path, err, output)
	}
	return nil
}
