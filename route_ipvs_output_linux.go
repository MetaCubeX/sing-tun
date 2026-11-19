//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	"github.com/metacubex/nftables/xt"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

func (b *autoRouteDNATBypass) ipvsOutputChain() string {
	return b.chainName + "-DNS"
}

func (b *autoRouteDNATBypass) ipvsReplyChain() string {
	return b.chainName + "-IPVS-R"
}

// IPVS looks up the backend route before translating the packet, without L4 ports.
// Re-route the translated DNS tuple in OUTPUT if that lookup selected this TUN.
// Select packets reinjected by IPVS before marking them for a second lookup.
func (b *autoRouteDNATBypass) updateIPVSDNSOutput(family int, next []ipvsDNSDestination) error {
	if family == 0 && len(b.options.Inet4Address) == 0 || family == 1 && len(b.options.Inet6Address) == 0 {
		return nil
	}
	old := b.ipvsOutput[family]
	if slices.Equal(old, next) {
		return nil
	}
	var err error
	if b.useNFTables {
		err = b.replaceNFTIPVSOutput(family == 1, next)
	} else {
		path := b.iptablesPath
		if family == 1 {
			path = b.ip6tablesPath
		}
		err = b.replaceIPTablesIPVSOutput(path, family == 1, len(old) > 0, next)
	}
	if err == nil {
		b.ipvsOutput[family] = next
	}
	return err
}

func (b *autoRouteDNATBypass) replaceNFTIPVSOutput(ipv6 bool, targets []ipvsDNSDestination) error {
	family := nftables.TableFamilyIPv4
	offset := uint32(16)
	if ipv6 {
		family, offset = nftables.TableFamilyIPv6, 24
	}
	tableName := b.tableName + "-ipvs"
	if len(targets) == 0 {
		return deleteRouteNFTTable(family, tableName)
	}
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	table := nft.AddTable(&nftables.Table{Family: family, Name: tableName})
	chain := &nftables.Chain{Table: table, Name: "output"}
	chain.Type, chain.Hooknum, chain.Priority = nftables.ChainTypeRoute, nftables.ChainHookOutput, nftables.ChainPriorityMangle
	nft.AddChain(chain)
	nft.FlushChain(chain)
	nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: nftablesIfname(b.options.Name)},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}})
	// struct xt_ipvs_mtinfo and XT_IPVS_IPVS_PROPERTY from linux/netfilter/xt_ipvs.h.
	ipvs := make(xt.Unknown, 40)
	ipvs[39] = 1
	mark, mask := b.options.translatedDNSRoutingMark()
	var reply *nftables.Chain
	if !ipv6 {
		reply = nft.AddChain(&nftables.Chain{Name: "reply", Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 3)})
		nft.FlushChain(reply)
	}
	for _, dst := range targets {
		nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: appendRouteMark([]expr.Any{
			&expr.Match{Name: "ipvs", Info: &ipvs},
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(dst.endpoint.Addr().BitLen() / 8)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dst.endpoint.Addr().AsSlice()},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(dst.protocol)}},
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(dst.endpoint.Port())},
		}, mask, mark)})
		if reply != nil {
			// Reverse routing swaps the transport ports. Tag only replies
			// tracked against a translated destination, before the lookup.
			addr := dst.endpoint.Addr().AsSlice()
			match := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: nftablesIfname(b.options.Name)},
				&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
				&expr.Ct{Key: expr.CtKeyDST, Register: 1, Direction: 0},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: addr},
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(dst.protocol)}},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(dst.endpoint.Port())},
			}
			match = appendServiceMarkMatch(match, b.options.autoRouteDNATBypassMask(), 0)
			nft.AddRule(&nftables.Rule{Table: table, Chain: reply, Exprs: appendRouteMark(match, mask, mark)})
		}
	}
	return nft.Flush()
}

func (b *autoRouteDNATBypass) replaceIPTablesIPVSOutput(path string, ipv6, existed bool, targets []ipvsDNSDestination) error {
	chain := b.ipvsOutputChain()
	reply := b.ipvsReplyChain()
	var rules bytes.Buffer
	fmt.Fprintln(&rules, "*mangle")
	if len(targets) == 0 {
		fmt.Fprintf(&rules, "-D OUTPUT -j %s\n-F %s\n-X %s\n", chain, chain, chain)
		if !ipv6 {
			fmt.Fprintf(&rules, "-D PREROUTING -j %s\n-F %s\n-X %s\n", reply, reply, reply)
		}
	} else {
		if existed {
			fmt.Fprintf(&rules, "-F %s\n", chain)
			if !ipv6 {
				fmt.Fprintf(&rules, "-F %s\n", reply)
			}
		} else {
			fmt.Fprintf(&rules, ":%s - [0:0]\n-A OUTPUT -j %s\n", chain, chain)
			if !ipv6 {
				fmt.Fprintf(&rules, ":%s - [0:0]\n-A PREROUTING -j %s\n", reply, reply)
			}
		}
		for _, dst := range targets {
			mark, mask := b.options.translatedDNSRoutingMark()
			fmt.Fprintf(&rules, "-A %s -o %s -d %s -p %d --dport %d -m ipvs --ipvs -j MARK --set-xmark %#x/%#x\n",
				chain, strconv.Quote(b.options.Name), dst.endpoint.Addr(), dst.protocol, dst.endpoint.Port(), mark, mask)
			if !ipv6 {
				port := dst.endpoint.Port()
				protocol := "udp"
				if dst.protocol == unix.IPPROTO_TCP {
					protocol = "tcp"
				}
				fmt.Fprintf(&rules, "-A %s ! -i %s -s %s -p %s --sport %d -m conntrack --ctdir REPLY ! --ctorigdst %s -m mark --mark 0/%#x -j MARK --set-xmark %#x/%#x\n",
					reply, strconv.Quote(b.options.Name), dst.endpoint.Addr(), protocol, port, dst.endpoint.Addr(), b.options.autoRouteDNATBypassMask(), mark, mask)
			}
		}
	}
	fmt.Fprintln(&rules, "COMMIT")
	cmd := exec.Command(path+"-restore", "--wait", "5", "--noflush")
	cmd.Stdin = &rules
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("replace %s IPVS DNS rules: %w: %s", path, err, output)
	}
	return nil
}
