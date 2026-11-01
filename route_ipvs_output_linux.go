//go:build linux

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	"golang.org/x/sys/unix"
)

func (b *autoRouteDNATBypass) ipvsOutputChain() string {
	return b.chainName + "-DNS"
}

// IPVS looks up the backend route before translating the packet, without L4 ports.
// Re-route the translated DNS tuple in OUTPUT if that lookup selected this TUN.
// XOR preserves unrelated bits and forces a new lookup even for pre-marked packets.
func (b *autoRouteDNATBypass) updateIPVSDNSOutput(destinations []ipvsDNSDestination) error {
	var families [2][]ipvsDNSDestination
	for _, dst := range destinations {
		if dst.endpoint.Addr().Is4() {
			if len(b.options.Inet4Address) > 0 {
				families[0] = append(families[0], dst)
			}
		} else if len(b.options.Inet6Address) > 0 {
			families[1] = append(families[1], dst)
		}
	}
	var errs []error
	for family, next := range families {
		old := b.ipvsOutput[family]
		if !ipvsDNSDestinationsChanged(old, next) {
			continue
		}
		var err error
		if b.useNFTables {
			err = b.replaceNFTIPVSOutput(family == 1, next)
		} else {
			path := b.iptablesPath
			if family == 1 {
				path = b.ip6tablesPath
			}
			err = b.replaceIPTablesIPVSOutput(path, len(old) > 0, next)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		b.ipvsOutput[family] = next
	}
	return errors.Join(errs...)
}

func (b *autoRouteDNATBypass) replaceNFTIPVSOutput(ipv6 bool, targets []ipvsDNSDestination) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: b.tableName}
	name := "ipvs_dns_output4"
	nfproto := byte(unix.NFPROTO_IPV4)
	offset := uint32(16)
	if ipv6 {
		name, nfproto, offset = "ipvs_dns_output6", unix.NFPROTO_IPV6, 24
	}
	chain := &nftables.Chain{Table: table, Name: name}
	if len(targets) == 0 {
		nft.FlushChain(chain)
		nft.DelChain(chain)
		return nft.Flush()
	}
	chain.Type, chain.Hooknum, chain.Priority = nftables.ChainTypeRoute, nftables.ChainHookOutput, nftables.ChainPriorityMangle
	nft.AddChain(chain)
	nft.FlushChain(chain)
	nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: nftablesIfname(b.options.Name)},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}})
	nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{nfproto}},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}})
	for _, dst := range targets {
		nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: appendRouteMark([]expr.Any{
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(dst.endpoint.Addr().BitLen() / 8)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dst.endpoint.Addr().AsSlice()},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(dst.protocol)}},
			&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(dst.endpoint.Port())},
		}, 0, b.options.autoRouteDNATBypassMark())})
	}
	return nft.Flush()
}

func (b *autoRouteDNATBypass) replaceIPTablesIPVSOutput(path string, existed bool, targets []ipvsDNSDestination) error {
	chain := b.ipvsOutputChain()
	var rules bytes.Buffer
	fmt.Fprintln(&rules, "*mangle")
	if len(targets) == 0 {
		fmt.Fprintf(&rules, "-D OUTPUT -j %s\n-F %s\n-X %s\n", chain, chain, chain)
	} else {
		if existed {
			fmt.Fprintf(&rules, "-F %s\n", chain)
		} else {
			fmt.Fprintf(&rules, ":%s - [0:0]\n-A OUTPUT -j %s\n", chain, chain)
		}
		for _, dst := range targets {
			fmt.Fprintf(&rules, "-A %s -o %s -d %s -p %d --dport %d -j MARK --xor-mark %#x\n",
				chain, strconv.Quote(b.options.Name), dst.endpoint.Addr(), dst.protocol, dst.endpoint.Port(), b.options.autoRouteDNATBypassMark())
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
