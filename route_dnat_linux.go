//go:build linux

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"go4.org/netipx"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

const (
	conntrackStatusDNAT = 1 << 5
	// Limit the bypass mark to bits owned by the output mark within the low 12-bit
	// field (plus at most one high discriminator bit) so foreign mark bits stay intact.
	autoRouteDNATBypassMarkFieldMask = 0xFFF
)

const (
	ipv4ConfPath     = "/proc/sys/net/ipv4/conf"
	srcValidMarkPath = ipv4ConfPath + "/all/src_valid_mark"
)

type autoRouteDNATBypass struct {
	options       *Options
	tableName     string
	chainName     string
	useNFTables   bool
	localDNAT     [2][]netip.Prefix
	srcValidMarks srcValidMarkOwner
	iptablesPath  string
	ip6tablesPath string
	ipvsOutput    [2][]ipvsDNSDestination
	ipvsActive    [2]bool
	dnsRules      [2][]*netlink.Rule
	forwardScopes [2]serviceForwardScope
	calicoQueue   *calicoServiceQueue
	serviceEvents chan<- struct{}
}

func (t *NativeTun) enableAutoRouteDNATBypass(
	prepare func(*Options) (*autoRouteDNATBypass, error),
) {
	bypass, err := prepare(&t.options)
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(
				err,
				"auto-route DNAT bypass unavailable; continuing without Docker DNAT protection",
			))
		}
		return
	}
	t.dnatBypass = bypass
}

func prepareAutoRouteDNATBypass(options *Options) (*autoRouteDNATBypass, error) {
	bypass, err := newAutoRouteDNATBypass(options)
	if err != nil {
		return nil, E.Cause(err, "initialize auto-route DNAT bypass")
	}
	err = bypass.Start()
	if err != nil {
		return nil, E.Cause(err, "start auto-route DNAT bypass")
	}
	return bypass, nil
}

func newAutoRouteDNATBypass(options *Options) (*autoRouteDNATBypass, error) {
	bypass := &autoRouteDNATBypass{
		options:       options,
		tableName:     "sing-tun-route-" + strconv.Itoa(options.IPRoute2TableIndex),
		chainName:     "STUN-DNAT-" + strconv.Itoa(options.IPRoute2TableIndex),
		srcValidMarks: srcValidMarkOwner{tunName: options.Name},
	}
	var err error
	nft, nftErr := nftables.New()
	if nftErr == nil {
		_, nftErr = nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
		_ = nft.CloseLasting()
	}
	if nftErr == nil {
		bypass.useNFTables = true
		return bypass, nil
	}
	if len(options.Inet4Address) > 0 {
		bypass.iptablesPath, err = exec.LookPath("iptables")
		if err != nil {
			return nil, E.Cause(err, "iptables is required for auto-route DNAT bypass")
		}
	}
	if len(options.Inet6Address) > 0 {
		bypass.ip6tablesPath, err = exec.LookPath("ip6tables")
		if err != nil {
			return nil, E.Cause(err, "ip6tables is required for auto-route DNAT bypass")
		}
	}
	return bypass, nil
}

func (o *Options) autoRouteOutputMark() uint32 {
	if o.AutoRedirectOutputMark == 0 {
		return DefaultAutoRedirectOutputMark
	}
	return o.AutoRedirectOutputMark
}

func (o *Options) autoRouteDNATBypassMark() uint32 {
	return o.autoRouteOutputMark() & o.autoRouteDNATBypassMask()
}

func (o *Options) autoRouteDNATBypassMask() uint32 {
	outputMark := o.autoRouteOutputMark()
	mask := outputMark & autoRouteDNATBypassMarkFieldMask
	if mask == 0 {
		mask = outputMark
	} else {
		// A shared low field alone must not look like our routing mark.
		mask |= o.autoRouteDNATDiscriminator()
	}
	if o.AutoRedirectMarkMode {
		difference := o.AutoRedirectInputMark ^ outputMark
		if difference&mask == 0 {
			// Add one distinguishing bit without touching the other mark fields.
			mask |= difference & -difference
		}
	}
	return mask
}

func (o *Options) autoRouteDNATDiscriminator() uint32 {
	mark := o.autoRouteOutputMark()
	if mark&autoRouteDNATBypassMarkFieldMask == 0 {
		return 0
	}
	high := mark &^ autoRouteDNATBypassMarkFieldMask
	return high & -high
}

func (b *autoRouteDNATBypass) Start() error {
	var err error
	// Remove stale rules from an interrupted instance before reusing this table.
	if err = b.cleanupBase(); err != nil {
		return err
	}
	if !b.useNFTables {
		if staleErr := errors.Join(b.cleanupNFTablesBase(), deleteRouteNFTTable(nftables.TableFamilyIPv4, b.tableName+"-dns"), deleteRouteNFTTable(nftables.TableFamilyIPv6, b.tableName+"-dns")); staleErr != nil && b.options.Logger != nil {
			b.options.Logger.Warn(E.Cause(staleErr, "cleanup previous nftables instance"))
		}
	}
	if err = b.cleanupStaleIPTables(); err != nil && b.options.Logger != nil {
		b.options.Logger.Warn(E.Cause(err, "cleanup previous firewall instance"))
	}
	if b.useNFTables {
		err = b.setupNFTables()
	} else {
		err = b.setupIPTables()
	}
	if err != nil {
		return E.Errors(err, b.cleanupBase())
	}
	if len(b.options.Inet4Address) > 0 {
		if err = b.srcValidMarks.syncForRPF(ipv4ConfPath, nil); err != nil && b.options.Logger != nil {
			b.options.Logger.Warn(E.Cause(err, "enable src_valid_mark for strict IPv4 reverse path filtering"))
		}
	}
	if err = b.cleanupDNS(); err != nil && b.options.Logger != nil {
		b.options.Logger.Warn(E.Cause(err, "cleanup optional auto-route DNS rules"))
	}
	return nil
}

func (b *autoRouteDNATBypass) Close() error {
	err := errors.Join(b.cleanupDNS(), b.cleanupBase())
	if b.calicoQueue != nil {
		b.calicoQueue.Close()
		b.calicoQueue = nil
	}
	return errors.Join(err, b.srcValidMarks.close())
}

func (b *autoRouteDNATBypass) cleanupBase() error {
	var err error
	if b.useNFTables {
		err = b.cleanupNFTablesBase()
	} else {
		err = b.cleanupIPTables()
	}
	if err == nil {
		b.ipvsOutput = [2][]ipvsDNSDestination{}
		b.ipvsActive = [2]bool{}
		b.forwardScopes = [2]serviceForwardScope{}
		b.localDNAT = [2][]netip.Prefix{}
	}
	return err
}

func readRPFilter(path string) (int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(string(bytes.TrimSpace(content)))
	if err != nil {
		return 0, err
	}
	if value < 0 || value > 2 {
		return 0, E.New("invalid rp_filter value: ", value)
	}
	return value, nil
}

func (b *autoRouteDNATBypass) setupNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	table := nft.AddTable(&nftables.Table{
		Name:   b.tableName,
		Family: nftables.TableFamilyINet,
	})
	chain := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 2),
		Type:     nftables.ChainTypeFilter,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: dnatMarkExpressions(b.options),
	})
	// Run after DNAT so ordinary traffic to a local address keeps its mark.
	original := append(nftablesDNATStatusExpressions(),
		&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: nftablesIfname("lo")},
	)
	original = appendServiceMarkMatch(original, b.options.autoRouteDNATBypassMask(), 0)
	// Use family-specific tables so conntrack's original destination has
	// an unambiguous address type for the kernel and nft rule readers.
	local, err := b.localDNATDestinations()
	if err != nil {
		return err
	}
	for i := range local {
		if i == 0 && len(b.options.Inet4Address) == 0 || i == 1 && len(b.options.Inet6Address) == 0 {
			continue
		}
		published := b.localDNATChain(i)
		table := nft.AddTable(published.Table)
		nft.AddChain(published)
		chain := nft.AddChain(&nftables.Chain{
			Name: "prerouting", Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 2),
		})
		if !b.options.AutoRedirectMarkMode {
			mark, mask := b.options.translatedDNSRoutingMark()
			for _, protocol := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				match := append(slices.Clone(original),
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
					&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)},
				)
				match = append(appendRouteMark(match, mask, mark), &expr.Verdict{Kind: expr.VerdictReturn})
				nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: match})
			}
		}
		// Only a VIP originally owned by this host gets published-port bypass.
		match := append(slices.Clone(original), &expr.Verdict{Kind: expr.VerdictJump, Chain: published.Name})
		nft.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: match})
		b.addLocalDNATRules(nft, published, local[i])
	}
	if err = nft.Flush(); err != nil {
		return err
	}
	b.localDNAT = local
	return nil
}

func (b *autoRouteDNATBypass) localDNATChain(i int) *nftables.Chain {
	return &nftables.Chain{
		Table: &nftables.Table{Name: b.tableName + "-dnat",
			Family: []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6}[i]},
		Name: "published",
	}
}

func (b *autoRouteDNATBypass) addLocalDNATRules(nft *nftables.Conn, chain *nftables.Chain, local []netip.Prefix) {
	for _, prefix := range local {
		match := []expr.Any{&expr.Ct{Key: expr.CtKeyDST, Register: 1}}
		bits := prefix.Addr().BitLen()
		if prefix.Bits() != bits {
			match = append(match, &expr.Bitwise{SourceRegister: 1, DestRegister: 1,
				Len: uint32(bits / 8), Mask: net.CIDRMask(prefix.Bits(), bits), Xor: make([]byte, bits/8)})
		}
		match = append(match, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: prefix.Addr().AsSlice()})
		nft.AddRule(&nftables.Rule{Table: chain.Table, Chain: chain, Exprs: nativeDNATMark(match, b.options)})
	}
}

func (b *autoRouteDNATBypass) localDNATDestinations() ([2][]netip.Prefix, error) {
	var destinations [2][]netip.Prefix
	for i, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if i == 0 && len(b.options.Inet4Address) == 0 || i == 1 && len(b.options.Inet6Address) == 0 {
			continue
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
		if err != nil {
			return destinations, err
		}
		var builder netipx.IPSetBuilder
		for _, route := range routes {
			if route.Type != unix.RTN_LOCAL || route.Dst == nil {
				continue
			}
			prefix, err := netip.ParsePrefix(route.Dst.String())
			if err != nil {
				return destinations, err
			}
			builder.AddPrefix(prefix)
		}
		addresses, err := builder.IPSet()
		if err != nil {
			return destinations, err
		}
		destinations[i] = addresses.Prefixes()
	}
	return destinations, nil
}

func (b *autoRouteDNATBypass) refreshLocalDNATDestinations() error {
	next, err := b.localDNATDestinations()
	if err != nil {
		return err
	}
	if slices.Equal(next[0], b.localDNAT[0]) && slices.Equal(next[1], b.localDNAT[1]) {
		return nil
	}
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	for i, addresses := range next {
		if slices.Equal(addresses, b.localDNAT[i]) {
			continue
		}
		chain := b.localDNATChain(i)
		nft.FlushChain(chain)
		b.addLocalDNATRules(nft, chain, addresses)
	}
	if err = nft.Flush(); err != nil {
		return err
	}
	b.localDNAT = next
	return nil
}

func deleteRouteNFTTable(family nftables.TableFamily, name string) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	nft.DelTable(&nftables.Table{Name: name, Family: family})
	err = nft.Flush()
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func dnatMarkExpressions(options *Options) []expr.Any {
	expressions := nftablesDNATStatusExpressions()
	expressions = append(expressions,
		&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
	)
	return nativeDNATMark(expressions, options)
}

const ciliumIdentityMask = ciliumMarkMask &^ ciliumRouteBit

func nativeDNATMark(expressions []expr.Any, options *Options) []expr.Any {
	expressions = append(expressions,
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(ciliumIdentityMask), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(ciliumIdentity)},
	)
	if options.AutoRedirectMarkMode {
		expressions = append(expressions,
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(options.AutoRedirectInputMark),
			},
		)
	}
	return appendRouteMark(expressions, options.autoRouteDNATBypassMask(), options.autoRouteDNATBypassMark())
}

func appendRouteMark(expressions []expr.Any, clearMask, xorMask uint32) []expr.Any {
	return append(expressions,
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^clearMask),
			Xor:            binaryutil.NativeEndian.PutUint32(xorMask),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
		&expr.Counter{},
	)
}

func (b *autoRouteDNATBypass) setupIPTables() error {
	markMask := b.options.autoRouteDNATBypassMask()
	identity := fmt.Sprintf("%#x/%#x", ciliumIdentity, ciliumIdentityMask)
	for _, path := range []string{b.iptablesPath, b.ip6tablesPath} {
		if path == "" {
			continue
		}
		if err := runIPTables(path, "-t", "mangle", "-N", b.chainName); err != nil {
			return err
		}
		if !b.options.AutoRedirectMarkMode {
			mark, mask := b.options.translatedDNSRoutingMark()
			for _, protocol := range []string{"tcp", "udp"} {
				if err := runIPTables(path, "-t", "mangle", "-A", b.chainName,
					"!", "-i", "lo",
					"-m", "addrtype", "--dst-type", "LOCAL", "-m", "conntrack", "--ctdir", "ORIGINAL",
					"-p", protocol, "--dport", "53", "-m", "mark", "--mark", "0",
					"-j", "MARK", "--set-xmark", fmt.Sprintf("%#x/%#x", mark, mask)); err != nil {
					return err
				}
			}
		}
		if err := runIPTables(
			path, "-t", "mangle", "-A", b.chainName,
			"!", "-i", "lo",
			"-m", "addrtype", "--dst-type", "LOCAL",
			"-m", "mark", "--mark", "0",
			"-j", "MARK", "--set-xmark", fmt.Sprintf("%#x/%#x", b.options.autoRouteDNATBypassMark(), markMask),
		); err != nil {
			return err
		}
		reply := []string{path, "-t", "mangle", "-A", b.chainName,
			"-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "REPLY",
			"-m", "mark", "!", "--mark", identity}
		if b.options.AutoRedirectMarkMode {
			reply = append(reply, "-m", "mark", "!", "--mark", fmt.Sprintf("%#x", b.options.AutoRedirectInputMark))
		}
		reply = append(reply, "-j", "MARK", "--set-xmark", fmt.Sprintf("%#x/%#x", b.options.autoRouteDNATBypassMark(), markMask))
		if err := runIPTables(reply[0], reply[1:]...); err != nil {
			return err
		}
		if err := runIPTables(path, "-t", "mangle", "-I", "PREROUTING", "-j", b.chainName); err != nil {
			return err
		}
	}
	return nil
}

func (b *autoRouteDNATBypass) cleanupNFTablesBase() error {
	return errors.Join(deleteRouteNFTTable(nftables.TableFamilyINet, b.tableName),
		deleteRouteNFTTable(nftables.TableFamilyIPv4, b.tableName+"-ipvs"),
		deleteRouteNFTTable(nftables.TableFamilyIPv6, b.tableName+"-ipvs"),
		deleteRouteNFTTable(nftables.TableFamilyIPv4, b.tableName+"-dnat"),
		deleteRouteNFTTable(nftables.TableFamilyIPv6, b.tableName+"-dnat"))
}

type iptablesChainRef struct {
	hook  string
	chain string
}

func (b *autoRouteDNATBypass) mangleChains() []iptablesChainRef {
	return []iptablesChainRef{
		{hook: "PREROUTING", chain: b.chainName},
		{hook: "OUTPUT", chain: b.ipvsOutputChain()},
		{hook: "PREROUTING", chain: b.ipvsReplyChain()},
		{hook: "PREROUTING", chain: b.chainName + "-FWD"},
		{hook: "", chain: b.chainName + "-QUEUE"},
		{hook: "INPUT", chain: b.chainName + "-INPUT"},
		{hook: "FORWARD", chain: b.chainName + "-FORWARD"},
		{hook: "POSTROUTING", chain: b.chainName + "-POST"},
	}
}

func legacyIPTablesHasTable(ipv6 bool, table string) bool {
	procPath := "/proc/net/ip_tables_names"
	if ipv6 {
		procPath = "/proc/net/ip6_tables_names"
	}
	data, err := os.ReadFile(procPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == table {
			return true
		}
	}
	return false
}

func nftablesHasXTables(family nftables.TableFamily) (mangle, raw bool, ok bool) {
	nft, err := nftables.New()
	if err != nil {
		return false, false, false
	}
	defer nft.CloseLasting()
	tables, err := nft.ListTablesOfFamily(family)
	if err != nil {
		return false, false, false
	}
	for _, table := range tables {
		switch table.Name {
		case "mangle":
			mangle = true
		case "raw":
			raw = true
		}
	}
	return mangle, raw, true
}

func (b *autoRouteDNATBypass) cleanupStaleIPTables() error {
	var err error
	for i, active := range []string{b.iptablesPath, b.ip6tablesPath} {
		if active == "" {
			continue
		}
		if strings.HasSuffix(active, "-legacy") && !legacyIPTablesHasTable(i == 1, "raw") {
			continue
		}
		err = errors.Join(err, cleanupIPTablesChain(active, "raw", "OUTPUT", b.chainName))
	}
	for i, tool := range []string{"iptables", "ip6tables"} {
		ipv6 := i == 1
		family := nftables.TableFamilyIPv4
		if ipv6 {
			family = nftables.TableFamilyIPv6
		}
		probedExplicit := false
		for _, backend := range []string{"-legacy", "-nft", ""} {
			if backend == "" && probedExplicit {
				break
			}
			path, lookupErr := exec.LookPath(tool + backend)
			if lookupErr != nil {
				continue
			}
			if backend != "" {
				probedExplicit = true
			}
			if path == b.iptablesPath || path == b.ip6tablesPath {
				continue
			}
			checkMangle, checkRaw := true, true
			switch backend {
			case "-legacy":
				checkMangle = legacyIPTablesHasTable(ipv6, "mangle")
				checkRaw = legacyIPTablesHasTable(ipv6, "raw")
			case "-nft":
				if hasMangle, hasRaw, ok := nftablesHasXTables(family); ok {
					checkMangle, checkRaw = hasMangle, hasRaw
				}
			}
			if checkMangle {
				err = errors.Join(err, b.cleanupIPTablesPath(path))
			}
			if checkRaw {
				err = errors.Join(err, cleanupIPTablesChain(path, "raw", "OUTPUT", b.chainName))
			}
		}
	}
	return err
}

func (b *autoRouteDNATBypass) cleanupIPTables() error {
	var err error
	for _, path := range []string{b.iptablesPath, b.ip6tablesPath} {
		if path != "" {
			err = errors.Join(err, b.cleanupIPTablesPath(path))
		}
	}
	return err
}

func (b *autoRouteDNATBypass) cleanupIPTablesPath(path string) error {
	return cleanupIPTablesTable(path, "mangle", b.mangleChains())
}

func cleanupIPTablesChain(path, table, hook, chain string) error {
	return cleanupIPTablesTable(path, table, []iptablesChainRef{{hook: hook, chain: chain}})
}

func cleanupIPTablesTable(path, table string, targets []iptablesChainRef) error {
	list, err := outputIPTables(path, "-t", table, "-S")
	if err != nil {
		return err
	}
	targetIndex := make(map[string]int, len(targets))
	for i, target := range targets {
		targetIndex[target.chain] = i
	}
	exists := make([]bool, len(targets))
	var deleteJumps []string
	for _, line := range strings.Split(string(list), "\n") {
		if name, ok := strings.CutPrefix(line, "-N "); ok {
			if idx, matched := targetIndex[name]; matched {
				exists[idx] = true
			}
			continue
		}
		for _, target := range targets {
			if target.hook != "" && line == "-A "+target.hook+" -j "+target.chain {
				deleteJumps = append(deleteJumps, fmt.Sprintf("-D %s -j %s", target.hook, target.chain))
				break
			}
		}
	}
	anyExists := false
	for _, found := range exists {
		if found {
			anyExists = true
			break
		}
	}
	if !anyExists && len(deleteJumps) == 0 {
		return nil
	}
	var script strings.Builder
	fmt.Fprintf(&script, "*%s\n", table)
	for _, rule := range deleteJumps {
		script.WriteString(rule)
		script.WriteByte('\n')
	}
	for i, target := range targets {
		if exists[i] {
			fmt.Fprintf(&script, "-F %s\n", target.chain)
		}
	}
	for i, target := range targets {
		if exists[i] {
			fmt.Fprintf(&script, "-X %s\n", target.chain)
		}
	}
	script.WriteString("COMMIT\n")
	cmd := exec.Command(path+"-restore", "--wait", "5", "--noflush")
	cmd.Stdin = strings.NewReader(script.String())
	if output, err := cmd.CombinedOutput(); err != nil {
		return E.Extend(err, fmt.Sprintf("%s-restore -t %s: %s", path, table, output))
	}
	return nil
}

func outputIPTables(path string, args ...string) ([]byte, error) {
	output, err := exec.Command(path, append([]string{"-w", "5"}, args...)...).CombinedOutput()
	if err != nil {
		return nil, E.Extend(err, fmt.Sprintf("%s %v: %s", path, args, output))
	}
	return output, nil
}

func runIPTables(path string, args ...string) error {
	_, err := outputIPTables(path, args...)
	return err
}

func nftablesDNATStatusExpressions() []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATUS,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(conntrackStatusDNAT),
			Xor:            make([]byte, 4),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(conntrackStatusDNAT),
		},
	}
}
