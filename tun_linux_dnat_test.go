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
	"strings"
	"testing"
	"time"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	"github.com/metacubex/sing/common/logger"
	"github.com/sagernet/netlink"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type warningRecorder struct {
	logger.Logger
	warnings []string
}

func (r *warningRecorder) Warn(args ...any) {
	r.warnings = append(r.warnings, fmt.Sprint(args...))
}

func TestAutoRouteDNATBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		dnatBypass: &autoRouteDNATBypass{},
		options: Options{
			AutoRoute:              true,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2RuleIndex:      DefaultIPRoute2RuleIndex,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet4RouteAddress:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
	}

	rules := nativeTun.rules()
	require.NotEmpty(t, rules)
	require.Equal(t, DefaultIPRoute2RuleIndex, rules[0].Priority)
	require.True(t, rules[0].MarkSet)
	require.Equal(t, uint32(0x2024), rules[0].Mark)
	require.Equal(t, 0x2FFF, rules[0].Mask)
	require.Equal(t, DefaultIPRoute2RuleIndex+10, rules[0].Goto)
}

func TestAutoRedirectDNATBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		dnatBypass: &autoRouteDNATBypass{},
		options: Options{
			AutoRoute:              true,
			AutoRedirectMarkMode:   true,
			AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2RuleIndex:      DefaultIPRoute2RuleIndex,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
	}

	rules := nativeTun.rules()
	require.GreaterOrEqual(t, len(rules), 6)
	for _, index := range []int{0, 3} {
		require.True(t, rules[index].MarkSet)
		require.Equal(t, uint32(0x2024), rules[index].Mark)
		require.Equal(t, 0x2FFF, rules[index].Mask)
	}
}

func TestAutoRouteWithoutDNATBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		options: Options{
			AutoRoute:              true,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2RuleIndex:      DefaultIPRoute2RuleIndex,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet4RouteAddress:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
	}

	for _, rule := range nativeTun.rules() {
		require.False(t,
			rule.MarkSet &&
				rule.Goto == DefaultIPRoute2RuleIndex+10,
			"DNAT bypass rule must not be installed without an active firewall backend",
		)
	}
}

func TestEnableAutoRouteDNATBypassDegradesOnUnavailableBackend(t *testing.T) {
	testLogger := &warningRecorder{Logger: logger.NOP()}
	nativeTun := &NativeTun{
		options: Options{Logger: testLogger},
	}

	nativeTun.enableAutoRouteDNATBypass(func(*Options) (*autoRouteDNATBypass, error) {
		return nil, errors.New("no firewall backend")
	})

	require.Nil(t, nativeTun.dnatBypass)
	require.Len(t, testLogger.warnings, 1)
	require.True(t, strings.Contains(testLogger.warnings[0], "continuing without Docker DNAT protection"))
}

func TestDNATMarkExpressions(t *testing.T) {
	options := &Options{AutoRedirectOutputMark: DefaultAutoRedirectOutputMark}
	expressions := dnatMarkExpressions(options)
	require.Len(t, expressions, 9)

	status, loaded := expressions[0].(*expr.Ct)
	require.True(t, loaded)
	require.Equal(t, expr.CtKeySTATUS, status.Key)

	require.Equal(t, expr.CtKeyDIRECTION, expressions[3].(*expr.Ct).Key)
	require.Equal(t, []byte{1}, expressions[4].(*expr.Cmp).Data)
	mark, loaded := expressions[5].(*expr.Meta)
	require.True(t, loaded)
	require.Equal(t, expr.MetaKeyMARK, mark.Key)
	require.False(t, mark.SourceRegister)

	mask, loaded := expressions[6].(*expr.Bitwise)
	require.True(t, loaded)
	require.Equal(t, binaryutil.NativeEndian.PutUint32(^uint32(0x2FFF)), mask.Mask)
	require.Equal(t, binaryutil.NativeEndian.PutUint32(0x2024), mask.Xor)

	meta, loaded := expressions[7].(*expr.Meta)
	require.True(t, loaded)
	require.Equal(t, expr.MetaKeyMARK, meta.Key)
	require.True(t, meta.SourceRegister)
}

func TestDNATMarkExpressionsExcludeAutoRedirectInputMark(t *testing.T) {
	options := &Options{
		AutoRedirectMarkMode:  true,
		AutoRedirectInputMark: DefaultAutoRedirectInputMark,
	}
	expressions := dnatMarkExpressions(options)
	require.Len(t, expressions, 11)
	mark, loaded := expressions[5].(*expr.Meta)
	require.True(t, loaded)
	require.Equal(t, expr.MetaKeyMARK, mark.Key)
	compare, loaded := expressions[6].(*expr.Cmp)
	require.True(t, loaded)
	require.Equal(t, expr.CmpOpNeq, compare.Op)
}

func TestAutoRouteDNATBypassUsesDefaultMark(t *testing.T) {
	options := Options{}
	require.Equal(t, uint32(0x2024), options.autoRouteDNATBypassMark())
}

func TestAutoRouteDNATBypassUsesConfiguredMarkField(t *testing.T) {
	options := Options{AutoRedirectOutputMark: 0x12345678}
	require.Equal(t, uint32(0x1678), options.autoRouteDNATBypassMark())
	require.Equal(t, uint32(0x1FFF), options.autoRouteDNATBypassMask())
}

func TestAutoRouteDNATBypassUsesConfiguredHighMark(t *testing.T) {
	options := Options{AutoRedirectOutputMark: 0x5000}
	require.Equal(t, uint32(0x5000), options.autoRouteDNATBypassMark())
	require.Equal(t, uint32(0x5000), options.autoRouteDNATBypassMask())
}

func TestAutoRedirectDNATBypassDoesNotMatchInputMark(t *testing.T) {
	for _, test := range []struct {
		name                string
		input, output, mask uint32
	}{
		{"default", 0x2023, 0x2024, 0x2fff},
		{"high output shares input bit", 0x2023, 0x2000, 0x2001},
		{"same low field", 0x2023, 0x1023, 0x1fff},
		{"highest distinguishing bit", 0x80000023, 0x23, 0x80000fff},
		{"nonconflicting high output", 0x2023, 0x5000, 0x5000},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := Options{AutoRoute: true, AutoRedirectMarkMode: true,
				AutoRedirectInputMark: test.input, AutoRedirectOutputMark: test.output,
				Inet4Address:       []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
				Inet6Address:       []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
				IPRoute2TableIndex: 19001, IPRoute2RuleIndex: 19000}
			n := &NativeTun{options: options, dnatBypass: &autoRouteDNATBypass{}}
			require.Equal(t, test.mask, options.autoRouteDNATBypassMask())
			for _, index := range []int{0, 3} {
				bypass, input := n.rules()[index], n.rules()[index+1]
				require.Equal(t, int(test.mask), bypass.Mask)
				require.NotEqual(t, bypass.Mark, test.input&uint32(bypass.Mask), "input must not take the bypass jump")
				require.Equal(t, test.input, input.Mark)
				require.Equal(t, 19001, input.Table)
			}
			expressions := dnatMarkExpressions(&options)
			operation, ok := expressions[len(expressions)-3].(*expr.Bitwise)
			require.True(t, ok)
			require.Equal(t, binaryutil.NativeEndian.PutUint32(^test.mask), operation.Mask)
			require.Equal(t, binaryutil.NativeEndian.PutUint32(options.autoRouteDNATBypassMark()), operation.Xor)
		})
	}
}

func TestAutoRedirectRejectsIdenticalMarksBeforeOpeningTUN(t *testing.T) {
	for _, output := range []uint32{0x2024, 0} {
		_, err := New(Options{AutoRoute: true, AutoRedirectMarkMode: true, AutoRedirectInputMark: 0x2024, AutoRedirectOutputMark: output})
		require.ErrorContains(t, err, "input and output marks must be different")
	}
}

func TestAutoRedirectDisablesNFTables(t *testing.T) {
	options := &Options{}
	redirect, err := NewAutoRedirect(AutoRedirectOptions{
		TunOptions:      options,
		DisableNFTables: true,
	})
	require.NoError(t, err)
	require.False(t, redirect.(*autoRedirect).useNFTables)
}

func createIPv4Conf(t *testing.T, allRPFilter string, defaultRPFilter string, interfaceRPFilter string) string {
	t.Helper()
	confPath := t.TempDir()
	for name, rpFilter := range map[string]string{
		"all":     allRPFilter,
		"default": defaultRPFilter,
		"eth0":    interfaceRPFilter,
	} {
		path := confPath + "/" + name
		require.NoError(t, os.MkdirAll(path, 0o700))
		require.NoError(t, os.WriteFile(path+"/rp_filter", []byte(rpFilter), 0o600))
		require.NoError(t, os.WriteFile(path+"/src_valid_mark", []byte("0"), 0o600))
	}
	require.NoError(t, os.WriteFile(confPath+"/all/src_valid_mark", []byte("0"), 0o600))
	return confPath
}

func TestAutoRouteDNATBypassNFTables(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a Linux network namespace with CAP_NET_ADMIN")
	}
	bypass := &autoRouteDNATBypass{
		options: &Options{
			Name:                   "dns-test",
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2TableIndex:     DefaultIPRoute2TableIndex,
			IPRoute2RuleIndex:      19000,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
		tableName:   "sing-tun-route-test",
		useNFTables: true,
	}
	confValue := func(iface, key string) string {
		t.Helper()
		value, err := os.ReadFile(ipv4ConfPath + "/" + iface + "/" + key)
		require.NoError(t, err)
		return string(bytes.TrimSpace(value))
	}
	interfaces, err := os.ReadDir(ipv4ConfPath)
	require.NoError(t, err)
	initial := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		initial[iface.Name()] = confValue(iface.Name(), "src_valid_mark")
	}
	require.NoError(t, bypass.Start())
	t.Cleanup(func() { require.NoError(t, bypass.Close()) })
	bypass.startDNS()
	allRPF, allMark := confValue("all", "rp_filter"), confValue("all", "src_valid_mark")
	for iface := range initial {
		rpf := confValue(iface, "rp_filter")
		if iface != "all" && iface != "default" && rpf != "2" && allRPF != "2" && (rpf == "1" || allRPF == "1") {
			require.True(t, allMark == "1" || confValue(iface, "src_valid_mark") == "1", iface)
		}
	}
	nft, err := nftables.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = nft.CloseLasting() })
	_, err = nft.ListTableOfFamily(bypass.tableName+"-dns", nftables.TableFamilyIPv4)
	require.NoError(t, err)
	_, err = nft.ListTableOfFamily(bypass.tableName+"-dns", nftables.TableFamilyIPv6)
	require.NoError(t, err)
	require.NoError(t, bypass.Close())
	for iface, mark := range initial {
		require.Equal(t, mark, confValue(iface, "src_valid_mark"), iface)
	}

	_, err = nft.ListTableOfFamily(bypass.tableName, nftables.TableFamilyINet)
	require.Error(t, err)
	_, err = nft.ListTableOfFamily(bypass.tableName+"-dns", nftables.TableFamilyIPv4)
	require.Error(t, err)
	_, err = nft.ListTableOfFamily(bypass.tableName+"-dns", nftables.TableFamilyIPv6)
	require.Error(t, err)
}

func TestDNSChainFailureKeepsPublishedPortBypass(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	recorder := &warningRecorder{Logger: logger.NOP()}
	b := &autoRouteDNATBypass{
		options: &Options{Name: "dns-test", Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			IPRoute2RuleIndex: 19000, IPRoute2TableIndex: 19001, Logger: recorder},
		useNFTables: true, tableName: "sing-tun-dns-failure",
	}
	nft, err := nftables.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = nft.CloseLasting() })
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	require.NoError(t, b.Start())
	table := nft.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: b.tableName + "-dns"})
	// A chain with a different hook makes the kernel reject the DNS batch.
	nft.AddChain(&nftables.Chain{Table: table, Name: "output", Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter})
	require.NoError(t, nft.Flush())
	b.startDNS()
	core, err := nft.ListTableOfFamily(b.tableName, nftables.TableFamilyINet)
	require.NoError(t, err)
	require.NotEmpty(t, recorder.warnings)
	require.Nil(t, b.dnsRules[0], "failed DNS setup must remove its policy rule")
	checkDNSPolicyCount(t, 19000, 0)
	// Deliver a translated packet through loopback and observe the original
	// DNAT mark counter while the DNS extension is unavailable.
	require.NoError(t, exec.Command("ip", "link", "set", "lo", "up").Run())
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.LocalAddr().(*net.UDPAddr).Port
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("table ip dnat_port_test {\nchain out { type nat hook output priority -100; ip daddr 127.0.0.2 udp dport %d dnat to 127.0.0.1; }\n}\n", port))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { require.NoError(t, deleteRouteNFTTable(nftables.TableFamilyIPv4, "dnat_port_test")) })
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte("published"))
	require.NoError(t, err)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 64)
	n, _, err := listener.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "published", string(buf[:n]))
	rules, err := nft.GetRules(core, &nftables.Chain{Name: "local_destination", Table: core})
	require.NoError(t, err)
	require.NotEmpty(t, rules)
	counter := rules[0].Exprs[len(rules[0].Exprs)-1].(*expr.Counter)
	require.Positive(t, counter.Packets)
	require.NoError(t, deleteRouteNFTTable(nftables.TableFamilyIPv4, table.Name))
	b.startDNS()
	require.NotNil(t, b.dnsRules[0], "setup must succeed after the conflicting chain is gone")
	checkDNSPolicyCount(t, 19000, 2)
	require.NoError(t, b.Close())
	checkDNSPolicyCount(t, 19000, 0)
}

func checkDNSPolicyCount(t *testing.T, priority, count int) {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	require.NoError(t, err)
	matched := 0
	for _, rule := range rules {
		if rule.Priority == priority {
			matched++
		}
	}
	require.Equal(t, count, matched)
}

func TestDNSMarkRespectsExplicitOutputMark(t *testing.T) {
	for _, output := range []uint32{0, 0x2024, 0x24, 0x5000, 0x12345678, 0xffffffff} {
		o := Options{AutoRedirectOutputMark: output}
		b := autoRouteDNATBypass{options: &o}
		mark, mask := b.dnsRoutingMark()
		if output == 0 {
			output = DefaultAutoRedirectOutputMark
		}
		require.NotEqual(t, output&mask, mark)
		require.Equal(t, o.autoRouteDNATBypassMark(), mark&o.autoRouteDNATBypassMask())
		require.Zero(t, mark&^mask)
	}
}

func TestDNSPolicyPreservesHighMaskBit(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	for _, output := range []uint32{0x80000024, 0x80000000} {
		b := &autoRouteDNATBypass{options: &Options{Name: "dns-test", IPRoute2RuleIndex: 19000,
			IPRoute2TableIndex: 19001, AutoRedirectOutputMark: output,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}, useNFTables: true, tableName: "sing-tun-dns-mask"}
		require.NoError(t, b.Start())
		t.Cleanup(func() { require.NoError(t, b.Close()) })
		require.NoError(t, b.startDNSFamily(0, b.options.Inet4Address))
		mark, mask := b.dnsRoutingMark()
		rules, err := netlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		count := 0
		for _, rule := range rules {
			if rule.Priority == 19000 {
				require.Equal(t, mark, rule.Mark)
				require.Equal(t, mask, uint32(rule.Mask))
				require.Equal(t, netip.MustParsePrefix("198.18.0.1/32"), rule.Src)
				require.Equal(t, "lo", rule.IifName)
				require.Equal(t, netlink.NewRulePortRange(53, 53), rule.Dport)
				if count == 0 {
					require.Equal(t, unix.RT_TABLE_MAIN, rule.Table)
					require.Equal(t, 0, rule.SuppressPrefixlen)
				} else {
					require.Equal(t, 19001, rule.Table)
				}
				count++
			}
		}
		require.Equal(t, 2, count)
		bypass := netlink.NewRule()
		bypass.Family, bypass.Priority, bypass.Goto = unix.AF_INET, 19002, 19010
		bypass.Mark, bypass.Mask, bypass.MarkSet = b.options.autoRouteDNATBypassMark(), int(b.options.autoRouteDNATBypassMask()), true
		require.NoError(t, setRules([]*netlink.Rule{bypass}))
		rules, err = netlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		found := false
		for _, rule := range rules {
			if rule.Priority == bypass.Priority {
				require.Equal(t, bypass.Mark, rule.Mark)
				require.Equal(t, uint32(bypass.Mask), uint32(rule.Mask))
				require.Equal(t, bypass.Goto, rule.Goto)
				found = true
			}
		}
		require.True(t, found)
		require.NoError(t, deleteAutoRouteRule(bypass))
		require.NoError(t, b.Close())
		checkDNSPolicyCount(t, 19000, 0)
	}
}

func TestDNSFilterFallback(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	b := &autoRouteDNATBypass{options: &Options{Name: "dns-test", IPRoute2RuleIndex: 19000, IPRoute2TableIndex: 19001,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}, tableName: "sing-tun-dns-filter", useNFTables: true}
	require.NoError(t, b.Start())
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	nft, err := nftables.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = nft.CloseLasting() })
	table := nft.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: b.tableName + "-dns"})
	// The existing filter chain rejects conversion to a route chain but
	// allows the fallback transaction to install its rules.
	chain := nft.AddChain(&nftables.Chain{Table: table, Name: "output", Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 1)})
	require.NoError(t, nft.Flush())
	require.NoError(t, b.startDNSFamily(0, b.options.Inet4Address))
	checkDNSPolicyCount(t, 19000, 2)
	rules, err := nft.GetRules(table, chain)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Nil(t, b.dnsRules[0][0].Dport, "the fallback sees the original port before DNAT")
}

func TestDNSFrontendScope(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	require.NoError(t, exec.Command("ip", "link", "set", "lo", "up").Run())
	lo, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	families := []struct{ source, first, second string }{
		{"127.0.0.1", "127.0.0.14", "127.0.0.15"},
		{"::1", "fd00::14", "fd00::15"},
	}
	options := &Options{Name: "lo", IPRoute2RuleIndex: 19000, IPRoute2TableIndex: 19001,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("::1/128")},
		DNSHijack: []DNSHijackRule{
			{Network: "udp", Address: netip.MustParseAddrPort("127.0.0.14:2053")},
			{Network: "udp", Address: netip.MustParseAddrPort("0.0.0.0:2053")},
			{Network: "udp", Address: netip.MustParseAddrPort("[fd00::14%lo]:3053")},
			{Network: "udp", Address: netip.MustParseAddrPort("[fd00::15%other]:3053")},
			{Network: "udp", Address: netip.AddrPortFrom(netip.MustParseAddr("fd00::15").WithZone(fmt.Sprint(lo.Index)), 4053)},
		},
	}
	for _, family := range families {
		for _, entry := range []struct{ network, ip string }{{"udp", family.first}, {"tcp", family.second}} {
			addr := netip.MustParseAddr(entry.ip)
			options.DNSHijack = append(options.DNSHijack, DNSHijackRule{Network: entry.network, Address: netip.AddrPortFrom(addr, 1053)})
			if addr.Is6() {
				cidr := entry.ip + "/128"
				require.NoError(t, exec.Command("ip", "-6", "addr", "add", cidr, "dev", "lo", "nodad").Run())
				t.Cleanup(func() { require.NoError(t, exec.Command("ip", "-6", "addr", "del", cidr, "dev", "lo").Run()) })
			}
		}
	}
	// Observe the packet mark after the original destination has been classified.
	// Count TCP SYNs only so that later ACKs cannot affect the next observation.
	nft, err := nftables.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = nft.CloseLasting() })
	table := &nftables.Table{Name: "dns_frontend_probe", Family: nftables.TableFamilyINet}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table inet dns_frontend_probe {
counter seen {}
counter marked {}
chain output { type filter hook output priority filter; policy accept;
tcp flags & (syn | ack) != syn return
meta l4proto { tcp, udp } th dport { 53, 1053, 2053, 3053, 4053 } jump observe
}
chain observe { counter name seen; meta mark != 0 counter name marked; }
}`)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { require.NoError(t, deleteRouteNFTTable(table.Family, table.Name)) })
	packets := func(t *testing.T, name string) uint64 {
		t.Helper()
		obj, err := nft.GetObject(&nftables.CounterObj{Table: table, Name: name})
		require.NoError(t, err)
		return obj.(*nftables.CounterObj).Packets
	}
	for _, backend := range []string{"nft-filter", "iptables-legacy"} {
		t.Run(backend, func(t *testing.T) {
			b := &autoRouteDNATBypass{options: options, useNFTables: backend == "nft-filter",
				tableName: "sing-tun-scope", chainName: "STUN-SCOPE"}
			if !b.useNFTables {
				b.iptablesPath, err = exec.LookPath("iptables-legacy")
				require.NoError(t, err)
				b.ip6tablesPath, err = exec.LookPath("ip6tables-legacy")
				require.NoError(t, err)
			}
			require.NoError(t, b.Start())
			t.Cleanup(func() { require.NoError(t, b.Close()) })
			require.NoError(t, b.installDNSFamily(0, options.Inet4Address, true))
			require.NoError(t, b.installDNSFamily(1, options.Inet6Address, true))
			for _, family := range families {
				for _, tc := range []struct {
					network, ip string
					port        uint16
					marked      bool
				}{
					{"udp", family.first, 1053, true}, {"udp", family.second, 1053, false},
					{"tcp", family.first, 1053, false}, {"tcp", family.second, 1053, true},
					{"udp", family.second, 2053, true}, {"tcp", family.second, 2053, false},
					{"udp", family.first, 3053, netip.MustParseAddr(family.first).Is6()}, {"udp", family.second, 3053, false},
					{"udp", family.second, 4053, netip.MustParseAddr(family.second).Is6()},
					{"udp", family.first, 53, true}, {"tcp", family.first, 53, true},
				} {
					dest := netip.AddrPortFrom(netip.MustParseAddr(tc.ip), tc.port)
					t.Run(tc.network+"/"+dest.String(), func(t *testing.T) {
						source := netip.AddrPortFrom(netip.MustParseAddr(family.source), 0)
						seen, marked := packets(t, "seen"), packets(t, "marked")
						if tc.network == "tcp" {
							listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(dest))
							require.NoError(t, err)
							defer listener.Close()
							client, err := net.DialTCP("tcp", net.TCPAddrFromAddrPort(source), listener.Addr().(*net.TCPAddr))
							require.NoError(t, err)
							client.Close()
						} else {
							client, err := net.DialUDP("udp", net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(dest))
							require.NoError(t, err)
							defer client.Close()
							_, err = client.Write([]byte("plain UDP"))
							require.NoError(t, err)
						}
						require.Equal(t, seen+1, packets(t, "seen"))
						if tc.marked {
							marked++
						}
						require.Equal(t, marked, packets(t, "marked"), "unexpected DNS mark on %s %s", tc.network, dest)
					})
				}
			}
		})
	}
}

func TestDNSLegacyRollbackKeepsPublishedPortBypass(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	path, err := exec.LookPath("iptables-legacy")
	require.NoError(t, err)
	b := &autoRouteDNATBypass{options: &Options{Name: "dns-test", IPRoute2RuleIndex: 19000, IPRoute2TableIndex: 19001,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}},
		chainName: "STUN-DNAT-TEST", iptablesPath: path}
	require.NoError(t, b.Start())
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	// raw commits before mangle in iptables-restore. Force the second
	// transaction to fail by referring to a nonexistent mangle chain.
	b.chainName = "STUN-MISSING-TEST"
	err = b.startDNSFamily(0, b.options.Inet4Address)
	require.Error(t, err)
	require.Nil(t, b.dnsRules[0])
	checkDNSPolicyCount(t, 19000, 0)
	raw, err := outputIPTables(path, "-t", "raw", "-S")
	require.NoError(t, err)
	require.NotContains(t, string(raw), b.chainName)
	b.chainName = "STUN-DNAT-TEST"
	require.NoError(t, runIPTables(path, "-t", "mangle", "-C", "PREROUTING", "-j", b.chainName))
	require.NoError(t, b.startDNSFamily(0, b.options.Inet4Address))
	checkDNSPolicyCount(t, 19000, 2)
	lock, err := os.CreateTemp(t.TempDir(), "xtables")
	require.NoError(t, err)
	defer lock.Close()
	t.Setenv("XTABLES_LOCKFILE", lock.Name())
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX))
	err = b.closeDNSFamily(0)
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_UN))
	require.Error(t, err)
	checkDNSPolicyCount(t, 19000, 2) // The classifier is still live.
	require.NoError(t, b.Close())
	checkDNSPolicyCount(t, 19000, 0)
	raw, err = outputIPTables(path, "-t", "raw", "-S")
	require.NoError(t, err)
	require.NotContains(t, string(raw), b.chainName)
}

func TestAutoRouteDNATBypassIPTables(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a Linux network namespace with CAP_NET_ADMIN")
	}
	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		t.Skip("iptables is unavailable")
	}
	bypass := &autoRouteDNATBypass{
		options: &Options{
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2TableIndex:     DefaultIPRoute2TableIndex,
		},
		chainName:    "STUN-DNAT-TEST",
		iptablesPath: iptablesPath,
	}
	require.NoError(t, bypass.Start())
	output, err := exec.Command(iptablesPath, "-t", "mangle", "-S", bypass.chainName).CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "--set-xmark 0x2024/0x2fff")
	require.NoError(t, bypass.Close())

	output, err = exec.Command(iptablesPath, "-t", "mangle", "-S", bypass.chainName).CombinedOutput()
	require.Error(t, err, string(output))
}

func TestAutoRouteDNATBypassIPTablesDisambiguatedMask(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a Linux network namespace with CAP_NET_ADMIN")
	}
	path, err := exec.LookPath("iptables")
	require.NoError(t, err)
	bypass := &autoRouteDNATBypass{
		options:   &Options{AutoRedirectMarkMode: true, AutoRedirectInputMark: 0x2023, AutoRedirectOutputMark: 0x2000},
		chainName: "STUN-DNAT-MASK-TEST", iptablesPath: path,
	}
	require.NoError(t, bypass.Start())
	t.Cleanup(func() { _ = bypass.Close() })
	output, err := exec.Command(path, "-t", "mangle", "-S", bypass.chainName).CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "--set-xmark 0x2000/0x2001")
}

func TestDNATCloseReportsIPTablesFailure(t *testing.T) {
	b := &autoRouteDNATBypass{iptablesPath: "/bin/false", chainName: "STUN-DNAT-TEST"}
	require.Error(t, b.Close())
}

func TestDNATCloseWithXTablesLock(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires iptables-legacy in an isolated network namespace")
	}
	path, err := exec.LookPath("iptables-legacy")
	if err != nil {
		path, err = exec.LookPath("iptables")
	}
	require.NoError(t, err)
	version, err := exec.Command(path, "-V").CombinedOutput()
	require.NoError(t, err)
	if strings.Contains(string(version), "nf_tables") {
		t.Skip("xtables file lock is only used by the legacy backend")
	}
	lock, err := os.CreateTemp(t.TempDir(), "xtables")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lock.Close() })
	t.Setenv("XTABLES_LOCKFILE", lock.Name())
	b := &autoRouteDNATBypass{options: &Options{}, chainName: "STUN-LOCK-TEST", iptablesPath: path}
	require.NoError(t, b.Start())
	t.Cleanup(func() { _ = b.Close() })
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX))
	err = b.Close()
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_UN))
	require.Error(t, err, "cleanup must report an unresolved lock")
	require.NoError(t, b.Close())
	out, err := exec.Command(path, "-t", "mangle", "-S").CombinedOutput()
	require.NoError(t, err)
	require.NotContains(t, string(out), b.chainName)
}
