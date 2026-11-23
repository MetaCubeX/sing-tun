//go:build linux

package tun

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestIPVSDNSOutputUpdateRetry(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			n := newIPVSDNSRuleTestTun()
			n.options.Name = "ipvs-test"
			n.options.IPRoute2RuleIndex = 29000
			n.options.IPRoute2TableIndex = 29001
			b := &autoRouteDNATBypass{options: &n.options, tableName: "sing-tun-route-29001", chainName: "STUN-DNAT-29001", useNFTables: backend == "nftables"}
			if !b.useNFTables {
				path, err := exec.LookPath("iptables")
				require.NoError(t, err)
				b.iptablesPath = path
			}
			require.NoError(t, b.Start())
			t.Cleanup(func() { require.NoError(t, b.Close()) })
			n.dnatBypass = b
			first := ipvsDNSDestination{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("192.0.2.53:1053")}
			second := ipvsDNSDestination{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("192.0.2.53:2053")}
			for _, dst := range []ipvsDNSDestination{first, second} {
				for _, rule := range n.ipvsDNSRules(dst) {
					rule := rule
					t.Cleanup(func() { _ = deleteIPVSDNSRule(rule) })
				}
			}
			list := func() []uint16 {
				rules, err := netlink.RuleList(netlink.FAMILY_V4)
				require.NoError(t, err)
				var ports []uint16
				for _, r := range rules {
					if r.Priority == 29001 && r.Dst == netip.MustParsePrefix("192.0.2.53/32") && r.Dport != nil {
						ports = append(ports, r.Dport.Start)
					}
				}
				return ports
			}
			current, err := n.updateIPVSDNSRules(nil, []ipvsDNSDestination{first}, addIPVSDNSRule, deleteIPVSDNSRule)
			require.NoError(t, err)
			table, path := b.tableName, b.iptablesPath
			b.tableName = strings.Repeat("x", 1024)
			b.iptablesPath = filepath.Join(t.TempDir(), "missing-iptables")
			current, err = n.updateIPVSDNSRules(current, []ipvsDNSDestination{second}, addIPVSDNSRule, deleteIPVSDNSRule)
			b.tableName, b.iptablesPath = table, path
			require.Error(t, err)
			require.ElementsMatch(t, []uint16{1053, 1053, 2053, 2053}, list(), "old routing must survive an uncommitted firewall update")
			require.Equal(t, []ipvsDNSDestination{first}, b.ipvsOutput[0])
			current, err = n.updateIPVSDNSRules(current, []ipvsDNSDestination{second}, addIPVSDNSRule, deleteIPVSDNSRule)
			require.NoError(t, err)
			require.Equal(t, []uint16{2053, 2053}, list())
			_, err = n.updateIPVSDNSRules(current, nil, addIPVSDNSRule, deleteIPVSDNSRule)
			require.NoError(t, err)
			require.Empty(t, list())
			require.Empty(t, b.ipvsOutput[0])
		})
	}
}

func TestIPVSDNSUpdateKeepsHealthyFamilyIndependent(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "backend0")
		n := startTestAutoRoute(t, 0)
		n.routeAccess.Lock()
		defer n.routeAccess.Unlock()
		b := n.dnatBypass
		useLegacyServiceFirewall(t, b)
		ipvs := func(args ...string) {
			t.Helper()
			out, err := exec.Command("ipvsadm", args...).CombinedOutput()
			require.NoError(t, err, "%v: %s", args, out)
		}

		const vip4 = "10.96.0.53:53"
		const vip6 = "[fd52:96::53]:53"
		previous := netip.MustParseAddrPort("10.85.1.27:53")
		replacement := netip.MustParseAddrPort("10.85.1.28:53")
		backend6 := netip.MustParseAddrPort("[fd52:1::27]:53")
		ipvs("-A", "-u", vip4, "-s", "rr")
		ipvs("-a", "-u", vip4, "-r", previous.String(), "-m")
		before, err := n.ipvsDNSBypass.Load()
		require.NoError(t, err)
		require.Equal(t, []ipvsDNSDestination{{unix.IPPROTO_UDP, previous}}, before)
		current, err := n.updateIPVSDNSRules(nil, before, addIPVSDNSRule, deleteIPVSDNSRule)
		require.NoError(t, err)
		hasIPVSRule := func(endpoint netip.AddrPort) bool {
			rules, err := netlink.RuleList(netlink.FAMILY_V4)
			require.NoError(t, err)
			expected := n.ipvsDNSRules(ipvsDNSDestination{unix.IPPROTO_UDP, endpoint})[0]
			for _, rule := range rules {
				if rule.Dst == expected.Dst && rule.Mark == expected.Mark && rule.IifName == "lo" &&
					rule.Table == expected.Table && rule.IPProto == expected.IPProto &&
					rule.Dport != nil && *rule.Dport == *expected.Dport {
					return true
				}
			}
			return false
		}
		require.True(t, hasIPVSRule(previous))
		require.False(t, hasIPVSRule(replacement))

		ipvs("-d", "-u", vip4, "-r", previous.String())
		ipvs("-a", "-u", vip4, "-r", replacement.String(), "-m")
		ipvs("-A", "-u", vip6, "-s", "rr")
		ipvs("-a", "-u", vip6, "-r", backend6.String(), "-m")
		after, err := n.ipvsDNSBypass.Load()
		require.NoError(t, err)
		require.Equal(t, []ipvsDNSDestination{{unix.IPPROTO_UDP, replacement}, {unix.IPPROTO_UDP, backend6}}, after)

		path := b.ip6tablesPath
		defer func() { b.ip6tablesPath = path }()
		b.ip6tablesPath = filepath.Join(t.TempDir(), "unavailable-ip6tables")
		current, err = n.updateIPVSDNSRules(current, after, addIPVSDNSRule, deleteIPVSDNSRule)
		require.ErrorContains(t, err, b.ip6tablesPath+"-restore")
		output, err := exec.Command(b.iptablesPath, "-t", "mangle", "-S", b.ipvsOutputChain()).CombinedOutput()
		require.NoError(t, err, string(output))
		require.Contains(t, string(output), "-d 10.85.1.28/32")
		require.NotContains(t, string(output), "-d 10.85.1.27/32")
		require.True(t, hasIPVSRule(replacement))
		require.False(t, hasIPVSRule(previous), "the IPv4 classifier has already retired this backend")
		for _, endpoint := range []netip.AddrPort{previous, replacement} {
			require.Contains(t, runTestIP(t, "-4", "route", "get", endpoint.Addr().String(), "ipproto", "udp", "dport", "53"), "dev test-tun ")
		}

		b.ip6tablesPath = path
		current, err = n.updateIPVSDNSRules(current, after, addIPVSDNSRule, deleteIPVSDNSRule)
		require.NoError(t, err)
		require.Equal(t, after, current)
		require.Equal(t, after[1:], b.ipvsOutput[1])
	})
}
