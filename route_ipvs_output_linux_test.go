//go:build linux

package tun

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
				rule := n.ipvsDNSRule(dst)
				t.Cleanup(func() { _ = deleteIPVSDNSRule(rule) })
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
			b.tableName = "missing-ipvs-test-table"
			b.iptablesPath = filepath.Join(t.TempDir(), "missing-iptables")
			current, err = n.updateIPVSDNSRules(current, []ipvsDNSDestination{second}, addIPVSDNSRule, deleteIPVSDNSRule)
			b.tableName, b.iptablesPath = table, path
			require.Error(t, err)
			require.ElementsMatch(t, []uint16{1053, 2053}, list(), "old routing must survive an uncommitted firewall update")
			require.Equal(t, []ipvsDNSDestination{first}, b.ipvsOutput[0])
			current, err = n.updateIPVSDNSRules(current, []ipvsDNSDestination{second}, addIPVSDNSRule, deleteIPVSDNSRule)
			require.NoError(t, err)
			require.Equal(t, []uint16{2053}, list())
			_, err = n.updateIPVSDNSRules(current, nil, addIPVSDNSRule, deleteIPVSDNSRule)
			require.NoError(t, err)
			require.Empty(t, list())
			require.Empty(t, b.ipvsOutput[0])
		})
	}
}
