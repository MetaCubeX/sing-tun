//go:build linux

package tun

import (
	"github.com/metacubex/sing/common/ranges"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
)

func TestAutoRoutePolicyPriorityBudget(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6", "dual"} {
		t.Run(family, func(t *testing.T) {
			n := &NativeTun{options: Options{
				Name: "dns-tun", AutoRoute: true, IPRoute2TableIndex: 19001, IPRoute2RuleIndex: 19000,
				IncludeInterface: []string{"lo"}, ExcludeUID: []ranges.Range[uint32]{{Start: 42, End: 42}},
			}, dnatBypass: &autoRouteDNATBypass{}, ipvsDNSBypass: &autoRouteIPVSDNSBypass{}}
			if family != "ipv6" {
				n.options.Inet4Address = []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}
			}
			if family != "ipv4" {
				n.options.Inet6Address = []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}
			}
			for _, rule := range n.rules() {
				if rule.Goto >= 0 {
					require.Greater(t, rule.Goto, rule.Priority, "policy jump must move forward: %v", rule)
				}
				if rule.Table == 19001 {
					require.Less(t, rule.Priority, 19010, "bypass target must follow every TUN lookup")
				}
			}
		})
	}
}
