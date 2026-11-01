//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestParseIPVSDNSDestinations(t *testing.T) {
	destinations, err := parseIPVSDNSDestinations(strings.NewReader(`IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
TCP  0A0A000A:0035 rr
  -> 0A7ADB47:0035      Masq    1      0          0
  -> 0A7ADB46:0035      Masq    1      0          0
UDP  0A0A000A:0035 rr
  -> 0A7ADB47:0035      Masq    1      0          0
TCP  0A0A9B4E:7578 rr
  -> C0A8001B:1C20      Masq    1      0          0
TCP  [fd00::a]:0035 rr
  -> [fd00::46]:0035    Masq    1      0          0
`))
	require.NoError(t, err)
	require.Equal(t, []ipvsDNSDestination{
		{protocol: unix.IPPROTO_TCP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")},
		{protocol: unix.IPPROTO_TCP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")},
		{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")},
		{protocol: unix.IPPROTO_TCP, endpoint: netip.MustParseAddrPort("[fd00::46]:53")},
	}, destinations)
}

func TestAutoRouteIPVSDNSBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		ipvsDNSBypass: &autoRouteIPVSDNSBypass{
			destinations: []ipvsDNSDestination{
				{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")},
			},
		},
		options: Options{
			AutoRoute:         true,
			IPRoute2RuleIndex: DefaultIPRoute2RuleIndex,
			Inet4Address:      []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			Inet4Gateway:      netip.MustParseAddr("198.18.0.2"),
		},
	}

	var found bool
	for _, rule := range nativeTun.rules() {
		if rule.Dst == netip.MustParsePrefix("10.122.219.70/32") {
			found = true
			require.Equal(t, unix.IPPROTO_UDP, rule.IPProto)
			require.NotNil(t, rule.Dport)
			require.Equal(t, uint16(53), rule.Dport.Start)
			require.Equal(t, uint16(53), rule.Dport.End)
			require.Equal(t, DefaultIPRoute2RuleIndex+10, rule.Goto)
		}
	}
	require.True(t, found)
}

func TestIPVSDNSDestinationsChanged(t *testing.T) {
	oldDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")}}
	newDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")}}
	require.False(t, ipvsDNSDestinationsChanged(oldDestinations, oldDestinations))
	require.True(t, ipvsDNSDestinationsChanged(oldDestinations, newDestinations))
}

func TestAutoRouteIPVSDNSBypassReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_vs")
	require.NoError(t, os.WriteFile(path, []byte("UDP  0A0A000A:0035 rr\n  -> 0A7ADB46:0035 Masq 1 0 0\n"), 0o600))
	bypass, err := newAutoRouteIPVSDNSBypass(path)
	require.NoError(t, err)
	require.Equal(t, []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")}}, bypass.Destinations())

	require.NoError(t, os.WriteFile(path, []byte("UDP  0A0A000A:0035 rr\n  -> 0A7ADB47:0035 Masq 1 0 0\n"), 0o600))
	destinations, err := bypass.Load()
	require.NoError(t, err)
	require.True(t, ipvsDNSDestinationsChanged(bypass.Destinations(), destinations))
	bypass.Replace(destinations)
	require.Equal(t, []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")}}, bypass.Destinations())
}

func TestAutoRouteIPVSDNSBypassMissingTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_vs")
	bypass, err := newAutoRouteIPVSDNSBypass(path)
	require.NoError(t, err)
	require.NotNil(t, bypass)
	require.Empty(t, bypass.Destinations())

	require.NoError(t, os.WriteFile(path, []byte("UDP  0A0A000A:0035 rr\n  -> 0A7ADB46:0035 Masq 1 0 0\n"), 0o600))
	destinations, err := bypass.Load()
	require.NoError(t, err)
	require.Equal(t, []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")}}, destinations)
}

func TestUpdateIPVSDNSRulesUsesExactDifference(t *testing.T) {
	nativeTun := newIPVSDNSRuleTestTun()
	oldDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")}}
	newDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_TCP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")}}
	var operations []string
	updatedDestinations, err := nativeTun.updateIPVSDNSRules(oldDestinations, newDestinations,
		func(rule *netlink.Rule) error {
			operations = append(operations, "add "+rule.Dst.String()+" tcp")
			require.Equal(t, unix.IPPROTO_TCP, rule.IPProto)
			return nil
		},
		func(rule *netlink.Rule) error {
			operations = append(operations, "delete "+rule.Dst.String()+" udp")
			require.Equal(t, unix.IPPROTO_UDP, rule.IPProto)
			return nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, []string{"add 10.122.219.71/32 tcp", "delete 10.122.219.70/32 udp"}, operations)
	require.Equal(t, newDestinations, updatedDestinations)
}

func TestUpdateIPVSDNSRulesKeepsOldRulesWhenAddFails(t *testing.T) {
	nativeTun := newIPVSDNSRuleTestTun()
	oldDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")}}
	newDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")}}
	deleteCalls := 0
	updatedDestinations, err := nativeTun.updateIPVSDNSRules(oldDestinations, newDestinations,
		func(*netlink.Rule) error { return errors.New("add failed") },
		func(*netlink.Rule) error {
			deleteCalls++
			return nil
		},
	)
	require.EqualError(t, err, "add IPVS DNS bypass rule for 10.122.219.71:53: add failed")
	require.Zero(t, deleteCalls)
	require.Equal(t, oldDestinations, updatedDestinations)
}

func TestUpdateIPVSDNSRulesTracksPartialUpdate(t *testing.T) {
	nativeTun := newIPVSDNSRuleTestTun()
	first := ipvsDNSDestination{protocol: unix.IPPROTO_TCP, endpoint: netip.MustParseAddrPort("10.122.219.70:53")}
	second := ipvsDNSDestination{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("10.122.219.71:53")}
	addCalls := 0
	updatedDestinations, err := nativeTun.updateIPVSDNSRules(nil, []ipvsDNSDestination{first, second},
		func(*netlink.Rule) error {
			addCalls++
			if addCalls == 2 {
				return errors.New("add failed")
			}
			return nil
		},
		func(*netlink.Rule) error { return nil },
	)
	require.EqualError(t, err, "add IPVS DNS bypass rule for 10.122.219.71:53: add failed")
	require.Equal(t, []ipvsDNSDestination{first}, updatedDestinations)

	deleteCalls := 0
	updatedDestinations, err = nativeTun.updateIPVSDNSRules([]ipvsDNSDestination{first, second}, nil,
		func(*netlink.Rule) error { return nil },
		func(*netlink.Rule) error {
			deleteCalls++
			if deleteCalls == 2 {
				return errors.New("delete failed")
			}
			return nil
		},
	)
	require.EqualError(t, err, "delete IPVS DNS bypass rule for 10.122.219.71:53: delete failed")
	require.Equal(t, []ipvsDNSDestination{second}, updatedDestinations)
}

func newIPVSDNSRuleTestTun() *NativeTun {
	return &NativeTun{
		options: Options{
			AutoRoute:         true,
			IPRoute2RuleIndex: DefaultIPRoute2RuleIndex,
			Inet4Address:      []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			Inet4Gateway:      netip.MustParseAddr("198.18.0.2"),
		},
	}
}

func TestIPVSDNSBackendPortRules(t *testing.T) {
	const table = `UDP  0A60000A:0035 rr
  -> 0AF40035:041D Masq 1 0 0
  -> 0AF40035:0035 Masq 1 0 0
  -> 0AF40035:0000 Masq 1 0 0
TCP  0A60000A:0035 rr
  -> 0AF40035:041D Masq 1 0 0
TCP  0A60000A:0050 rr
  -> 0AF40035:1F90 Masq 1 0 0
`
	backends, err := parseIPVSDNSDestinations(strings.NewReader(table))
	require.NoError(t, err)
	n := newIPVSDNSRuleTestTun()
	var targets [][2]int
	for _, backend := range backends {
		rule := n.ipvsDNSRule(backend)
		require.Equal(t, netip.MustParsePrefix("10.244.0.53/32"), rule.Dst)
		targets = append(targets, [2]int{rule.IPProto, int(rule.Dport.Start)})
		require.Equal(t, rule.Dport.Start, rule.Dport.End)
	}
	require.ElementsMatch(t, [][2]int{{unix.IPPROTO_UDP, 53}, {unix.IPPROTO_UDP, 1053}, {unix.IPPROTO_TCP, 1053}}, targets)
}
