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
		{protocol: unix.IPPROTO_TCP, address: netip.MustParseAddr("10.122.219.70")},
		{protocol: unix.IPPROTO_TCP, address: netip.MustParseAddr("10.122.219.71")},
		{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.71")},
		{protocol: unix.IPPROTO_TCP, address: netip.MustParseAddr("fd00::46")},
	}, destinations)
}

func TestAutoRouteIPVSDNSBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		ipvsDNSBypass: &autoRouteIPVSDNSBypass{
			destinations: []ipvsDNSDestination{
				{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.70")},
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
	oldDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.70")}}
	newDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.71")}}
	require.False(t, ipvsDNSDestinationsChanged(oldDestinations, oldDestinations))
	require.True(t, ipvsDNSDestinationsChanged(oldDestinations, newDestinations))
}

func TestAutoRouteIPVSDNSBypassReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_vs")
	require.NoError(t, os.WriteFile(path, []byte("UDP  0A0A000A:0035 rr\n  -> 0A7ADB46:0035 Masq 1 0 0\n"), 0o600))
	bypass, err := newAutoRouteIPVSDNSBypass(path)
	require.NoError(t, err)
	require.Equal(t, []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.70")}}, bypass.Destinations())

	require.NoError(t, os.WriteFile(path, []byte("UDP  0A0A000A:0035 rr\n  -> 0A7ADB47:0035 Masq 1 0 0\n"), 0o600))
	destinations, err := bypass.Load()
	require.NoError(t, err)
	require.True(t, ipvsDNSDestinationsChanged(bypass.Destinations(), destinations))
	bypass.Replace(destinations)
	require.Equal(t, []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.71")}}, bypass.Destinations())
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
	require.Equal(t, []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.70")}}, destinations)
}

func TestUpdateIPVSDNSRulesUsesExactDifference(t *testing.T) {
	nativeTun := newIPVSDNSRuleTestTun()
	oldDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.70")}}
	newDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_TCP, address: netip.MustParseAddr("10.122.219.71")}}
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
	oldDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.70")}}
	newDestinations := []ipvsDNSDestination{{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.71")}}
	deleteCalls := 0
	updatedDestinations, err := nativeTun.updateIPVSDNSRules(oldDestinations, newDestinations,
		func(*netlink.Rule) error { return errors.New("add failed") },
		func(*netlink.Rule) error {
			deleteCalls++
			return nil
		},
	)
	require.EqualError(t, err, "add IPVS DNS bypass rule for 10.122.219.71: add failed")
	require.Zero(t, deleteCalls)
	require.Equal(t, oldDestinations, updatedDestinations)
}

func TestUpdateIPVSDNSRulesTracksPartialUpdate(t *testing.T) {
	nativeTun := newIPVSDNSRuleTestTun()
	first := ipvsDNSDestination{protocol: unix.IPPROTO_TCP, address: netip.MustParseAddr("10.122.219.70")}
	second := ipvsDNSDestination{protocol: unix.IPPROTO_UDP, address: netip.MustParseAddr("10.122.219.71")}
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
	require.EqualError(t, err, "add IPVS DNS bypass rule for 10.122.219.71: add failed")
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
	require.EqualError(t, err, "delete IPVS DNS bypass rule for 10.122.219.71: delete failed")
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
