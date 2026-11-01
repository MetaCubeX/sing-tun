//go:build linux

package tun

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/nftables"
	"github.com/metacubex/sing/common/logger"
	"github.com/sagernet/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigureDNSFailureCleansAutoRoute(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a Linux network namespace with CAP_NET_ADMIN")
	}
	for name, testCase := range map[string]struct {
		address          string
		markMode         bool
		dns              []netip.Addr
		includeInterface bool
	}{
		"IPv4":                   {address: "198.18.0.1/32"},
		"IPv6":                   {address: "fd00::1/128"},
		"mark mode":              {address: "fd00::1/128", markMode: true},
		"valid DNS":              {address: "fd00::1/128", dns: []netip.Addr{netip.MustParseAddr("fd00::2")}},
		"IPv6 include interface": {address: "fd00::1/128", dns: []netip.Addr{netip.MustParseAddr("fd00::2")}, includeInterface: true},
	} {
		t.Run(name, func(t *testing.T) {
			binDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(binDir, "resolvectl"), []byte("#!/bin/sh\nexit 0\n"), 0o700))
			t.Setenv("PATH", binDir)

			link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dns-cleanup"}}
			require.NoError(t, netlink.LinkAdd(link))
			t.Cleanup(func() { _ = netlink.LinkDel(link) })
			nativeTun := &NativeTun{options: Options{
				Name:                                  link.Attrs().Name,
				MTU:                                   1500,
				AutoRoute:                             true,
				AutoRedirectMarkMode:                  testCase.markMode,
				AutoRedirectInputMark:                 DefaultAutoRedirectInputMark,
				AutoRedirectOutputMark:                DefaultAutoRedirectOutputMark,
				IPRoute2TableIndex:                    19001,
				IPRoute2RuleIndex:                     19000,
				IPRoute2AutoRedirectFallbackRuleIndex: 19020,
				DNSServers:                            testCase.dns,
				Logger:                                logger.NOP(),
			}}
			address := netip.MustParsePrefix(testCase.address)
			if testCase.includeInterface {
				nativeTun.options.IncludeInterface = []string{"lo"}
			}
			if address.Addr().Is4() {
				nativeTun.options.Inet4Address = []netip.Prefix{address}
			} else {
				nativeTun.options.Inet6Address = []netip.Prefix{address}
			}
			t.Cleanup(func() { _ = nativeTun.Close() })

			err := nativeTun.configure(link)
			if len(testCase.dns) == 0 {
				require.ErrorContains(t, err, "set search domain: no ")
				require.ErrorContains(t, err, "for DNS")
			} else {
				require.NoError(t, err)
			}
			require.NotNil(t, nativeTun.dnatBypass, "test requires an active firewall backend")
			require.True(t, nativeTun.dnatBypass.useNFTables, "test requires nftables support")

			nft, err := nftables.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = nft.CloseLasting() })
			assertAutoRouteState := func(active bool) {
				t.Helper()
				tables, listErr := nft.ListTablesOfFamily(nftables.TableFamilyINet)
				require.NoError(t, listErr)
				var tablePresent bool
				for _, table := range tables {
					if table.Name == nativeTun.dnatBypass.tableName {
						tablePresent = true
					}
				}
				assert.Equal(t, active, tablePresent, "DNAT firewall table")

				routes, listErr := netlink.RouteListFiltered(netlink.FAMILY_ALL,
					&netlink.Route{Table: nativeTun.options.IPRoute2TableIndex}, netlink.RT_FILTER_TABLE)
				require.NoError(t, listErr)
				assert.Equal(t, active, len(routes) > 0, "TUN routes")

				rules, listErr := netlink.RuleList(netlink.FAMILY_ALL)
				require.NoError(t, listErr)
				var rulePresent, fallbackPresent bool
				for _, rule := range rules {
					if rule.Priority >= 19000 && rule.Priority <= 19010 {
						rulePresent = true
					}
					if rule.Priority == 19020 {
						fallbackPresent = true
					}
				}
				assert.Equal(t, active, rulePresent, "TUN policy rules")
				assert.Equal(t, active && testCase.markMode, fallbackPresent, "auto redirect fallback rule")
			}
			assertAutoRouteState(len(testCase.dns) > 0)
			if len(testCase.dns) > 0 {
				require.NoError(t, nativeTun.Close())
				assertAutoRouteState(false)
			}
		})
	}
}
