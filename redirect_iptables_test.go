//go:build linux

package tun

import (
	"net/netip"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPTablesDNSRulesForFamily(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires iptables in an isolated Linux network namespace")
	}
	for _, family := range []struct{ tool, tun, dns, target string }{
		{"iptables", "198.18.0.1/32", "198.18.0.2", "192.0.2.53:5353"},
		{"ip6tables", "fd00::1/128", "fd00::2", "[fd01::53]:5353"},
	} {
		path, err := exec.LookPath(family.tool)
		require.NoError(t, err)
		target := netip.MustParseAddrPort(family.target)
		for _, tc := range []struct {
			name  string
			rules []DNSHijackRule
			port  string
		}{
			{"default", nil, "53"},
			{"empty", []DNSHijackRule{}, ""},
			{"tcp-only", []DNSHijackRule{{Network: "tcp", Address: target}}, ""},
			{"explicit-udp", []DNSHijackRule{{Network: "udp", Address: target}}, "5353"},
		} {
			t.Run(family.tool+"/"+tc.name, func(t *testing.T) {
				options := &Options{Name: "tun0", AutoRoute: true, DNSHijack: tc.rules}
				r := &autoRedirect{tunOptions: options, tableName: "dns-test", customRedirectPort: 1234}
				addresses := []netip.Prefix{netip.MustParsePrefix(family.tun)}
				if target.Addr().Is4() {
					r.enableIPv4, r.iptablesPath, options.Inet4Address = true, path, addresses
				} else {
					r.enableIPv6, r.ip6tablesPath, options.Inet6Address = true, path, addresses
				}
				if tc.port != "" {
					options.DNSServers = []netip.Addr{netip.MustParseAddr(family.dns)}
				}
				t.Cleanup(r.cleanupIPTables)
				require.NoError(t, r.setupIPTablesForFamily(path))
				output, err := exec.Command(path, "-t", "nat", "-S", "dns-test-prerouting").CombinedOutput()
				require.NoError(t, err, string(output))
				if tc.port == "" {
					require.NotContains(t, string(output), "-j DNAT")
				} else {
					require.Contains(t, string(output), "--dport "+tc.port+" -j DNAT")
					require.Contains(t, string(output), family.dns)
				}
			})
		}
	}
}
