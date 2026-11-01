//go:build linux

package tun

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/sing/common/ranges"
	"github.com/stretchr/testify/require"
)

func TestAutoRedirectIPTablesLocalDestinationOrder(t *testing.T) {
	for name, testCase := range map[string]struct {
		autoRoute            bool
		dnsMode              string
		dnsHijack            bool
		ipv6                 bool
		localBeforeDNSHijack bool
	}{
		"auto route":              {autoRoute: true, dnsHijack: true, localBeforeDNSHijack: true},
		"without auto route":      {dnsMode: DNSModeHijack, dnsHijack: true},
		"default without route":   {},
		"disabled DNS":            {autoRoute: true, dnsMode: DNSModeDisabled},
		"native DNS":              {autoRoute: true, dnsMode: DNSModeNative},
		"IPv6 auto route":         {autoRoute: true, dnsHijack: true, ipv6: true, localBeforeDNSHijack: true},
		"IPv6 without auto route": {dnsMode: DNSModeHijack, dnsHijack: true, ipv6: true},
	} {
		t.Run(name, func(t *testing.T) {
			tempDir := t.TempDir()
			commandLogPath := filepath.Join(tempDir, "iptables.log")
			iptablesPath := filepath.Join(tempDir, "iptables")
			require.NoError(t, os.WriteFile(
				iptablesPath,
				[]byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$IPTABLES_LOG\"\n"),
				0o700,
			))
			t.Setenv("IPTABLES_LOG", commandLogPath)

			redirect := &autoRedirect{
				tunOptions: &Options{
					Name:         "tun0",
					AutoRoute:    testCase.autoRoute,
					DNSMode:      testCase.dnsMode,
					Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
					Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
					DNSServers:   []netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("fd00::2")},
				},
				tableName:          "test",
				enableIPv4:         true,
				iptablesPath:       iptablesPath,
				customRedirectPort: 12345,
			}
			if testCase.ipv6 {
				redirect.iptablesPath = ""
				redirect.ip6tablesPath = iptablesPath
			}

			require.NoError(t, redirect.setupIPTablesForFamily(iptablesPath))
			commandLog, err := os.ReadFile(commandLogPath)
			require.NoError(t, err)

			localReturnIndex := -1
			dnsHijackIndex := -1
			for index, command := range strings.Split(strings.TrimSpace(string(commandLog)), "\n") {
				if strings.Contains(command, "test-prerouting -m addrtype --dst-type LOCAL -j RETURN") {
					localReturnIndex = index
				}
				if strings.Contains(command, "test-prerouting -p udp --dport 53 -j DNAT --to") {
					dnsHijackIndex = index
				}
			}
			require.NotEqual(t, -1, localReturnIndex)
			if !testCase.dnsHijack {
				require.Equal(t, -1, dnsHijackIndex)
				return
			}
			require.NotEqual(t, -1, dnsHijackIndex)
			dnsServer := "198.18.0.2"
			if testCase.ipv6 {
				dnsServer = "fd00::2"
			}
			require.Contains(t, string(commandLog), "--dport 53 -j DNAT --to "+dnsServer+"\n")
			if testCase.localBeforeDNSHijack {
				require.Less(t, localReturnIndex, dnsHijackIndex)
			} else {
				require.Greater(t, localReturnIndex, dnsHijackIndex)
			}
		})
	}
}

func TestConfiguredDNSDoesNotExpandUIDsInPrerouting(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	path := filepath.Join(dir, "iptables")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\necho \"$*\" >> \"$ARG_LOG\"\n"), 0700))
	t.Setenv("ARG_LOG", log)
	r := &autoRedirect{iptablesPath: path, tableName: "test", customRedirectPort: 1234, tunOptions: &Options{Name: "tun0", AutoRoute: true, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, IncludeUID: []ranges.Range[uint32]{{Start: 10, End: 12}}, DNSHijack: []DNSHijackRule{{Network: "udp", Address: netip.MustParseAddrPort("0.0.0.0:53")}}}}
	require.NoError(t, r.setupIPTablesForFamily(path))
	cmds, err := os.ReadFile(log)
	require.NoError(t, err)
	for _, line := range strings.Split(string(cmds), "\n") {
		if strings.Contains(line, "test-prerouting ") {
			require.NotContains(t, line, "--uid-owner")
		}
	}
}

func TestIPTablesMaxIncludeUID(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires CAP_NET_ADMIN in an isolated network namespace")
	}
	path, err := exec.LookPath("iptables")
	require.NoError(t, err)
	r := &autoRedirect{
		iptablesPath: path, enableIPv4: true, tableName: "uid-test", customRedirectPort: 1234,
		tunOptions: &Options{
			Name: "tun0", AutoRoute: true,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			IncludeUID:   []ranges.Range[uint32]{{Start: 0xfffffffe, End: 0xffffffff}},
			DNSHijack:    []DNSHijackRule{{Network: "udp", Address: netip.MustParseAddrPort("0.0.0.0:53")}},
		},
	}
	t.Cleanup(r.cleanupIPTables)
	require.NoError(t, r.setupIPTablesForFamily(path))
	output, err := exec.Command(path, "-t", "nat", "-S", "uid-test-output").CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "-o tun0")
}

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
