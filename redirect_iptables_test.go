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
		},
	}
	t.Cleanup(r.cleanupIPTables)
	require.NoError(t, r.setupIPTablesForFamily(path))
	output, err := exec.Command(path, "-t", "nat", "-S", "uid-test-output").CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "-o tun0")
}
