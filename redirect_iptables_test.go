//go:build linux

package tun

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAutoRedirectIPTablesLocalDestinationOrder(t *testing.T) {
	for name, testCase := range map[string]struct {
		autoRoute            bool
		localBeforeDNSHijack bool
	}{
		"auto route":         {autoRoute: true, localBeforeDNSHijack: true},
		"without auto route": {autoRoute: false, localBeforeDNSHijack: false},
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
					Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
					DNSServers:   []netip.Addr{netip.MustParseAddr("198.18.0.2")},
				},
				tableName:          "test",
				enableIPv4:         true,
				iptablesPath:       iptablesPath,
				customRedirectPort: 12345,
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
			require.NotEqual(t, -1, dnsHijackIndex)
			if testCase.localBeforeDNSHijack {
				require.Less(t, localReturnIndex, dnsHijackIndex)
			} else {
				require.Greater(t, localReturnIndex, dnsHijackIndex)
			}
		})
	}
}
