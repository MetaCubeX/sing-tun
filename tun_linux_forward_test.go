//go:build linux

package tun

import (
	"net/netip"
	"os/exec"
	"testing"

	"github.com/metacubex/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func startTestAutoRoute(t *testing.T, outputMark uint32) *NativeTun {
	t.Helper()
	dev, err := New(Options{Name: "test-tun", MTU: 1500, AutoRoute: true, DNSMode: DNSModeDisabled,
		Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		AutoRedirectOutputMark: outputMark,
		IPRoute2RuleIndex:      19000, IPRoute2TableIndex: 19001, Logger: logger.NOP(),
	})
	require.NoError(t, err)
	n := dev.(*NativeTun)
	t.Cleanup(func() { require.NoError(t, n.Close()) })
	return n
}

func runTestIP(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("ip", args...).CombinedOutput()
	require.NoError(t, err, "%v: %s", args, output)
	return string(output)
}
