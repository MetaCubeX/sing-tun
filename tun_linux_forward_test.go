//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
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

func TestAutoRouteNetlinkDescriptorsArePrivate(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	for _, protocol := range []int{unix.NETLINK_ROUTE, unix.NETLINK_NETFILTER} {
		socket, err := subscribeAutoRouteNetlink(protocol)
		require.NoError(t, err)
		func() {
			defer socket.Close()
			link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", socket.GetFd()))
			require.NoError(t, err)
			child, err := exec.Command("sh", "-c", "for fd in /proc/self/fd/*; do readlink \"$fd\" || :; done").CombinedOutput()
			require.NoError(t, err, string(child))
			require.NotContains(t, string(child), link, "child retained the owner's netlink socket")
		}()
	}
}

func TestAutoRoutePreservesServiceRouterDNS(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a private Linux network namespace")
	}
	for i, name := range []string{"cilium_host", "bpfin.cali", "lan0"} {
		name := name
		peer := fmt.Sprintf("dnspeer%d", i)
		runTestIP(t, "link", "add", name, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
		runTestIP(t, "link", "set", name, "up")
		runTestIP(t, "link", "set", peer, "up")
		runTestIP(t, "address", "add", fmt.Sprintf("10.99.%d.1/24", i), "dev", name)
		runTestIP(t, "route", "add", fmt.Sprintf("10.101.%d.0/24", i), "via", fmt.Sprintf("10.99.%d.2", i), "dev", name)
		runTestIP(t, "-6", "address", "add", fmt.Sprintf("fd51:%d::1/64", i), "dev", name, "nodad")
		runTestIP(t, "-6", "route", "add", fmt.Sprintf("fd52:%d::/64", i), "via", fmt.Sprintf("fd51:%d::2", i), "dev", name)
	}
	t.Cleanup(func() { require.NotContains(t, runTestIP(t, "rule", "show"), "19000:") })
	startTestAutoRoute(t, 0)
	for i, want := range []string{"cilium_host", "bpfin.cali", "test-tun"} {
		for _, proto := range []string{"tcp", "udp"} {
			route := runTestIP(t, "route", "get", fmt.Sprintf("10.101.%d.9", i), "ipproto", proto, "dport", "53")
			require.Contains(t, route, "dev "+want+" ", "DNS backend or ordinary LAN resolver, %s", proto)
			route = runTestIP(t, "-6", "route", "get", fmt.Sprintf("fd52:%d::9", i), "from", "fd51:0::2", "iif", "cilium_host", "ipproto", proto, "dport", "53")
			require.Contains(t, route, "dev "+want+" ", "IPv6 DNS backend or ordinary LAN resolver, %s", proto)
		}
	}
	runTestIP(t, "route", "add", "10.102.0.0/24", "via", "10.99.0.2", "dev", "cilium_host")
	require.Eventually(t, func() bool {
		return strings.Contains(runTestIP(t, "route", "get", "10.102.0.9", "ipproto", "udp", "dport", "53"), "dev cilium_host ")
	}, 8*time.Second, 100*time.Millisecond)
	runTestIP(t, "route", "replace", "10.102.0.0/24", "via", "10.99.2.2", "dev", "lan0")
	require.Eventually(t, func() bool {
		return strings.Contains(runTestIP(t, "route", "get", "10.102.0.9", "ipproto", "udp", "dport", "53"), "dev test-tun ")
	}, 8*time.Second, 100*time.Millisecond)
}
