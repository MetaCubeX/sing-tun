//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func setupForwardingPeers(t *testing.T, backend string) {
	t.Helper()
	for _, link := range []struct {
		ns, device, ipv4, ipv6, peer4, peer6 string
	}{
		{"client", "edge0", "192.0.2.1/24", "fd51:1::1/64", "192.0.2.2/24", "fd51:1::2/64"},
		{"backend", backend, "10.85.1.1/24", "fd52:1::1/64", "10.85.1.27/24", "fd52:1::27/64"},
	} {
		link := link
		runTestIP(t, "netns", "add", link.ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", link.ns).Run() })
		runTestIP(t, "link", "add", link.device, "type", "veth", "peer", "name", "eth0", "netns", link.ns)
		for _, ns := range [][]string{nil, {"-n", link.ns}} {
			device, v4, v6 := link.device, link.ipv4, link.ipv6
			if len(ns) != 0 {
				device, v4, v6 = "eth0", link.peer4, link.peer6
			}
			runTestIP(t, append(ns, "link", "set", "lo", "up")...)
			runTestIP(t, append(ns, "link", "set", device, "up")...)
			runTestIP(t, append(ns, "addr", "add", v4, "dev", device)...)
			runTestIP(t, append(ns, "-6", "addr", "add", v6, "dev", device, "nodad")...)
		}
	}
	runTestIP(t, "-n", "client", "route", "add", "default", "via", "192.0.2.1")
	runTestIP(t, "-n", "backend", "route", "add", "default", "via", "10.85.1.1")
	runTestIP(t, "-n", "client", "-6", "route", "add", "default", "via", "fd51:1::1")
	runTestIP(t, "-n", "backend", "-6", "route", "add", "default", "via", "fd52:1::1")
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0))
}

func bindReadonlySysctl(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("mount", "--bind", path, path).CombinedOutput()
	require.NoError(t, err, string(out))
	out, err = exec.Command("mount", "-o", "remount,bind,ro", path).CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestPublishedPortWithLooseRPFilter(t *testing.T) {
	for _, access := range []string{"writable", "readonly"} {
		t.Run(access, func(t *testing.T) {
			runCalicoIntegration(t, func() { checkPublishedPortRPFilter(t, "2", "0", access == "readonly", 18888) })
		})
	}
}

func TestPublishedPortWithStrictRPFilter(t *testing.T) {
	for _, port := range []int{18888, 53} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			runCalicoIntegration(t, func() { checkPublishedPortRPFilter(t, "1", "1", false, port) })
		})
	}
}

func checkPublishedPortRPFilter(t *testing.T, filter, mark string, readOnly bool, backendPort int) {
	t.Helper()
	setupForwardingPeers(t, "backend0")
	runTestIP(t, "-n", "client", "addr", "add", "203.0.113.7/32", "dev", "lo")
	runTestIP(t, "route", "add", "default", "via", "192.0.2.2")
	require.NoError(t, os.WriteFile(ipv4ConfPath+"/all/rp_filter", []byte(filter), 0))
	require.NoError(t, os.WriteFile(srcValidMarkPath, []byte("0"), 0))
	require.NoError(t, os.WriteFile(ipv4ConfPath+"/edge0/src_valid_mark", []byte("0"), 0))
	if readOnly {
		bindReadonlySysctl(t, srcValidMarkPath)
	}
	rules := exec.Command("nft", "-f", "-")
	rules.Stdin = strings.NewReader(fmt.Sprintf(`table ip test_published_port {
chain prerouting { type nat hook prerouting priority dstnat; iifname "edge0" ip daddr 192.0.2.1 tcp dport 30080 dnat to 10.85.1.27:%d; }
}`, backendPort))
	out, err := rules.CombinedOutput()
	require.NoError(t, err, string(out))
	server := exec.Command("ip", "netns", "exec", "backend", "socat", fmt.Sprintf("TCP4-LISTEN:%d,bind=10.85.1.27,reuseaddr,fork", backendPort), "EXEC:/bin/cat")
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	require.Eventually(t, func() bool {
		b, _ := exec.Command("ip", "netns", "exec", "backend", "ss", "-ltn").Output()
		return strings.Contains(string(b), fmt.Sprintf("10.85.1.27:%d", backendPort))
	}, 3*time.Second, 20*time.Millisecond)
	exchange := func(payload string) {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", "client", "socat", "-t", "1", "-T", "2", "-", "TCP4:192.0.2.1:30080,bind=203.0.113.7,connect-timeout=2")
		cmd.Stdin = strings.NewReader(payload)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "published TCP port %s: %s", payload, out)
		require.Equal(t, payload, string(out))
	}
	exchange("before TUN")
	{
		t.Cleanup(func() {
			value, err := os.ReadFile(srcValidMarkPath)
			require.NoError(t, err)
			require.Equal(t, "0", strings.TrimSpace(string(value)), "namespace source validation after TUN shutdown")
			value, err = os.ReadFile(ipv4ConfPath + "/edge0/src_valid_mark")
			require.NoError(t, err)
			require.Equal(t, "0", strings.TrimSpace(string(value)))
		})
	}
	startTestAutoRoute(t, 0)
	exchange("with TUN")
	value, err := os.ReadFile(ipv4ConfPath + "/edge0/src_valid_mark")
	require.NoError(t, err)
	require.Equal(t, mark, strings.TrimSpace(string(value)), "source validation with TUN active")
}
