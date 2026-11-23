//go:build linux

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/nftables"
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

func TestAutoRoutePreservesForwardedServiceReply(t *testing.T) {
	if os.Getenv("SING_TUN_ECHO_PEER") == "1" {
		sock, err := net.ListenPacket("udp4", "10.85.1.27:18888")
		require.NoError(t, err)
		defer sock.Close()
		buf := make([]byte, 128)
		for {
			n, peer, err := sock.ReadFrom(buf)
			require.NoError(t, err)
			_, err = sock.WriteTo(buf[:n], peer)
			require.NoError(t, err)
		}
	}
	for _, backend := range []string{"cali-backend", "cilium_host"} {
		t.Run(backend, func(t *testing.T) {
			runCalicoIntegration(t, func() { checkForwardedService(t, backend, 0, "") })
		})
	}
	t.Run("cilium_host_high_output_mark", func(t *testing.T) {
		runCalicoIntegration(t, func() { checkForwardedService(t, "cilium_host", 0x10000, "") })
	})
	for _, mode := range []string{"dnat", "preexisting-connmark", "ecmp"} {
		t.Run(mode, func(t *testing.T) {
			runCalicoIntegration(t, func() { checkForwardedService(t, "cilium_host", 0, mode) })
		})
	}
}

func checkForwardedService(t *testing.T, backend string, outputMark uint32, mode string) {
	t.Helper()
	gateways := []string{"192.0.2.1/24", "198.51.100.1/24"}
	peers := []string{"192.0.2.2/24", "198.51.100.2/24"}
	names := []string{fmt.Sprintf("st-client-%d", os.Getpid()), fmt.Sprintf("st-pod-%d", os.Getpid())}
	if backend == "cali-backend" {
		runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "bpfin.cali").Run() })
	}
	for i, ns := range names {
		ns := ns
		dev := []string{"edge0", backend}[i]
		runTestIP(t, "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		runTestIP(t, "link", "add", dev, "type", "veth", "peer", "name", "peer0", "netns", ns)
		t.Cleanup(func() { require.NoError(t, exec.Command("ip", "link", "del", dev).Run()) })
		runTestIP(t, "addr", "add", gateways[i], "dev", dev)
		runTestIP(t, "link", "set", dev, "up")
		runTestIP(t, "-n", ns, "addr", "add", peers[i], "dev", "peer0")
		runTestIP(t, "-n", ns, "link", "set", "peer0", "up")
		runTestIP(t, "-n", ns, "link", "set", "lo", "up")
		runTestIP(t, "-n", ns, "route", "add", "default", "via", netip.MustParsePrefix(gateways[i]).Addr().String())
	}
	runTestIP(t, "-n", names[0], "addr", "add", "203.0.113.7/32", "dev", "lo")
	if mode == "ecmp" {
		runTestIP(t, "-n", names[0], "addr", "add", "192.0.2.3/24", "dev", "peer0")
		runTestIP(t, "route", "add", "default", "nexthop", "via", "192.0.2.2", "dev", "edge0", "nexthop", "via", "192.0.2.3", "dev", "edge0")
	} else {
		runTestIP(t, "route", "add", "default", "via", "192.0.2.2")
	}
	runTestIP(t, "-n", names[1], "address", "add", "10.85.1.27/32", "dev", "peer0")
	target := "10.85.1.27"
	if backend == "cilium_host" {
		runTestIP(t, "route", "add", "10.85.1.0/24", "via", "198.51.100.2", "dev", backend)
	} else {
		runTestIP(t, "route", "add", "10.85.1.27/32", "dev", backend)
	}
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("1"), 0))
	server := exec.Command("ip", "netns", "exec", names[1], os.Args[0], "-test.run=^TestAutoRoutePreservesForwardedServiceReply$")
	server.Env = append(os.Environ(), "SING_TUN_ECHO_PEER=1")
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	require.Eventually(t, func() bool {
		b, _ := exec.Command("ip", "netns", "exec", names[1], "ss", "-lun").Output()
		return strings.Contains(string(b), ":18888 ")
	}, 3*time.Second, 20*time.Millisecond)
	if backend == "cilium_host" {
		// Include a nonzero cluster ID. Both parts of the Cilium security
		// identity must still be available to forwarding policy after routing.
		cmd := exec.Command("nft", "-f", "-")
		var extra string
		switch mode {
		case "dnat":
			target = "192.0.2.1"
			runTestIP(t, "route", "add", "203.0.113.7/32", "via", "192.0.2.2", "dev", "edge0")
			extra = "chain published { type nat hook prerouting priority dstnat; iifname \"edge0\" ip daddr 192.0.2.1 udp dport 18888 dnat ip to 10.85.1.27; }\n"
		case "preexisting-connmark":
			extra = "chain foreign_mark { type filter hook prerouting priority mangle; iifname \"edge0\" ip daddr 10.85.1.27 udp dport 18888 ct mark set ct mark | 0x40000000; }\n"
		}
		cmd.Stdin = strings.NewReader(
			"table inet service_identity_test {\n" +
				extra +
				"chain ingress { type filter hook prerouting priority raw; iifname \"cilium_host\" ip saddr 10.85.1.27 meta mark set 0xbf2a0f5a; }\n" +
				"chain verify_forwarding { type filter hook forward priority filter; ip daddr 10.85.1.27 udp dport 18888 ct mark != 0 ct mark set ct mark | 0x40000000; ip saddr 10.85.1.27 udp sport 18888 meta mark != 0xbf2a0f5a drop; }\n}\n")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		t.Cleanup(func() {
			require.NoError(t, exec.Command("nft", "delete", "table", "inet", "service_identity_test").Run())
		})
	}
	echo := func(payload string) string {
		cmd := exec.Command("ip", "netns", "exec", names[0], "socat", "-t", "1", "-T", "2", "-", "UDP4:"+target+":18888,bind=203.0.113.7")
		cmd.Stdin = strings.NewReader(payload)
		b, err := cmd.CombinedOutput()
		require.NoError(t, err, string(b))
		return string(b)
	}
	require.Equal(t, "before", echo("before"))
	n := startTestAutoRoute(t, outputMark)
	require.NotNil(t, n.dnatBypass)
	nft, err := nftables.New()
	require.NoError(t, err)
	defer nft.CloseLasting()
	_, err = nft.ListTableOfFamily(n.dnatBypass.tableName, nftables.TableFamilyINet)
	require.NoError(t, err)
	checkTraffic := func() {
		if backend == "cali-backend" {
			for _, port := range []string{"53", "18888"} {
				probe := exec.Command("ip", "route", "get", "10.85.1.27", "from", "192.0.2.2", "iif", "edge0", "mark", "0", "ipproto", "udp", "sport", "49152", "dport", port)
				probe.Env = append(os.Environ(), "LC_ALL=C")
				output, err := probe.CombinedOutput()
				require.Error(t, err, "unmarked BPF probe to port %s bypassed host conntrack: %s", port, output)
				require.Contains(t, string(output), "unreachable")
			}
		}
		require.Equal(t, "after", echo("after"))
		if mode == "dnat" {
			// This replay pins the client's route to the physical peer.
			return
		}
		if backend == "cilium_host" && mode != "dnat" {
			ct, err := exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "203.0.113.7", "--orig-dst", "10.85.1.27", "--dport", "18888").CombinedOutput()
			require.NoError(t, err, string(ct))
			require.Contains(t, string(ct), fmt.Sprintf("mark=%d", n.options.autoRouteOutputMark()|0x40000000))
		}
		outbound := exec.Command("ip", "netns", "exec", names[1], "socat", "-u", "-", "UDP4:203.0.113.7:18889,bind=10.85.1.27")
		outbound.Stdin = strings.NewReader("new-outbound")
		require.NoError(t, outbound.Run())
		fds := []unix.PollFd{{Fd: int32(n.tunFd), Events: unix.POLLIN}}
		buf := make([]byte, 1500)
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			count, err := unix.Poll(fds, int(time.Until(deadline).Milliseconds()))
			require.NoError(t, err)
			if count == 0 {
				break
			}
			size, err := n.Read(buf)
			require.NoError(t, err)
			if size >= 28 && buf[0] == 0x45 && buf[9] == unix.IPPROTO_UDP && string(buf[28:size]) == "new-outbound" {
				return
			}
		}
		t.Fatal("new backend datagram did not arrive at the TUN")
	}
	checkTraffic()
	// Exercise the kernel's legacy netfilter backend in the same topology.
	func() {
		n.routeAccess.Lock()
		defer n.routeAccess.Unlock()
		b := n.dnatBypass
		require.NotNil(t, b)
		require.NoError(t, b.Close())
		b.useNFTables = false
		path, err := exec.LookPath("iptables-legacy")
		require.NoError(t, err)
		b.iptablesPath = path
		b.ip6tablesPath, err = exec.LookPath("ip6tables-legacy")
		require.NoError(t, err)
		require.NoError(t, b.Start())
		require.NoError(t, n.refreshServiceRoutes())
	}()
	checkTraffic()
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
