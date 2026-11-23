//go:build linux

package tun

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalDestinationPreservesForeignMarks(t *testing.T) {
	for _, backend := range []string{"nftables", "legacy"} {
		t.Run(backend, func(t *testing.T) {
			runCalicoIntegration(t, func() { checkLocalDestinationPreservesForeignMarks(t, backend == "legacy") })
		})
	}
}

func checkLocalDestinationPreservesForeignMarks(t *testing.T, legacy bool) {
	t.Helper()
	setupForwardingPeers(t, "backend0")
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table ip local_mark_test {
chain mark_ingress { type filter hook prerouting priority mangle - 1; udp dport 18890 meta mark set udp sport map { 18891 : 0x100, 18892 : 0xd00, 18893 : 0xe00, 18894 : 0x0 }; }
chain record_mark { type filter hook input priority filter; udp dport 18890 ct mark set meta mark; }
}`)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	n := startTestAutoRoute(t, 0)
	if legacy {
		useLegacyServiceFirewall(t, n.dnatBypass)
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 18890})
	require.NoError(t, err)
	defer server.Close()
	for i, mark := range []int{0x100, 0xd00, 0xe00, 0} {
		if legacy && mark == 0 {
			continue
		}
		port := fmt.Sprint(18891 + i)
		cmd = exec.Command("ip", "netns", "exec", "client", "python3", "-c",
			"import socket,sys; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(('192.0.2.2', int(sys.argv[1]))); s.sendto(sys.argv[1].encode(), ('192.0.2.1', 18890))", port)
		out, err = cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
		var payload [16]byte
		size, _, err := server.ReadFromUDP(payload[:])
		require.NoError(t, err)
		require.Equal(t, port, string(payload[:size]))
		out, err = exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "192.0.2.2", "--sport", port, "--dport", "18890").CombinedOutput()
		require.NoError(t, err, string(out))
		require.Contains(t, string(out), fmt.Sprintf("mark=%d ", mark))
	}
}

func TestForwardedDNSRouteIsolation(t *testing.T) {
	for _, mode := range []string{"dnat", "dnat-connected", "dnat-local-connected", "dnat-local-external", "dnat-local-external-legacy", "dnat-non-dns-external", "foreign-mark", "ipvs-nftables", "ipvs-legacy", "ipvs-external-nftables", "ipvs-external-legacy"} {
		t.Run(mode, func(t *testing.T) {
			runCalicoIntegration(t, func() { checkForwardedDNSRoute(t, mode) })
		})
	}
}

func checkForwardedDNSRoute(t *testing.T, mode string) {
	setupForwardingPeers(t, "backend0")
	runTestIP(t, "-n", "client", "addr", "add", "203.0.113.7/32", "dev", "lo")
	runTestIP(t, "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
	const vip = "10.96.0.53"
	const backend = "203.0.113.7"
	port := 53
	if mode == "dnat-non-dns-external" {
		port = 5300
	}
	translated := backend
	if mode == "dnat-connected" || mode == "dnat-local-connected" {
		translated = "192.0.2.2"
	}
	if strings.HasPrefix(mode, "dnat-local-") {
		runTestIP(t, "addr", "add", vip+"/32", "dev", "lo")
	}
	if strings.HasPrefix(mode, "ipvs-") {
		if !strings.HasPrefix(mode, "ipvs-external-") {
			runTestIP(t, "route", "add", backend+"/32", "via", "192.0.2.2", "dev", "edge0")
		}
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/conf/edge0/rp_filter", []byte("1"), 0))
		runTestIP(t, "addr", "add", vip+"/32", "dev", "lo")
		for _, args := range [][]string{{"-A", "-u", vip + ":53", "-s", "rr"}, {"-a", "-u", vip + ":53", "-r", backend + ":53", "-m"}} {
			out, err := exec.Command("ipvsadm", args...).CombinedOutput()
			require.NoError(t, err, string(out))
		}
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/vs/conntrack", []byte("1"), 0))
	} else {
		rule := "chain tag_ingress { type filter hook prerouting priority mangle; iifname \"backend0\" meta mark set 0x10024; }"
		if strings.HasPrefix(mode, "dnat") {
			rule = fmt.Sprintf(`chain nat { type nat hook prerouting priority dstnat; iifname "backend0" ip daddr %s udp dport %d dnat to %s; }`, vip, port, translated)
		}
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader("table ip route_test {\n" + rule + "\n}\n")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	n := startTestAutoRoute(t, 0)
	if strings.HasSuffix(mode, "-legacy") {
		n.routeAccess.Lock()
		useLegacyServiceFirewall(t, n.dnatBypass)
		n.routeAccess.Unlock()
		n.refreshIPVSDNSBypass()
	}
	send := func(address, payload string) {
		t.Helper()
		cmd := exec.Command("ip", "netns", "exec", "backend", "python3", "-c",
			"import socket,sys; s=socket.socket(type=socket.SOCK_DGRAM); s.sendto(sys.stdin.buffer.read(),(sys.argv[1],int(sys.argv[2])))", address, fmt.Sprint(port))
		cmd.Stdin = strings.NewReader(payload)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	send(backend, "direct-dns")
	readCalicoTestTUN(t, n, "direct-dns")
	if mode == "dnat" || strings.HasPrefix(mode, "dnat-local-external") || mode == "dnat-non-dns-external" {
		send(vip, "translated-dns")
		readCalicoTestTUN(t, n, "translated-dns")
	}
	if mode == "dnat" || strings.HasPrefix(mode, "dnat-local-external") || mode == "dnat-non-dns-external" || mode == "foreign-mark" {
		return
	}

	if strings.HasPrefix(mode, "ipvs-external-") {
		send(vip, "translated-service")
		readCalicoTestTUN(t, n, "translated-service")
		return
	}

	receiver := exec.Command("ip", "netns", "exec", "client", "python3", "-u", "-c",
		"import socket,sys\ns=socket.socket(type=socket.SOCK_DGRAM)\ns.bind((sys.argv[1],53))\ns.settimeout(3)\nprint('ready')\ndata,peer=s.recvfrom(128)\nprint(data.decode())\ns.sendto(data,peer)", translated)
	out, err := receiver.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, receiver.Start())
	defer func() { _ = receiver.Process.Kill(); _ = receiver.Wait() }()
	scan := bufio.NewScanner(out)
	require.True(t, scan.Scan())
	require.Equal(t, "ready", scan.Text())
	if strings.HasPrefix(mode, "ipvs-") {
		client := exec.Command("ip", "netns", "exec", "backend", "socat", "-t", "1", "-T", "3", "-", "UDP4:"+vip+":53")
		client.Stdin = strings.NewReader("translated-service")
		response, err := client.CombinedOutput()
		require.NoError(t, err, string(response))
		require.Equal(t, "translated-service", string(response))
	} else {
		send(vip, "translated-service")
	}
	require.True(t, scan.Scan(), "the translated request did not arrive at the backend")
	require.Equal(t, "translated-service", scan.Text())
}

func TestLegacyDNATRestartClearsInactiveFamily(t *testing.T) {
	runCalicoIntegration(t, func() {
		v4, err := exec.LookPath("iptables-legacy")
		require.NoError(t, err)
		v6, err := exec.LookPath("ip6tables-legacy")
		require.NoError(t, err)
		options := Options{Name: "test-tun", IPRoute2RuleIndex: 19000, IPRoute2TableIndex: 19001,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}}
		old := &autoRouteDNATBypass{options: &options, chainName: "STUN-DNAT-19001", iptablesPath: v4, ip6tablesPath: v6}
		require.NoError(t, old.Start())
		old.startDNS()
		list := func(table string) string {
			out, err := exec.Command(v6, "-t", table, "-S").CombinedOutput()
			require.NoError(t, err, string(out))
			return string(out)
		}
		for _, table := range []string{"mangle", "raw"} {
			require.Contains(t, list(table), old.chainName)
		}
		// The new instance has no knowledge of the old instance's rules.
		options.Inet6Address = nil
		next := &autoRouteDNATBypass{options: &options, chainName: old.chainName, iptablesPath: v4}
		require.NoError(t, next.Start())
		t.Cleanup(func() { require.NoError(t, next.Close()) })
		for _, table := range []string{"mangle", "raw"} {
			require.NotContains(t, list(table), old.chainName)
		}
	})
}
