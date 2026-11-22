//go:build linux

package tun

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseIPVSSnapshotTracksNonDNSServices(t *testing.T) {
	snapshot, err := parseIPVSSnapshot(strings.NewReader(`IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port Forward Weight ActiveConn InActConn
TCP  C0000201:7580 rr
  -> 0A55011B:49C8      Masq    1      0          0
UDP  [fd51:1::1]:7580 rr
  -> [fd52:1::27]:49C8  Masq    1      0          0
`))
	require.NoError(t, err)
	require.Empty(t, snapshot.destinations)
	require.Equal(t, [2]bool{true, true}, snapshot.hasServices)
}

func TestIPVSNodePortReplyPreservedUnderTUN(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, backend := range []string{"nftables", "legacy"} {
			for _, policy := range []string{"cluster", "local"} {
				if family == "ipv6" && policy == "cluster" {
					continue
				}
				name := family + "-" + backend + "-" + policy
				t.Run(name, func(t *testing.T) {
					runCalicoIntegration(t, func() {
						checkIPVSNodePortReply(t, family == "ipv6", backend == "legacy", policy == "cluster")
					})
				})
			}
		}
	}
}

func checkIPVSNodePortReply(t *testing.T, ipv6, legacy, masquerade bool) {
	t.Helper()
	if ipv6 {
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv6/conf/all/accept_dad", []byte("0"), 0))
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0"), 0))
	}
	setupForwardingPeers(t, "backend0")
	clientIP, nodeIP, podIP, pyFamily := "203.0.113.7", "192.0.2.1", "10.85.1.27", "socket.AF_INET"
	vip, rip := nodeIP+":30080", podIP+":18888"
	if ipv6 {
		for _, ns := range []string{"client", "backend"} {
			_ = exec.Command("ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0").Run()
		}
		clientIP, nodeIP, podIP, pyFamily = "2001:db8::7", "fd51:1::1", "fd52:1::27", "socket.AF_INET6"
		vip, rip = "["+nodeIP+"]:30080", "["+podIP+"]:18888"
		runTestIP(t, "-n", "client", "-6", "addr", "add", clientIP+"/128", "dev", "lo", "nodad")
		runTestIP(t, "-6", "route", "add", "default", "via", "fd51:1::2", "dev", "edge0")
		require.Eventually(t, func() bool {
			for _, ns := range []string{"", "client", "backend"} {
				args := []string{"-6", "addr", "show", "tentative"}
				if ns != "" {
					args = append([]string{"-n", ns}, args...)
				}
				if runTestIP(t, args...) != "" {
					return false
				}
			}
			return true
		}, 4*time.Second, 20*time.Millisecond)
	} else {
		runTestIP(t, "-n", "client", "addr", "add", clientIP+"/32", "dev", "lo")
		runTestIP(t, "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/conf/edge0/rp_filter", []byte("1"), 0))
	}
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/vs/conntrack", []byte("1"), 0))

	for _, args := range [][]string{
		{"-A", "-t", vip, "-s", "rr"},
		{"-a", "-t", vip, "-r", rip, "-m"},
		{"-A", "-u", vip, "-s", "rr"},
		{"-a", "-u", vip, "-r", rip, "-m"},
	} {
		out, err := exec.Command("ipvsadm", args...).CombinedOutput()
		require.NoError(t, err, "%v: %s", args, out)
	}
	if masquerade {
		// Mimic kube-proxy IPVS externalTrafficPolicy=Cluster SNAT on backend egress.
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(`table ip ipvs_cluster_masq {
chain postrouting { type nat hook postrouting priority srcnat; oifname "backend0" ip daddr 10.85.1.27 masquerade; }
}
`)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	server := exec.Command("ip", "netns", "exec", "backend", "python3", "-u", "-c", fmt.Sprintf(`
import selectors, socket
sel = selectors.DefaultSelector()
tcp = socket.socket(%s, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((%q, 18888))
tcp.listen()
udp = socket.socket(%s, socket.SOCK_DGRAM)
udp.bind((%q, 18888))
sel.register(tcp, selectors.EVENT_READ)
sel.register(udp, selectors.EVENT_READ)
print("ready", flush=True)
while True:
    for key, _ in sel.select():
        s = key.fileobj
        if s is udp:
            data, peer = s.recvfrom(1024)
            s.sendto(data, peer)
        else:
            conn, _ = s.accept()
            with conn:
                data = conn.recv(1024)
                if data:
                    conn.sendall(data)
`, pyFamily, podIP, pyFamily, podIP))
	stdout, err := server.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	line := bufio.NewScanner(stdout)
	require.True(t, line.Scan())
	require.Equal(t, "ready", line.Text())

	probe := func(proto, payload string) {
		t.Helper()
		script := fmt.Sprintf(`
import socket, sys
proto, payload = sys.argv[1], sys.argv[2].encode()
if proto == "tcp":
    s = socket.socket(%s, socket.SOCK_STREAM)
    s.settimeout(2)
    s.bind((%q, 0))
    s.connect((%q, 30080))
    s.sendall(payload)
    print(s.recv(1024).decode(), flush=True)
    s.close()
else:
    s = socket.socket(%s, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.bind((%q, 0))
    s.sendto(payload, (%q, 30080))
    print(s.recv(1024).decode(), flush=True)
    s.close()
`, pyFamily, clientIP, nodeIP, pyFamily, clientIP, nodeIP)
		out, err := exec.Command("ip", "netns", "exec", "client", "python3", "-c", script, proto, payload).CombinedOutput()
		require.NoError(t, err, "%s %s: %s", proto, payload, out)
		require.Equal(t, payload, strings.TrimSpace(string(out)))
	}

	probe("tcp", "ipvs-tcp-before")
	probe("udp", "ipvs-udp-before")

	n := startTestAutoRoute(t, 0)
	if legacy {
		n.routeAccess.Lock()
		useLegacyServiceFirewall(t, n.dnatBypass)
		n.routeAccess.Unlock()
		n.refreshIPVSDNSBypass()
	}

	probe("tcp", "ipvs-tcp-with-tun")
	probe("udp", "ipvs-udp-with-tun")

	if !ipv6 {
		// Ordinary pod outbound traffic must still enter TUN.
		out, err := exec.Command("ip", "netns", "exec", "backend", "python3", "-c",
			`import socket; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(("10.85.1.27",0)); s.sendto(b"pod-outbound-tun",("203.0.113.7",18889))`).CombinedOutput()
		require.NoError(t, err, string(out))
		readCalicoTestTUN(t, n, "pod-outbound-tun")
	}
}

func TestLegacyBackendPodClusterIPDNS(t *testing.T) {
	for _, cni := range []string{"flannel-cni0", "calico-non-bpf"} {
		t.Run(cni, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				checkLegacyPodClusterIPDNS(t, cni)
			})
		})
	}
}

func checkLegacyPodClusterIPDNS(t *testing.T, cni string) {
	t.Helper()
	runTestIP(t, "netns", "add", "pod-client")
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "pod-client").Run() })
	runTestIP(t, "netns", "add", "pod-dns")
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "pod-dns").Run() })

	var dnsIP string
	if cni == "flannel-cni0" {
		runTestIP(t, "link", "add", "cni0", "type", "bridge")
		runTestIP(t, "addr", "add", "10.244.0.1/24", "dev", "cni0")
		runTestIP(t, "link", "set", "cni0", "up")
		for _, p := range []struct{ ns, hostDev, ip string }{
			{"pod-client", "veth-c", "10.244.0.10/24"},
			{"pod-dns", "veth-d", "10.244.0.2/24"},
		} {
			runTestIP(t, "link", "add", p.hostDev, "type", "veth", "peer", "name", "eth0", "netns", p.ns)
			runTestIP(t, "link", "set", p.hostDev, "master", "cni0")
			runTestIP(t, "link", "set", p.hostDev, "up")
			runTestIP(t, "-n", p.ns, "link", "set", "lo", "up")
			runTestIP(t, "-n", p.ns, "addr", "add", p.ip, "dev", "eth0")
			runTestIP(t, "-n", p.ns, "link", "set", "eth0", "up")
			runTestIP(t, "-n", p.ns, "route", "add", "default", "via", "10.244.0.1")
		}
		dnsIP = "10.244.0.2"
	} else {
		for _, p := range []struct{ ns, hostDev, gw, ip string }{
			{"pod-client", "cali-client", "198.51.100.1/24", "10.244.1.10"},
			{"pod-dns", "cali-coredns", "198.51.101.1/24", "10.244.1.2"},
		} {
			runTestIP(t, "link", "add", p.hostDev, "type", "veth", "peer", "name", "eth0", "netns", p.ns)
			runTestIP(t, "addr", "add", p.gw, "dev", p.hostDev)
			runTestIP(t, "link", "set", p.hostDev, "up")
			runTestIP(t, "route", "add", p.ip+"/32", "dev", p.hostDev)
			runTestIP(t, "-n", p.ns, "link", "set", "lo", "up")
			runTestIP(t, "-n", p.ns, "addr", "add", p.ip+"/32", "dev", "eth0")
			runTestIP(t, "-n", p.ns, "link", "set", "eth0", "up")
			gw := strings.Split(p.gw, "/")[0]
			runTestIP(t, "-n", p.ns, "route", "add", gw+"/32", "dev", "eth0")
			runTestIP(t, "-n", p.ns, "route", "add", "default", "via", gw)
		}
		dnsIP = "10.244.1.2"
	}
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))

	// Mimic kube-proxy ClusterIP DNAT (10.96.0.10:53 is NOT a local address).
	legacy, err := exec.LookPath("iptables-legacy")
	require.NoError(t, err)
	require.NoError(t, runIPTables(legacy, "-t", "nat", "-A", "PREROUTING", "-d", "10.96.0.10/32", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dnsIP+":53"))

	server := exec.Command("ip", "netns", "exec", "pod-dns", "python3", "-u", "-c", `
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 53))
print("ready", flush=True)
while True:
    data, peer = s.recvfrom(512)
    s.sendto(b"coredns:" + data, peer)
`, dnsIP)
	stdout, err := server.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	line := bufio.NewScanner(stdout)
	require.True(t, line.Scan())
	require.Equal(t, "ready", line.Text())

	n := startTestAutoRoute(t, 0)
	n.routeAccess.Lock()
	useLegacyServiceFirewall(t, n.dnatBypass)
	n.routeAccess.Unlock()
	n.refreshIPVSDNSBypass()

	// ClusterIP DNS must reach CoreDNS rather than TUN.
	out, err := exec.Command("ip", "netns", "exec", "pod-client", "python3", "-c", `
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"cluster-query", ("10.96.0.10", 53))
print(s.recv(512).decode(), flush=True)
`).CombinedOutput()
	require.NoError(t, err, string(out))
	require.Equal(t, "coredns:cluster-query", strings.TrimSpace(string(out)))

	// Direct external DNS must still go into TUN.
	out, err = exec.Command("ip", "netns", "exec", "pod-client", "python3", "-c", `
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"external-dns-query", ("203.0.113.7", 53))
`).CombinedOutput()
	require.NoError(t, err, string(out))
	readCalicoTestTUN(t, n, "external-dns-query")
}
