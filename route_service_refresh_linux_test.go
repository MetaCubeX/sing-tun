//go:build linux

package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/netlink/nl"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestServiceDNSRespectsMainTableOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, flag, gateway, lanGateway, source string
		cluster, lan, nested, fallback          string
		clusterDNS, lanDNS, nestedDNS           string
	}{
		{"ipv4", "-4", "10.85.1.27", "192.0.2.2", "192.0.2.2",
			"10.85.0.0/16", "10.85.17.0/24", "10.85.17.128/25", "10.0.0.0/8",
			"10.85.18.53", "10.85.17.53", "10.85.17.153"},
		{"ipv6", "-6", "fd52:1::27", "fd51:1::2", "fd51:1::2",
			"fd52:1700::/24", "fd52:17ab::/32", "fd52:17ab:8000::/33", "fd52::/16",
			"fd52:17cd::53", "fd52:17ab::53", "fd52:17ab:8000::53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				setupForwardingPeers(t, "cilium_host")
				change := func(action, cidr, gateway, device string) {
					runTestIP(t, tc.flag, "route", action, cidr, "via", gateway, "dev", device)
				}
				change("add", tc.fallback, tc.lanGateway, "edge0")
				change("add", tc.cluster, tc.gateway, "cilium_host")
				n := startTestAutoRoute(t, 0)
				n.routeAccess.Lock()
				defer n.routeAccess.Unlock()

				check := func(address, device string) {
					t.Helper()
					for _, proto := range []string{"tcp", "udp"} {
						route := runTestIP(t, tc.flag, "route", "get", address, "from", tc.source, "iif", "edge0", "ipproto", proto, "dport", "53")
						require.Contains(t, route, "dev "+device+" ", "%s DNS to %s", proto, address)
					}
				}
				check(tc.lanDNS, "cilium_host")
				change("add", tc.lan, tc.lanGateway, "edge0")
				change("add", tc.nested, tc.gateway, "cilium_host")
				require.NoError(t, n.refreshServiceRoutes())
				check(tc.lanDNS, "test-tun")
				check(tc.clusterDNS, "cilium_host")
				check(tc.nestedDNS, "cilium_host")

				// During withdrawal, a split rule must still require the original
				// cluster prefix length. The broader LAN route must never win.
				change("del", tc.cluster, tc.gateway, "cilium_host")
				check(tc.clusterDNS, "test-tun")
				require.NoError(t, n.refreshServiceRoutes())
				check(tc.lanDNS, "test-tun")
				check(tc.nestedDNS, "cilium_host")
				change("add", tc.cluster, tc.gateway, "cilium_host")
				change("del", tc.lan, tc.lanGateway, "edge0")
				require.NoError(t, n.refreshServiceRoutes())
				check(tc.lanDNS, "cilium_host")
			})
		})
	}
}

func TestServiceForwardRefreshIsolatesAddressFamilies(t *testing.T) {
	for _, failure := range []string{"ipv6", "ipv4"} {
		t.Run(failure, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				n := startTestAutoRoute(t, 0)
				n.routeAccess.Lock()
				defer n.routeAccess.Unlock()
				b := n.dnatBypass
				useLegacyServiceFirewall(t, b)
				setupForwardingPeers(t, "cilium_host")
				runTestIP(t, "-4", "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
				runTestIP(t, "-6", "route", "add", "default", "via", "fd51:1::2", "dev", "edge0")
				runTestIP(t, "-4", "route", "add", "10.86.1.0/24", "via", "10.85.1.27", "dev", "cilium_host")
				runTestIP(t, "-6", "route", "add", "fd52:2::/64", "via", "fd52:1::27", "dev", "cilium_host")

				failing, healthy := &b.ip6tablesPath, &b.iptablesPath
				bad, good := 1, 0
				if failure == "ipv4" {
					failing, healthy = healthy, failing
					bad, good = good, bad
				}
				saved := *failing
				defer func() { *failing = saved }()
				*failing = filepath.Join(t.TempDir(), "unavailable-restore")
				require.ErrorContains(t, n.refreshServiceRoutes(), *failing+"-restore")
				dump, err := exec.Command(*healthy, "-t", "mangle", "-S", b.chainName+"-FWD").CombinedOutput()
				require.NoError(t, err, string(dump))
				require.Contains(t, string(dump), "0x1f00")
				route := func(i int) string {
					tuple := [2][]string{
						{"-4", "route", "get", "203.0.113.7", "from", "10.86.1.42"},
						{"-6", "route", "get", "2001:db8::7", "from", "fd52:2::42"},
					}
					args := append(tuple[i], "iif", "cilium_host", "mark", "0xbf2a1f5a", "ipproto", "udp", "sport", "8081", "dport", "35900")
					return runTestIP(t, args...)
				}
				require.Contains(t, route(good), "dev edge0 ", "working family's classifier already applied")
				require.Contains(t, route(bad), "dev test-tun ", "failed family has no reply route")
				*failing = saved
				require.NoError(t, n.refreshServiceRoutes())
				require.Contains(t, route(good), "dev edge0 ")
				require.Contains(t, route(bad), "dev edge0 ", "failed family recovered")
			})
		})
	}
}

func useLegacyServiceFirewall(t *testing.T, b *autoRouteDNATBypass) {
	t.Helper()
	require.NoError(t, b.Close())
	b.useNFTables = false
	var err error
	b.iptablesPath, err = exec.LookPath("iptables-legacy")
	require.NoError(t, err)
	b.ip6tablesPath, err = exec.LookPath("ip6tables-legacy")
	require.NoError(t, err)
	require.NoError(t, b.Start())
}

func reserveCalicoQueueNumber(t *testing.T, b *autoRouteDNATBypass, number uint16) *calicoServiceQueue {
	t.Helper()
	options := *b.options
	options.IPRoute2TableIndex = int(number) + 65536
	reservation, err := newCalicoServiceQueue(&autoRouteDNATBypass{options: &options})
	require.NoError(t, err)
	t.Cleanup(reservation.Close)
	require.Equal(t, number, reservation.number)
	return reservation
}

func TestCalicoQueueUnavailableRemovesProbeRules(t *testing.T) {
	for _, backend := range []string{"nftables", "legacy"} {
		t.Run(backend, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				checkCalicoQueueUnavailable(t, backend == "legacy")
			})
		})
	}
}

func TestCalicoQueueReaderRecoversWithoutRouteChange(t *testing.T) {
	runCalicoIntegration(t, func() {
		// Avoid delayed IPv6 address validation emitting route events while
		// the test is waiting for the queue reader's notification.
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv6/conf/all/accept_dad", []byte("0"), 0))
		require.NoError(t, os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0"), 0))
		setupForwardingPeers(t, "cali-backend")
		runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
		runTestIP(t, "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
		runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-backend")
		n := startTestAutoRoute(t, 0)
		b := n.dnatBypass
		var failed *calicoServiceQueue
		func() {
			n.routeAccess.Lock()
			defer n.routeAccess.Unlock()
			failed = b.calicoQueue
			require.NotNil(t, failed)
			require.NoError(t, failed.reader.SetReadDeadline(time.Now()))
		}()
		require.Eventually(t, func() bool {
			n.routeAccess.Lock()
			defer n.routeAccess.Unlock()
			return b.calicoQueue != nil && b.calicoQueue != failed
		}, 2*time.Second, 10*time.Millisecond, "reader exit must wake the refresher before the periodic retry")
	})
}

func TestCalicoQueueKeepsReadingAfterRecoverableErrors(t *testing.T) {
	for _, failure := range []string{"expired-verdict", "netlink-overflow"} {
		t.Run(failure, func(t *testing.T) {
			runCalicoIntegration(t, func() { checkCalicoQueueRecoverableError(t, failure) })
		})
	}
}

func checkCalicoQueueRecoverableError(t *testing.T, failure string) {
	b := &autoRouteDNATBypass{
		options:       &Options{IPRoute2TableIndex: 19001},
		serviceEvents: make(chan struct{}, 1),
	}
	queue, err := newCalicoServiceQueue(b)
	require.NoError(t, err)
	t.Cleanup(queue.Close)
	request := queue.request(nfqMessageVerdict, 0, unix.AF_INET)
	request.AddData(nl.NewRtAttr(nfqVerdictHeader, []byte{0, 0, 0, 1, 0, 0, 0, 1}))
	nft := exec.Command("nft", "-f", "-")
	nft.Stdin = strings.NewReader(fmt.Sprintf(`table ip queue_test {
chain output { type filter hook output priority mangle; udp dport 18890 ct state new,established queue num %d; }
}`, queue.number))
	output, err := nft.CombinedOutput()
	require.NoError(t, err, string(output))
	runTestIP(t, "link", "set", "lo", "up")
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18890})
	require.NoError(t, err)
	defer listener.Close()
	peer, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer peer.Close()
	if failure == "expired-verdict" {
		require.NoError(t, queue.socket.Send(request))
	} else {
		var socket unix.Stat_t
		require.NoError(t, unix.Fstat(queue.socket.GetFd(), &socket))
		readStats := func() []string {
			stats, err := os.ReadFile("/proc/net/netlink")
			require.NoError(t, err)
			for _, line := range strings.Split(string(stats), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 10 && fields[9] == fmt.Sprint(socket.Ino) {
					return fields
				}
			}
			return nil
		}
		func() {
			fd := queue.socket.GetFd()
			require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4096))
			queue.access.Lock()
			defer queue.access.Unlock()
			_, err := peer.Write([]byte("hold-reader"))
			require.NoError(t, err)
			for i := 0; i < 64; i++ {
				_, err := peer.Write([]byte("overflow-reader"))
				require.NoError(t, err)
			}
			stats := readStats()
			require.Len(t, stats, 10)
			require.NotEqual(t, "0", stats[8], "netlink socket must report drops")
		}()
		require.Eventually(t, func() bool {
			stats := readStats()
			return len(stats) == 10 && stats[4] == "0"
		}, time.Second, 10*time.Millisecond, "same socket must drain after overflow")
	}
	_, err = peer.Write([]byte("after-netlink-error"))
	require.NoError(t, err)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(time.Second)))
	var data [64]byte
	for {
		n, _, err := listener.ReadFromUDP(data[:])
		require.NoError(t, err)
		if string(data[:n]) == "after-netlink-error" {
			break
		}
	}
	require.True(t, queue.running())
}

func TestCalicoQueueBypassKeepsUnmarkedTrafficRoutable(t *testing.T) {
	for _, backend := range []string{"nftables", "legacy"} {
		t.Run(backend, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				setupForwardingPeers(t, "cali-backend")
				runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
				runTestIP(t, "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
				runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-backend")
				n := startTestAutoRoute(t, 0)
				n.routeAccess.Lock()
				defer n.routeAccess.Unlock()
				b := n.dnatBypass
				if backend == "legacy" {
					useLegacyServiceFirewall(t, b)
					require.NoError(t, n.refreshServiceRoutes())
				}
				require.NotNil(t, b.calicoQueue)
				b.calicoQueue.Close()
				cmd := exec.Command("ip", "netns", "exec", "backend", "python3", "-c",
					"import socket; s=socket.socket(type=socket.SOCK_DGRAM); s.sendto(b'queue-bypassed', ('203.0.113.7',18889))")
				output, err := cmd.CombinedOutput()
				require.NoError(t, err, string(output))
				readCalicoTestTUN(t, n, "queue-bypassed")
			})
		})
	}
}

func checkCalicoQueueUnavailable(t *testing.T, legacy bool) {
	t.Helper()
	// Exercise the failure path with a real busy preferred queue and an
	// unavailable queue inventory, isolated from the host's active queues.
	n := startTestAutoRoute(t, 0)
	n.routeAccess.Lock()
	defer n.routeAccess.Unlock()
	b := n.dnatBypass
	if legacy {
		useLegacyServiceFirewall(t, b)
	}
	setupForwardingPeers(t, "cali-backend")
	runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
	runTestIP(t, "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
	runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-backend")
	require.NoError(t, n.refreshServiceRoutes())
	require.NotNil(t, b.calicoQueue)
	number := b.calicoQueue.number
	probes := func() int {
		count := 0
		for _, rule := range strings.Split(runTestIP(t, "-4", "rule", "show"), "\n") {
			if strings.Contains(rule, "10.85.1.27") && strings.Contains(rule, "unreachable") {
				count++
			}
		}
		return count
	}
	require.Equal(t, 2, probes())
	b.calicoQueue.Close()
	reservation := reserveCalicoQueueNumber(t, b, number)
	// Keep the live sysctls available while hiding the queue inventory.
	procView := t.TempDir()
	viewSys := filepath.Join(procView, "sys")
	require.NoError(t, os.Mkdir(viewSys, 0700))
	require.NoError(t, unix.Mount("/proc/sys", viewSys, "", unix.MS_BIND, ""))
	defer func() { require.NoError(t, unix.Unmount(viewSys, 0)) }()
	require.NoError(t, unix.Mount(procView, "/proc", "", unix.MS_BIND|unix.MS_REC, ""))
	procMasked := true
	defer func() {
		if procMasked {
			require.NoError(t, unix.Unmount("/proc", unix.MNT_DETACH))
		}
	}()
	_, err := os.Stat("/proc/net/netfilter/nfnetlink_queue")
	require.ErrorIs(t, err, os.ErrNotExist)

	require.Error(t, n.refreshServiceRoutes())
	require.Nil(t, b.calicoQueue)
	require.Zero(t, probes(), "no rule may assume an unavailable classifier")
	readClassifier := func(queue bool) ([]byte, error) {
		if legacy {
			chain := b.chainName + "-FWD"
			if queue {
				chain = b.chainName + "-QUEUE"
			}
			return exec.Command(b.iptablesPath, "-t", "mangle", "-S", chain).CombinedOutput()
		}
		chain := "service_forward4"
		if queue {
			chain = "service_queue4"
		}
		return exec.Command("nft", "list", "chain", "inet", b.tableName, chain).CombinedOutput()
	}
	out, err := readClassifier(false)
	require.Error(t, err, string(out))
	out, err = readClassifier(true)
	require.Error(t, err, string(out))
	base := exec.Command("nft", "list", "table", "inet", b.tableName)
	dnatRule := "dnat"
	if legacy {
		base = exec.Command(b.iptablesPath, "-t", "mangle", "-S", b.chainName)
		dnatRule = "--ctstate DNAT"
	}
	out, err = base.CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), dnatRule, "base DNAT rules remain")
	require.NoError(t, unix.Unmount("/proc", unix.MNT_DETACH))
	procMasked = false

	require.NoError(t, n.refreshServiceRoutes())
	require.NotNil(t, b.calicoQueue)
	require.NotEqual(t, reservation.number, b.calicoQueue.number)
	require.Equal(t, 2, probes())
	out, err = readClassifier(true)
	require.NoError(t, err, string(out))
	queueRule := "queue [^\n]*\\b%d\\b"
	if legacy {
		queueRule = "--queue-num %d\\b"
	}
	require.Regexp(t, fmt.Sprintf(queueRule, b.calicoQueue.number), string(out))
}
