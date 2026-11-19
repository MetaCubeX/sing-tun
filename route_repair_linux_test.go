//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/logger"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDNATRestartAcrossBackends(t *testing.T) {
	runCalicoIntegration(t, func() {
		legacy, err := exec.LookPath("iptables-legacy")
		require.NoError(t, err)
		options := &Options{Name: "test-tun", IPRoute2RuleIndex: 19000, IPRoute2TableIndex: 19001, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}
		old := &autoRouteDNATBypass{options: options, tableName: "sing-tun-route-19001", chainName: "STUN-DNAT-19001", iptablesPath: legacy}
		require.NoError(t, old.Start())
		t.Cleanup(func() { require.NoError(t, old.Close()) })
		legacyRules := func() string {
			out, err := outputIPTables(legacy, "-t", "mangle", "-S")
			require.NoError(t, err)
			return string(out)
		}
		require.Contains(t, legacyRules(), "-A PREROUTING -j "+old.chainName)
		next := &autoRouteDNATBypass{options: options, tableName: old.tableName, chainName: old.chainName, useNFTables: true}
		require.NoError(t, next.Start())
		t.Cleanup(func() { require.NoError(t, next.Close()) })
		require.NotContains(t, legacyRules(), "-A PREROUTING -j "+old.chainName)
	})
}

func TestWideMarkPreservesIPVSSelectors(t *testing.T) {
	runCalicoIntegration(t, func() {
		n := &NativeTun{options: Options{
			AutoRedirectOutputMark: 0x80000024, IPRoute2RuleIndex: 19000,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		}}
		rule := n.ipvsDNSRules(ipvsDNSDestination{protocol: unix.IPPROTO_UDP, endpoint: netip.MustParseAddrPort("192.0.2.10:53")})[0]
		require.NoError(t, addAutoRouteRule(rule))
		rules := runTestIP(t, "-4", "rule", "show")
		require.Contains(t, rules, "fwmark 0x80001020/0x80001fff")
		require.Contains(t, rules, "ipproto udp")
		require.Contains(t, rules, "dport 53")
	})
}

func TestLocalDNATDestinationsFollowAddressChanges(t *testing.T) {
	for _, markMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("mark-mode-%t", markMode), func(t *testing.T) {
			runCalicoIntegration(t, func() {
				setupForwardingPeers(t, "backend0")
				device, err := New(Options{Name: "test-tun", MTU: 1500, AutoRoute: true, DNSMode: DNSModeDisabled,
					Inet4Address:       []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
					IPRoute2TableIndex: 19001, IPRoute2RuleIndex: 19000,
					AutoRedirectMarkMode: markMode, AutoRedirectInputMark: DefaultAutoRedirectInputMark,
					IPRoute2AutoRedirectFallbackRuleIndex: 32765})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, device.Close()) })
				n := device.(*NativeTun)
				require.True(t, n.dnatBypass.useNFTables)
				rules, err := exec.Command("nft", "list", "table", "ip", n.dnatBypass.tableName+"-dnat").CombinedOutput()
				require.NoError(t, err, string(rules))
				for _, change := range []struct {
					command string
					present bool
				}{{"add", true}, {"del", false}} {
					runTestIP(t, "addr", change.command, "192.0.2.99/32", "dev", "edge0")
					require.Eventually(t, func() bool {
						out, err := exec.Command("nft", "list", "chain", "ip", n.dnatBypass.tableName+"-dnat", "published").CombinedOutput()
						return err == nil && strings.Contains(string(out), "192.0.2.99") == change.present
					}, 8*time.Second, 100*time.Millisecond)
				}
			})
		})
	}
}

func TestServiceDiscoveryFailureKeepsOtherFamilyUpdating(t *testing.T) {
	runCalicoIntegration(t, func() {
		n := &NativeTun{options: Options{IPRoute2RuleIndex: 19000}}
		dns := serviceRoute{prefix: netip.MustParsePrefix("192.0.2.10/32"), lookupBits: 32}
		discoveryErr := fmt.Errorf("IPv6 interface disappeared")
		next := [2]serviceRoutePlan{{routes: map[serviceRoute]bool{dns: true}}, {discoveryErr: discoveryErr}}
		require.ErrorIs(t, n.syncServicePlans(next), discoveryErr)
		require.True(t, n.serviceRoutes[0][dns])
		require.Contains(t, runTestIP(t, "-4", "rule", "show"), "to 192.0.2.10 dport 53")
	})
}

func TestLegacyDNATReplyKeepsExplicitInputMark(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "backend0")
		for _, iface := range []string{"all", "edge0", "backend0"} {
			require.NoError(t, os.WriteFile(ipv4ConfPath+"/"+iface+"/rp_filter", []byte("0"), 0))
		}
		runTestIP(t, "-n", "client", "addr", "add", "203.0.113.7/32", "dev", "lo")
		runTestIP(t, "route", "add", "default", "via", "192.0.2.2")
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(`table ip reply_mark_test {
chain published { type nat hook prerouting priority dstnat; iifname "edge0" udp dport 30080 dnat to 10.85.1.27:18888; }
chain tag { type filter hook prerouting priority mangle - 1; iifname "backend0" udp dport 48882 meta mark set 0x2023; }
chain record { type filter hook prerouting priority mangle + 1; iifname "backend0" udp sport 18888 ct mark set meta mark; }
}`)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		device, err := New(Options{Name: "test-tun", MTU: 1500, AutoRoute: true, DNSMode: DNSModeDisabled,
			Inet4Address:       []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			IPRoute2TableIndex: 19001, IPRoute2RuleIndex: 19000, AutoRedirectMarkMode: true,
			AutoRedirectInputMark: DefaultAutoRedirectInputMark, AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2AutoRedirectFallbackRuleIndex: DefaultIPRoute2AutoRedirectFallbackRuleIndex})
		require.NoError(t, err)
		n := device.(*NativeTun)
		t.Cleanup(func() { require.NoError(t, n.Close()) })
		n.routeAccess.Lock()
		func() {
			defer n.routeAccess.Unlock()
			useLegacyServiceFirewall(t, n.dnatBypass)
		}()
		require.Contains(t, runTestIP(t, "-4", "route", "get", "203.0.113.7", "from", "10.85.1.27", "iif", "backend0", "mark", "0x2023"), "dev test-tun")
		server := exec.Command("ip", "netns", "exec", "backend", "python3", "-c",
			"import socket; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(('10.85.1.27',18888)); "+
				"exec('while True:\\n data,peer=s.recvfrom(1024)\\n s.sendto(data,peer)')")
		require.NoError(t, server.Start())
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
		require.Eventually(t, func() bool {
			out, _ := exec.Command("ip", "netns", "exec", "backend", "ss", "-lun").Output()
			return strings.Contains(string(out), ":18888 ")
		}, time.Second, 20*time.Millisecond)
		for _, tc := range []struct {
			port, payload string
			mark          uint32
		}{{"48881", "native-reply", n.options.autoRouteDNATBypassMark()}, {"48882", "tun-reply", DefaultAutoRedirectInputMark}} {
			cmd := exec.Command("ip", "netns", "exec", "client", "python3", "-c",
				"import socket,sys; s=socket.socket(type=socket.SOCK_DGRAM); s.bind(('203.0.113.7',int(sys.argv[1]))); s.settimeout(.4); "+
					"s.sendto(sys.argv[2].encode(),('192.0.2.1',30080)); "+
					"exec('try: print(s.recv(1024).decode())\\nexcept TimeoutError: pass')", tc.port, tc.payload)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
			marks, err := exec.Command("conntrack", "-L", "-p", "udp", "--sport", tc.port, "--dport", "30080").CombinedOutput()
			require.NoError(t, err, string(marks))
			require.Contains(t, string(marks), fmt.Sprintf("mark=%d ", tc.mark))
			if tc.mark == DefaultAutoRedirectInputMark {
				require.Empty(t, out)
				readCalicoTestTUN(t, n, tc.payload)
			} else {
				require.Equal(t, tc.payload, strings.TrimSpace(string(out)))
			}
		}
	})
}

func TestLegacyGatewayDNSPreservesRoutedHostClients(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "backend0")
		runTestIP(t, "-n", "client", "addr", "add", "203.0.113.7/32", "dev", "lo")
		runTestIP(t, "route", "add", "203.0.113.7/32", "via", "192.0.2.2", "dev", "edge0")
		n := startTestAutoRoute(t, 0)
		options := n.options
		options.DNSMode = DNSModeHijack
		path, err := exec.LookPath("iptables-legacy")
		require.NoError(t, err)
		monitor, err := NewNetworkUpdateMonitor(logger.NOP())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, monitor.Close()) })
		require.NoError(t, monitor.Start())
		redirect := &autoRedirect{
			tunOptions: &options, iptablesPath: path, enableIPv4: true,
			tableName: "test-redirect", customRedirectPort: 12345,
			interfaceFinder: control.NewDefaultInterfaceFinder(),
			networkMonitor:  monitor, logger: logger.NOP(),
		}
		require.NoError(t, redirect.Start())
		t.Cleanup(func() { require.NoError(t, redirect.Close()) })
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53})
		require.NoError(t, err)
		defer server.Close()
		send := func(source, dest, payload string) {
			out, err := exec.Command("ip", "netns", "exec", "client", "python3", "-c",
				"import socket,sys; s=socket.socket(type=socket.SOCK_DGRAM); s.bind((sys.argv[1],0)); s.sendto(sys.argv[3].encode(),(sys.argv[2],53))", source, dest, payload).CombinedOutput()
			require.NoError(t, err, string(out))
		}
		send("192.0.2.2", "192.0.2.1", "gateway-dns")
		readCalicoTestTUN(t, n, "gateway-dns")
		runTestIP(t, "link", "add", "rd-test", "type", "bridge")
		runTestIP(t, "link", "add", "rd-edge", "type", "veth", "peer", "name", "rd-peer", "netns", "client")
		runTestIP(t, "link", "set", "rd-edge", "master", "rd-test")
		runTestIP(t, "link", "set", "rd-edge", "up")
		runTestIP(t, "link", "set", "rd-test", "up")
		runTestIP(t, "-n", "client", "link", "set", "rd-peer", "up")
		checkBridgeRule := func(present, absent string) {
			t.Helper()
			require.Eventually(t, func() bool {
				out, err := outputIPTables(path, "-t", "nat", "-S", redirect.tableName+"-local-dns")
				return err == nil && (present == "" || strings.Contains(string(out), "-s "+present+" -i rd-test")) &&
					(absent == "" || !strings.Contains(string(out), "-s "+absent+" -i rd-test"))
			}, 8*time.Second, 100*time.Millisecond)
		}
		runTestIP(t, "addr", "add", "198.19.1.1/24", "dev", "rd-test")
		runTestIP(t, "-n", "client", "addr", "add", "198.19.1.2/24", "dev", "rd-peer")
		checkBridgeRule("198.19.1.0/24", "")
		send("198.19.1.2", "198.19.1.1", "new-bridge-dns")
		readCalicoTestTUN(t, n, "new-bridge-dns")
		runTestIP(t, "addr", "del", "198.19.1.1/24", "dev", "rd-test")
		runTestIP(t, "addr", "add", "198.19.2.1/24", "dev", "rd-test")
		checkBridgeRule("198.19.2.0/24", "198.19.1.0/24")
		runTestIP(t, "link", "del", "rd-test")
		checkBridgeRule("", "198.19.2.0/24")
		send("203.0.113.7", "192.0.2.1", "host-dns")
		require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
		var data [64]byte
		size, _, err := server.ReadFromUDP(data[:])
		require.NoError(t, err)
		require.Equal(t, "host-dns", string(data[:size]))
	})
}

func TestSrcValidMarkLeaseSurvivesInterfaceMigration(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "backend0")
		runTestIP(t, "netns", "add", "migrated")
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "migrated").Run() })
		runTestIP(t, "link", "add", "lease-test", "type", "dummy")
		write := func(iface, field, value string) {
			t.Helper()
			require.NoError(t, os.WriteFile(ipv4ConfPath+"/"+iface+"/"+field, []byte(value), 0))
		}
		read := func(iface string) string {
			t.Helper()
			value, err := os.ReadFile(ipv4ConfPath + "/" + iface + "/src_valid_mark")
			require.NoError(t, err)
			return strings.TrimSpace(string(value))
		}
		write("all", "rp_filter", "0")
		write("all", "src_valid_mark", "0")
		for _, iface := range []string{"edge0", "lease-test"} {
			write(iface, "rp_filter", "1")
			write(iface, "src_valid_mark", "0")
		}
		owner := srcValidMarkOwner{stateDir: t.TempDir() + "/state"}
		t.Cleanup(func() { require.NoError(t, owner.close()) })
		require.NoError(t, owner.syncForRPF(ipv4ConfPath, nil))
		require.Equal(t, "1", read("lease-test"))
		runTestIP(t, "link", "set", "lease-test", "netns", "migrated")
		require.NoError(t, owner.syncForRPF(ipv4ConfPath, nil))
		require.Equal(t, "1", read("edge0"))
		runTestIP(t, "link", "add", "lease-test", "type", "dummy")
		write("lease-test", "rp_filter", "1")
		write("lease-test", "src_valid_mark", "1")
		require.NoError(t, owner.syncForRPF(ipv4ConfPath, nil))
		require.NoError(t, owner.close())
		require.Equal(t, "0", read("edge0"))
		require.Equal(t, "1", read("lease-test"))
	})
}

func TestSrcValidMarkLeaseReleasesUnusedConsumers(t *testing.T) {
	conf := createIPv4Conf(t, "0", "0", "2")
	require.NoError(t, os.Mkdir(conf+"/eth1", 0700))
	require.NoError(t, os.WriteFile(conf+"/eth1/rp_filter", []byte("1"), 0600))
	require.NoError(t, os.WriteFile(conf+"/eth1/src_valid_mark", []byte("0"), 0600))
	owner := srcValidMarkOwner{stateDir: t.TempDir() + "/state"}
	t.Cleanup(func() { require.NoError(t, owner.close()) })
	read := func(iface string) string {
		t.Helper()
		value, err := os.ReadFile(conf + "/" + iface + "/src_valid_mark")
		require.NoError(t, err)
		return string(value)
	}
	require.NoError(t, owner.syncForRPF(conf, map[string]struct{}{"eth0": {}}))
	require.Equal(t, "1", read("eth0"))
	require.Equal(t, "1", read("eth1"))
	require.NoError(t, owner.syncForRPF(conf, nil))
	require.Equal(t, "0", read("eth0"))
	require.Equal(t, "1", read("eth1"))
	require.NoError(t, os.WriteFile(conf+"/eth1/rp_filter", []byte("0"), 0600))
	require.NoError(t, owner.syncForRPF(conf, nil))
	require.Equal(t, "0", read("eth1"))
}

func TestCalicoIPv6TCPWithTruncatedOptions(t *testing.T) {
	packet := make([]byte, 40+72+20)
	packet[0], packet[5], packet[6], packet[7] = 0x60, 92, unix.IPPROTO_DSTOPTS, 64
	packet[40], packet[41] = unix.IPPROTO_TCP, 8
	binary.BigEndian.PutUint16(packet[112:], 18888)
	binary.BigEndian.PutUint16(packet[114:], 49152)
	packet[124] = 0x50
	flow, ok := parseCalicoUntrackedTCP(packet[:128], unix.AF_INET6)
	require.True(t, ok)
	require.Equal(t, uint16(18888), flow.sourcePort)
	require.Equal(t, uint16(49152), flow.destinationPort)
	_, ok = parseCalicoUntrackedTCP(packet[:115], unix.AF_INET6)
	require.False(t, ok)
}
