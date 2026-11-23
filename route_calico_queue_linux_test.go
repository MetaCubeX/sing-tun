//go:build linux

package tun

import (
	"bufio"
	"fmt"
	"github.com/sagernet/netlink/nl"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func checkCalicoQueueABIReplay(t *testing.T, legacy, unknown bool) {
	ns := fmt.Sprintf("qpod-%d", os.Getpid())
	runTestIP(t, "netns", "add", ns)
	defer exec.Command("ip", "netns", "del", ns).Run()
	runTestIP(t, "-n", ns, "link", "set", "lo", "up")
	runTestIP(t, "link", "add", "cali-backend", "type", "veth", "peer", "name", "peer0", "netns", ns)
	runTestIP(t, "addr", "add", "198.51.100.1/24", "dev", "cali-backend")
	runTestIP(t, "link", "set", "cali-backend", "up")
	runTestIP(t, "-n", ns, "addr", "add", "198.51.100.2/24", "dev", "peer0")
	runTestIP(t, "-n", ns, "addr", "add", "10.85.1.27/32", "dev", "peer0")
	runTestIP(t, "-n", ns, "link", "set", "peer0", "up")
	runTestIP(t, "-n", ns, "route", "add", "default", "via", "198.51.100.1")
	runTestIP(t, "link", "add", "edge0", "type", "veth", "peer", "name", "edge1")
	runTestIP(t, "addr", "add", "192.0.2.1/24", "dev", "edge0")
	runTestIP(t, "link", "set", "edge0", "up")
	runTestIP(t, "route", "add", "default", "via", "192.0.2.2")
	runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
	runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-backend")
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0))
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/conf/edge1/rp_filter", []byte("1"), 0))
	if unknown {
		replaceCalicoQueueTestMap(t, 96, true)
	} else {
		replaceCalicoQueueTestMap(t, 88, true)
	}
	n := startTestAutoRoute(t, 0)
	b := n.dnatBypass
	require.NotNil(t, b.calicoQueue)
	if legacy {
		n.routeAccess.Lock()
		require.NoError(t, b.Close())
		b.useNFTables = false
		b.iptablesPath = "/usr/sbin/iptables-legacy"
		b.ip6tablesPath = "/usr/sbin/ip6tables-legacy"
		require.NoError(t, b.Start())
		require.NoError(t, n.refreshServiceRoutes())
		n.routeAccess.Unlock()
	}
	stats := func() uint64 {
		data, e := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
		require.NoError(t, e)
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) > 7 && f[0] == strconv.Itoa(int(b.calicoQueue.number)) {
				v, e := strconv.ParseUint(f[7], 10, 64)
				require.NoError(t, e)
				return v
			}
		}
		t.Fatal("queue is not bound")
		return 0
	}
	initial := stats()
	code := "import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('10.85.1.27',18888))\nfor x in sys.stdin:\n s.sendto(x.strip().encode(),('203.0.113.7',18889))\n print('sent',flush=True)\n"
	p := exec.Command("ip", "netns", "exec", ns, "python3", "-u", "-c", code)
	in, e := p.StdinPipe()
	require.NoError(t, e)
	out, e := p.StdoutPipe()
	require.NoError(t, e)
	require.NoError(t, p.Start())
	defer func() { in.Close(); p.Wait() }()
	scanner := bufio.NewScanner(out)
	for i := 0; i < 8; i++ {
		if unknown && i == 2 {
			replaceCalicoQueueTestMap(t, 88, false)
		}
		token := fmt.Sprintf("ordinary-port18888-%d", i)
		_, e := fmt.Fprintln(in, token)
		require.NoError(t, e)
		require.True(t, scanner.Scan())
		readCalicoTestTUN(t, n, token)
		require.Eventually(t, func() bool {
			want := uint64(1)
			if unknown {
				want = uint64(i + 1)
				if want > 3 {
					want = 3
				}
			}
			return stats() == initial+want
		}, time.Second, 10*time.Millisecond)
	}
	ct, e := exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "10.85.1.27").CombinedOutput()
	require.NoError(t, e, string(ct))
	require.Contains(t, string(ct), fmt.Sprintf("mark=%d", b.forwardedInputMark()))
	t.Logf("8 real same-socket datagrams from backend port18888 reached TUN; queue ID sequence %d -> %d; %s", initial, stats(), ct)
	updateMark := func(mark string) {
		v, e := exec.Command("conntrack", "-U", "-p", "udp", "--orig-src", "10.85.1.27", "--orig-dst", "203.0.113.7", "--sport", "18888", "--dport", "18889", "--mark", mark).CombinedOutput()
		require.NoError(t, e, string(v))
	}
	updateMark("0")
	func() {
		b.calicoQueue.access.Lock()
		defer b.calicoQueue.access.Unlock()
		_, e := fmt.Fprintln(in, "mask-race")
		require.NoError(t, e)
		require.True(t, scanner.Scan())
		require.Eventually(t, func() bool {
			want := uint64(2)
			if unknown {
				want = 4
			}
			return stats() == initial+want
		}, time.Second, 10*time.Millisecond)
		updateMark("0xa0000000")
	}()
	readCalicoTestTUN(t, n, "mask-race")
	ct, e = exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "10.85.1.27").CombinedOutput()
	require.NoError(t, e, string(ct))
	require.Contains(t, string(ct), fmt.Sprintf("mark=%d", uint32(0xa0000000)|b.forwardedInputMark()))
	t.Logf("held CT MASK preserved concurrent external high mark: %s", ct)
	if legacy && !unknown {
		updateMark("0")
		testCalicoQueueDuringXTablesUpdate(t, n, func() {
			_, err := fmt.Fprintln(in, "during-xtables-lock")
			require.NoError(t, err)
			require.True(t, scanner.Scan())
			readCalicoTestTUN(t, n, "during-xtables-lock")
		})
	}
	link, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", b.calicoQueue.socket.GetFd()))
	require.NoError(t, e)
	child, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", p.Process.Pid, b.calicoQueue.socket.GetFd()))
	t.Logf("queue fd parent=%s child=%s error=%v", link, child, e)
	require.NotEqual(t, link, child, "queue socket must not be inherited by a live child")
	n.routeAccess.Lock()
	old := b.calicoQueue
	old.Close()
	var reservation *calicoServiceQueue
	if !unknown {
		reservation = reserveCalicoQueueNumber(t, b, old.number)
	}
	dump, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	t.Logf("after Close kernel queue: %s", dump)
	n.routeAccess.Unlock()
	require.Eventually(t, func() bool {
		n.routeAccess.Lock()
		defer n.routeAccess.Unlock()
		err := n.refreshServiceRoutes()
		if err != nil {
			t.Logf("queue recreation retry: %v", err)
		}
		return err == nil
	}, 6*time.Second, 40*time.Millisecond)
	require.NotSame(t, old, b.calicoQueue)
	if reservation != nil {
		require.NotEqual(t, reservation.number, b.calicoQueue.number, "live queue must avoid the reserved number")
	}
	require.NotEmpty(t, b.calicoQueue.scopes[0].backends)
	select {
	case <-b.calicoQueue.done:
		t.Fatal("replacement queue is closed")
	default:
		t.Log("closed queue recovered with current backend scope")
	}
	updateMark("0")
	_, e = fmt.Fprintln(in, "after-rebind")
	require.NoError(t, e)
	require.True(t, scanner.Scan())
	readCalicoTestTUN(t, n, "after-rebind")
	require.Equal(t, uint64(1), stats(), "replacement queue must classify the next real packet")
	ct, e = exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "10.85.1.27").CombinedOutput()
	require.NoError(t, e, string(ct))
	require.Contains(t, string(ct), fmt.Sprintf("mark=%d", b.forwardedInputMark()))
	// Post-BPF ABI replay: the kernel forwards real packets; Calico's NAT engine
	// itself is covered by the separate real-CNI acceptance tests.
	clientNS := fmt.Sprintf("qclient-%d", os.Getpid())
	runTestIP(t, "netns", "add", clientNS)
	defer exec.Command("ip", "netns", "del", clientNS).Run()
	runTestIP(t, "link", "set", "edge1", "netns", clientNS)
	runTestIP(t, "-n", clientNS, "link", "set", "lo", "up")
	runTestIP(t, "-n", clientNS, "addr", "add", "192.0.2.2/24", "dev", "edge1")
	runTestIP(t, "-n", clientNS, "addr", "add", "203.0.113.7/32", "dev", "lo")
	runTestIP(t, "-n", clientNS, "link", "set", "edge1", "up")
	runTestIP(t, "-n", clientNS, "route", "add", "default", "via", "192.0.2.1")
	require.NoError(t, os.Remove("/sys/fs/bpf/tc/globals/cali_v4_ct4"))
	fd := createCalicoTestMap(t, "cali_v4_ct4", 16, 88, unix.BPF_MAP_TYPE_LRU_HASH)
	value := make([]byte, 88)
	value[16] = 2
	workload, e := net.InterfaceByName("cali-backend")
	require.NoError(t, e)
	uplink, e := net.InterfaceByName("edge0")
	require.NoError(t, e)
	nl.NativeEndian().PutUint32(value[40:], 0x50)
	nl.NativeEndian().PutUint32(value[44:], uint32(workload.Index))
	nl.NativeEndian().PutUint32(value[64:], 0x30)
	nl.NativeEndian().PutUint32(value[68:], uint32(uplink.Index))
	copy(value[76:], netip.MustParseAddr("192.0.2.1").AsSlice())
	nl.NativeEndian().PutUint16(value[80:], 30081)
	copy(value[84:], netip.MustParseAddr("203.0.113.7").AsSlice())
	key := calicoTestKey(netip.MustParseAddr("10.85.1.27"), netip.MustParseAddr("203.0.113.7"), 18888, 18889)
	require.Equal(t, unix.Errno(0), updateCalicoTestMap(t, fd, key, value))
	pinCalicoTestMap(t, fd, "/sys/fs/bpf/tc/globals/cali_v4_ct4")
	peer := exec.Command("ip", "netns", "exec", clientNS, "python3", "-u", "-c", "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('203.0.113.7',18889))\ns.settimeout(2)\nprint('ready',flush=True)\nfor _ in range(2): print(s.recvfrom(1024)[0].decode(),flush=True)\n")
	peerOut, e := peer.StdoutPipe()
	require.NoError(t, e)
	require.NoError(t, peer.Start())
	defer func() { peer.Process.Kill(); peer.Wait() }()
	peerLines := bufio.NewScanner(peerOut)
	require.True(t, peerLines.Scan())
	require.Equal(t, "ready", peerLines.Text())
	updateMark("0")
	_, e = fmt.Fprintln(in, "native-service-reply")
	require.NoError(t, e)
	require.True(t, scanner.Scan())
	require.True(t, peerLines.Scan(), "native reply must reach the actual external peer")
	require.Equal(t, "native-service-reply", peerLines.Text())
	ct, e = exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "10.85.1.27").CombinedOutput()
	require.NoError(t, e, string(ct))
	require.Contains(t, string(ct), fmt.Sprintf("mark=%d", b.options.autoRouteOutputMark()))
	marked := b.options.autoRouteOutputMark() | 0x40000000
	updateMark(fmt.Sprintf("%#x", marked))
	const taggedReply = "native-reply-with-foreign-mark"
	_, e = fmt.Fprintln(in, taggedReply)
	require.NoError(t, e)
	require.True(t, scanner.Scan())
	if !peerLines.Scan() {
		readCalicoTestTUN(t, n, taggedReply)
		t.Fatal("the second datagram from the same service flow went to TUN after adding a foreign ctmark bit")
	}
	require.Equal(t, taggedReply, peerLines.Text())
	ct, e = exec.Command("conntrack", "-L", "-p", "udp", "--orig-src", "10.85.1.27").CombinedOutput()
	require.NoError(t, e, string(ct))
	require.Contains(t, string(ct), fmt.Sprintf("mark=%d", marked))
	require.Equal(t, uint64(2), stats())
	for {
		fds := []unix.PollFd{{Fd: int32(n.tunFd), Events: unix.POLLIN}}
		ready, e := unix.Poll(fds, 50)
		if e == unix.EINTR {
			continue
		}
		require.NoError(t, e)
		if ready == 0 {
			break
		}
		buf := make([]byte, 1500)
		size, e := n.Read(buf)
		require.NoError(t, e)
		if size >= 28 && buf[0] == 0x45 && buf[9] == unix.IPPROTO_UDP {
			require.NotEqual(t, "native-service-reply", string(buf[28:size]))
			require.NotEqual(t, taggedReply, string(buf[28:size]))
		}
	}
	t.Log("replacement queue forwarded the first native ABI reply to the peer, set output CT mark, and kept it out of TUN")

}

func testCalicoQueueDuringXTablesUpdate(t *testing.T, n *NativeTun, send func()) {
	t.Helper()
	dir := t.TempDir()
	lock, err := os.Create(dir + "/xtables.lock")
	require.NoError(t, err)
	defer lock.Close()
	t.Setenv("XTABLES_LOCKFILE", lock.Name())
	b := n.dnatBypass
	path := b.iptablesPath
	wrapper := dir + "/iptables"
	require.NoError(t, os.WriteFile(wrapper+"-restore", []byte("#!/bin/sh\n: > "+dir+"/started\nexec "+path+"-restore \"$@\"\n"), 0700))
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX))
	n.routeAccess.Lock()
	b.iptablesPath = wrapper
	scope := b.forwardScopes[0]
	scope.backends = append(append([]netip.Prefix(nil), scope.backends...), netip.MustParsePrefix("198.18.1.1/32"))
	done := make(chan error, 1)
	go func() { done <- b.syncServiceForward(0, scope) }()
	defer func() {
		err := unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		syncErr := <-done
		b.iptablesPath = path
		n.routeAccess.Unlock()
		require.NoError(t, err)
		require.NoError(t, syncErr)
	}()
	require.Eventually(t, func() bool {
		_, err := os.Stat(dir + "/started")
		return err == nil
	}, time.Second, 10*time.Millisecond)
	send()
}

func TestCalicoQueueABIReplay(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, unknown := range []bool{false, true} {
			name := "nft"
			if legacy {
				name = "legacy"
			}
			if unknown {
				name += "-unknown-recovery"
			} else {
				name += "-normal-cache"
			}
			t.Run(name, func(t *testing.T) { runCalicoIntegration(t, func() { checkCalicoQueueABIReplay(t, legacy, unknown) }) })
		}
	}
}

func readCalicoTestTUN(t *testing.T, n *NativeTun, token string) {
	t.Helper()
	for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline); {
		fds := []unix.PollFd{{Fd: int32(n.tunFd), Events: unix.POLLIN}}
		ready, e := unix.Poll(fds, int(time.Until(deadline).Milliseconds()))
		if e == unix.EINTR {
			continue
		}
		require.NoError(t, e)
		if ready == 0 {
			break
		}
		buf := make([]byte, 1500)
		size, e := n.Read(buf)
		require.NoError(t, e)
		if size >= 28 && buf[0] == 0x45 && buf[9] == unix.IPPROTO_UDP && string(buf[28:size]) == token {
			return
		}
	}
	t.Fatalf("ordinary packet %q did not reach TUN", token)
}
