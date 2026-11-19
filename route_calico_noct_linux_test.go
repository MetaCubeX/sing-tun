//go:build linux

package tun

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/netlink/nl"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestCalicoQueueUnpaddedDatagram(t *testing.T) {
	// Captured from the Debian 6.12 NFQUEUE socket for the real mask-race UDP packet.
	data, err := hex.DecodeString("1101000000030000000000000000000002004a390b0001000000000208000000080005000000000210000900000600001688bec2014d000014000400000000006afc853900000000000f02f18c000b803400018014000180080001000a55011b08000200cb0071071c00028005000100110000000600020049c800000600030049c90000340002801400018008000100cb007107080002000a55011b1c00028005000100110000000600020049c900000600030049c8000008000c00a72d0cf50800030000000008080007000000001e080008000000000008000c000000000208000e000000000129000a0045000025800e4000401173420a55011bcb00710749c849c90011479a6d61736b2d72616365")
	require.NoError(t, err)
	require.Len(t, data, 273)
	// Netlink envelope headers use the receiver's native byte order.
	nl.NativeEndian().PutUint32(data, 273)
	nl.NativeEndian().PutUint16(data[4:], unix.NFNL_SUBSYS_QUEUE<<8|nfqMessagePacket)
	for offset := unix.NLMSG_HDRLEN + 4; offset < len(data); {
		length, typ := binary.LittleEndian.Uint16(data[offset:]), binary.LittleEndian.Uint16(data[offset+2:])
		nl.NativeEndian().PutUint16(data[offset:], length)
		nl.NativeEndian().PutUint16(data[offset+2:], typ)
		offset += (int(length) + 3) &^ 3
	}
	_, err = syscall.ParseNetlinkMessage(data)
	require.ErrorIs(t, err, unix.EINVAL)
	messages, err := parseCalicoQueueMessages(data)
	require.NoError(t, err)
	require.Len(t, messages, 1)
	attrs, err := parseCalicoQueueAttributes(messages[0].Data[4:])
	require.NoError(t, err)
	require.Equal(t, uint16(nfqPayload), attrs[len(attrs)-1].Attr.Type)
	require.Equal(t, "mask-race", string(attrs[len(attrs)-1].Value[28:]))
	invalidAttrs := append([]byte(nil), messages[0].Data[4:]...)
	nl.NativeEndian().PutUint16(invalidAttrs[len(invalidAttrs)-41:], 42)
	_, err = parseCalicoQueueAttributes(invalidAttrs)
	require.ErrorIs(t, err, unix.EINVAL)
	padded := append(append([]byte(nil), data...), 0, 0, 0)
	messages, err = parseCalicoQueueMessages(append(padded, data...))
	require.NoError(t, err)
	require.Len(t, messages, 2)
	for _, length := range []uint32{15, 274, 277} {
		invalid := append([]byte(nil), data...)
		nl.NativeEndian().PutUint32(invalid, length)
		_, err = parseCalicoQueueMessages(invalid)
		require.ErrorIs(t, err, unix.EINVAL)
	}
}

func TestCalicoUntrackedTCPReplay(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, mode := range []string{"native", "ordinary", "unknown-abi"} {
			name := "nft-" + mode
			if legacy {
				name = "legacy-" + mode
			}
			t.Run(name, func(t *testing.T) {
				runCalicoIntegration(t, func() { checkCalicoUntrackedTCP(t, legacy, mode, 0, false) })
			})
		}
	}
}

func TestCalicoRPFilterReplay(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, filter := range []int{0, 1, 2} {
			name := "nft-" + strconv.Itoa(filter)
			if legacy {
				name = "legacy-" + strconv.Itoa(filter)
			}
			t.Run(name, func(t *testing.T) {
				runCalicoIntegration(t, func() { checkCalicoUntrackedTCP(t, legacy, "native", filter, false) })
			})
		}
	}
}

func TestCalicoRPFilterReadonlyInterface(t *testing.T) {
	runCalicoIntegration(t, func() { checkCalicoUntrackedTCP(t, false, "native", 2, true) })
}

func checkCalicoUntrackedTCP(t *testing.T, legacy bool, mode string, filter int, readonlyIface bool) {
	for i, name := range []string{"noct-pod", "noct-peer"} {
		name := name
		runTestIP(t, "netns", "add", name)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
		dev := []string{"cali-backend", "edge0"}[i]
		runTestIP(t, "link", "add", dev, "type", "veth", "peer", "name", "peer0", "netns", name)
		gateway := []string{"198.51.100.1/24", "192.0.2.1/24"}[i]
		peer := []string{"198.51.100.2/24", "192.0.2.2/24"}[i]
		runTestIP(t, "addr", "add", gateway, "dev", dev)
		runTestIP(t, "link", "set", dev, "up")
		runTestIP(t, "-n", name, "addr", "add", peer, "dev", "peer0")
		runTestIP(t, "-n", name, "link", "set", "peer0", "up")
		runTestIP(t, "-n", name, "link", "set", "lo", "up")
		runTestIP(t, "-n", name, "route", "add", "default", "via", netip.MustParsePrefix(gateway).Addr().String())
	}
	runTestIP(t, "-n", "noct-pod", "addr", "add", "10.85.1.27/32", "dev", "peer0")
	runTestIP(t, "-n", "noct-peer", "addr", "add", "203.0.113.7/32", "dev", "lo")
	runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-backend")
	runTestIP(t, "route", "add", "default", "via", "192.0.2.2")
	runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
	interfaces, err := os.ReadDir(ipv4ConfPath)
	require.NoError(t, err)
	for _, iface := range interfaces {
		require.NoError(t, os.WriteFile(ipv4ConfPath+"/"+iface.Name()+"/rp_filter", []byte("0"), 0))
	}
	require.NoError(t, os.WriteFile("/proc/sys/net/ipv4/conf/cali-backend/rp_filter", []byte(strconv.Itoa(filter)), 0))
	require.NoError(t, os.WriteFile(srcValidMarkPath, []byte("0"), 0))
	const ifaceMarkPath = ipv4ConfPath + "/cali-backend/src_valid_mark"
	require.NoError(t, os.WriteFile(ifaceMarkPath, []byte("0"), 0))
	wantMark, wantIfaceMark := "0", "0"
	if readonlyIface {
		bindReadonlySysctl(t, ifaceMarkPath)
		wantMark = "1"
	} else if filter != 0 {
		wantIfaceMark = "1"
	}
	t.Cleanup(func() {
		mark, err := os.ReadFile(srcValidMarkPath)
		require.NoError(t, err)
		require.Equal(t, "0", strings.TrimSpace(string(mark)), "namespace source validation after close")
		mark, err = os.ReadFile(ifaceMarkPath)
		require.NoError(t, err)
		require.Equal(t, "0", strings.TrimSpace(string(mark)), "interface source validation after close")
	})
	observer := exec.Command("nft", "-f", "-")
	observer.Stdin = strings.NewReader("table inet noct_observer {\n" +
		"chain ingress { type filter hook prerouting priority mangle; iifname \"cali-backend\" ip saddr 10.85.1.27 ip daddr 203.0.113.7 tcp sport 8080 tcp dport 49152 ct state invalid counter meta mark set meta mark | 0x01000000; }\n" +
		"chain forwarding { type filter hook forward priority filter; ip saddr 10.85.1.27 ip daddr 203.0.113.7 tcp sport 8080 tcp dport 49152 meta mark & 0xff000000 != 0x01000000 drop; }\n" +
		"chain egress { type filter hook postrouting priority mangle + 1; oifname \"edge0\" ip saddr 10.85.1.27 ip daddr 203.0.113.7 tcp sport 8080 tcp dport 49152 meta mark & 0xff002000 != 0x01000000 drop; }\n}\n")
	output, err := observer.CombinedOutput()
	require.NoError(t, err, string(output))

	mountCalicoTestBPFFS(t)
	valueSize := uint32(88)
	if mode == "unknown-abi" {
		valueSize = 96
	}
	fd := createCalicoTestMap(t, "cali_v4_ct4", 16, valueSize, unix.BPF_MAP_TYPE_LRU_HASH)
	value := make([]byte, valueSize)
	value[16] = 2
	if mode == "ordinary" {
		value[16] = 0
	}
	workload, err := net.InterfaceByName("cali-backend")
	require.NoError(t, err)
	uplink, err := net.InterfaceByName("edge0")
	require.NoError(t, err)
	// Calico v3.32.2's captured NAT_REV layout, with TCP protocol in the key.
	nl.NativeEndian().PutUint32(value[40:], 0x50)
	nl.NativeEndian().PutUint32(value[44:], uint32(workload.Index))
	nl.NativeEndian().PutUint32(value[64:], 0x30)
	nl.NativeEndian().PutUint32(value[68:], uint32(uplink.Index))
	copy(value[76:], netip.MustParseAddr("192.0.2.1").AsSlice())
	nl.NativeEndian().PutUint16(value[80:], 30080)
	copy(value[84:], netip.MustParseAddr("203.0.113.7").AsSlice())
	key := calicoTestKey(netip.MustParseAddr("10.85.1.27"), netip.MustParseAddr("203.0.113.7"), 8080, 49152)
	nl.NativeEndian().PutUint32(key, unix.IPPROTO_TCP)
	require.Equal(t, unix.Errno(0), updateCalicoTestMap(t, fd, key, value))
	pinCalicoTestMap(t, fd, "/sys/fs/bpf/tc/globals/cali_v4_ct4")

	invalidCount := func() uint64 {
		dump, err := exec.Command("nft", "list", "table", "inet", "noct_observer").CombinedOutput()
		require.NoError(t, err, string(dump))
		fields := strings.Fields(string(dump))
		for i, word := range fields {
			if word == "packets" {
				count, err := strconv.ParseUint(fields[i+1], 10, 64)
				require.NoError(t, err)
				return count
			}
		}
		t.Fatal("INVALID observer counter missing")
		return 0
	}
	assertNoCT := func() {
		data, err := exec.Command("conntrack", "-L", "-p", "tcp", "--orig-src", "10.85.1.27", "--orig-dst", "203.0.113.7", "--sport", "8080", "--dport", "49152").CombinedOutput()
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			require.True(t, ok)
			require.Equal(t, 1, exit.ExitCode(), string(data))
		}
		require.NotContains(t, string(data), "src=10.85.1.27", "replay unexpectedly acquired host conntrack state")
		t.Logf("host CT lookup: %s", data)
	}
	send := func(token string) []byte {
		packet := calicoNoCTTCPPacket(token)
		cmd := exec.Command("ip", "netns", "exec", "noct-pod", "python3", "-c", "import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW);s.sendto(bytes.fromhex(sys.argv[1]),('203.0.113.7',0))", fmt.Sprintf("%x", packet))
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		return packet
	}
	peer := func(token string) (*exec.Cmd, *bufio.Scanner) {
		cmd := exec.Command("ip", "netns", "exec", "noct-peer", "python3", "-u", "-c", "import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP);s.bind(('203.0.113.7',0));s.settimeout(2);print('ready',flush=True)\nwhile True:\n p=s.recv(65535)\n if sys.argv[1].encode() in p:print(p.hex(),flush=True);break", token)
		output, err := cmd.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		scanner := bufio.NewScanner(output)
		require.True(t, scanner.Scan())
		require.Equal(t, "ready", scanner.Text())
		return cmd, scanner
	}
	_, beforePeer := peer("noct-before")
	before := send("noct-before")
	require.True(t, beforePeer.Scan(), "raw TCP baseline must reach the external peer")
	require.Contains(t, beforePeer.Text(), fmt.Sprintf("%x", before[20:]))
	require.Eventually(t, func() bool { return invalidCount() == 1 }, time.Second, 10*time.Millisecond, "fixture must produce an actual kernel INVALID packet")
	assertNoCT()

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
	token := "noct-on-" + mode + strings.Repeat("-long-payload", 40)
	if mode == "native" {
		_, onPeer := peer(token)
		packet := send(token)
		require.True(t, onPeer.Scan(), "first INVALID TCP reply must reach the actual external peer")
		require.Contains(t, onPeer.Text(), fmt.Sprintf("%x", packet[20:]), "TCP header, checksum and payload must remain unchanged")
		for deadline := time.Now().Add(150 * time.Millisecond); time.Now().Before(deadline); {
			fds := []unix.PollFd{{Fd: int32(n.tunFd), Events: unix.POLLIN}}
			ready, err := unix.Poll(fds, int(time.Until(deadline).Milliseconds()))
			if err == unix.EINTR {
				continue
			}
			require.NoError(t, err)
			if ready == 0 {
				break
			}
			buf := make([]byte, 1500)
			size, err := n.Read(buf)
			require.NoError(t, err)
			if size >= 40 && buf[0] == 0x45 && buf[9] == unix.IPPROTO_TCP {
				require.NotEqual(t, token, string(buf[40:size]), "native TCP reply also entered TUN")
			}
		}
	} else {
		send(token)
		readCalicoNoCTTUN(t, n, token)
	}
	require.Eventually(t, func() bool { return invalidCount() == 2 }, time.Second, 10*time.Millisecond)
	queue, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	require.NoError(t, err)
	var received string
	for _, line := range strings.Split(string(queue), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 7 && fields[0] == strconv.Itoa(int(b.calicoQueue.number)) {
			received = fields[7]
		}
	}
	require.Equal(t, "1", received, "actual INVALID TCP packet must traverse the bound kernel queue once")
	assertNoCT()
	mark, err := os.ReadFile(srcValidMarkPath)
	require.NoError(t, err)
	require.Equal(t, wantMark, strings.TrimSpace(string(mark)))
	mark, err = os.ReadFile(ifaceMarkPath)
	require.NoError(t, err)
	require.Equal(t, wantIfaceMark, strings.TrimSpace(string(mark)))
	filterValue, err := os.ReadFile("/proc/sys/net/ipv4/conf/cali-backend/rp_filter")
	require.NoError(t, err)
	require.Equal(t, strconv.Itoa(filter), strings.TrimSpace(string(filterValue)), "product must not change rp_filter")
	t.Log("same real INVALID TCP tuple remained without host CT; native reply reached peer, ordinary/unknown stayed on TUN")
}

func calicoNoCTTCPPacket(token string) []byte {
	packet := make([]byte, 40+len(token))
	packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:], netip.MustParseAddr("10.85.1.27").AsSlice())
	copy(packet[16:], netip.MustParseAddr("203.0.113.7").AsSlice())
	binary.BigEndian.PutUint16(packet[20:], 8080)
	binary.BigEndian.PutUint16(packet[22:], 49152)
	binary.BigEndian.PutUint32(packet[24:], 0x10203040)
	binary.BigEndian.PutUint32(packet[28:], 0x55667788)
	packet[32], packet[33] = 0x50, 0x12
	binary.BigEndian.PutUint16(packet[34:], 4096)
	copy(packet[40:], token)
	checksum := func(data []byte) uint16 {
		var sum uint32
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data))
			data = data[2:]
		}
		if len(data) != 0 {
			sum += uint32(data[0]) << 8
		}
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
	pseudo := append([]byte(nil), packet[12:20]...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, byte((len(packet)-20)>>8), byte(len(packet)-20))
	pseudo = append(pseudo, packet[20:]...)
	binary.BigEndian.PutUint16(packet[36:], checksum(pseudo))
	return packet
}

func readCalicoNoCTTUN(t *testing.T, n *NativeTun, token string) {
	t.Helper()
	for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline); {
		fds := []unix.PollFd{{Fd: int32(n.tunFd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, int(time.Until(deadline).Milliseconds()))
		if err == unix.EINTR {
			continue
		}
		require.NoError(t, err)
		if ready == 0 {
			break
		}
		buf := make([]byte, 1500)
		size, err := n.Read(buf)
		require.NoError(t, err)
		if size >= 40 && buf[0] == 0x45 && buf[9] == unix.IPPROTO_TCP && string(buf[40:size]) == token {
			return
		}
	}
	t.Fatalf("unclassified TCP packet %q did not reach TUN", token)
}
