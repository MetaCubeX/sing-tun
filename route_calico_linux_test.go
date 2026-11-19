//go:build linux

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"testing"
	"unsafe"

	"github.com/sagernet/netlink/nl"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func runCalicoIntegration(t *testing.T, test func()) {
	t.Helper()
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires privileged Linux network and mount namespaces")
	}
	if os.Getenv("SING_TUN_CALICO_CHILD") == t.Name() {
		current, err := os.Readlink("/proc/self/ns/mnt")
		require.NoError(t, err)
		require.NotEqual(t, os.Getenv("SING_TUN_CALICO_PARENT_MNT"), current, "private mount namespace required")
		require.NoError(t, os.MkdirAll("/run/netns", 0755))
		out, err := exec.Command("mount", "-t", "tmpfs", "tmpfs", "/run/netns").CombinedOutput()
		require.NoError(t, err, string(out))
		test()
		return
	}
	require.Equal(t, 0, os.Geteuid())
	for _, tool := range []string{"unshare", "mount", "ip", "nft", "iptables-legacy", "ip6tables-legacy", "conntrack", "python3"} {
		_, err := exec.LookPath(tool)
		require.NoError(t, err, "required integration tool %s", tool)
	}
	parent, err := os.Readlink("/proc/self/ns/mnt")
	require.NoError(t, err)
	cmd := exec.Command("unshare", "--mount", "--net", "--propagation", "private", os.Args[0], "-test.v", "-test.timeout=30s", "-test.run=^"+regexp.QuoteMeta(t.Name())+"$")
	cmd.Env = append(os.Environ(), "SING_TUN_CALICO_CHILD="+t.Name(), "SING_TUN_CALICO_PARENT_MNT="+parent)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Log(string(out))
}

func mountCalicoTestBPFFS(t *testing.T) {
	t.Helper()
	out, err := exec.Command("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").CombinedOutput()
	require.NoError(t, err, string(out))
	require.NoError(t, os.MkdirAll("/sys/fs/bpf/tc/globals", 0700))
}

func createCalicoTestMap(t *testing.T, name string, keySize, valueSize, mapType uint32) int {
	t.Helper()
	attr := struct {
		Type, Key, Value, Max, Flags, Inner, Numa uint32
		Name                                      [16]byte
	}{Type: mapType, Key: keySize, Value: valueSize, Max: 8}
	copy(attr.Name[:], name)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_CREATE, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	require.Equal(t, unix.Errno(0), errno)
	t.Cleanup(func() { unix.Close(int(fd)) })
	return int(fd)
}

func pinCalicoTestMap(t *testing.T, fd int, path string) {
	t.Helper()
	p, err := unix.BytePtrFromString(path)
	require.NoError(t, err)
	attr := struct {
		Path      uint64
		FD, Flags uint32
	}{Path: uint64(uintptr(unsafe.Pointer(p))), FD: uint32(fd)}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_PIN, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(p)
	require.Equal(t, unix.Errno(0), errno)
}

func updateCalicoTestMap(t *testing.T, fd int, key, value []byte) unix.Errno {
	t.Helper()
	attr := struct {
		FD, Pad           uint32
		Key, Value, Flags uint64
	}{FD: uint32(fd), Key: uint64(uintptr(unsafe.Pointer(&key[0]))), Value: uint64(uintptr(unsafe.Pointer(&value[0])))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return errno
}

// These byte offsets come from Calico v3.32.2 felix/bpf/conntrack/v4/map{,6}.go
// and bpf-gpl/conntrack_types.h, rather than the implementation under test.
func calicoTestKey(source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	length := 4
	if source.Is6() {
		length = 16
	}
	key := make([]byte, 8+length*2)
	nl.NativeEndian().PutUint32(key, unix.IPPROTO_UDP)
	copy(key[4:], source.AsSlice())
	copy(key[4+length:], destination.AsSlice())
	nl.NativeEndian().PutUint16(key[4+2*length:], sourcePort)
	nl.NativeEndian().PutUint16(key[6+2*length:], destinationPort)
	return key
}

func replaceCalicoQueueTestMap(t *testing.T, valueSize uint32, first bool) {
	t.Helper()
	path := "/sys/fs/bpf/tc/globals/cali_v4_ct4"
	if first {
		mountCalicoTestBPFFS(t)
	} else {
		require.NoError(t, os.Remove(path))
	}
	fd := createCalicoTestMap(t, "cali_v4_ct4", 16, valueSize, unix.BPF_MAP_TYPE_LRU_HASH)
	key := calicoTestKey(netip.MustParseAddr("10.85.1.27"), netip.MustParseAddr("203.0.113.7"), 18888, 18889)
	require.Equal(t, unix.Errno(0), updateCalicoTestMap(t, fd, key, make([]byte, valueSize)))
	pinCalicoTestMap(t, fd, path)
	if valueSize == 88 {
		readOnly, err := openCalicoConntrack(false)
		require.NoError(t, err)
		defer unix.Close(readOnly)
		require.Equal(t, unix.EPERM, updateCalicoTestMap(t, readOnly, key, make([]byte, 88)))
	}
}

func TestCalicoConntrackABIReplay(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				mountCalicoTestBPFFS(t)
				source, destination, original := netip.MustParseAddr("10.85.1.27"), netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("192.0.2.1")
				mapName, keySize, valueSize, origOffset := "cali_v4_ct4", uint32(16), uint32(88), 76
				if ipv6 {
					source = netip.MustParseAddr("fd85::27")
					destination = netip.MustParseAddr("2001:db8::7")
					original = netip.MustParseAddr("fd51::1")
					mapName, keySize, valueSize, origOffset = "cali_v6_ct4", 40, 128, 88
				}
				for _, iface := range []string{"cali-backend", "edge0"} {
					runTestIP(t, "link", "add", iface, "type", "veth", "peer", "name", iface+"p")
					runTestIP(t, "link", "set", iface, "up")
				}
				runTestIP(t, "addr", "add", fmt.Sprintf("%s/%d", original, original.BitLen()), "dev", "edge0")
				workload, err := net.InterfaceByName("cali-backend")
				require.NoError(t, err)
				uplink, err := net.InterfaceByName("edge0")
				require.NoError(t, err)
				flow := calicoServiceFlow{source: source, destination: destination, sourcePort: 18888, destinationPort: 18889, protocol: unix.IPPROTO_UDP, input: uint32(workload.Index)}
				scope := serviceForwardScope{backends: []netip.Prefix{netip.PrefixFrom(source, source.BitLen())}, uplinks: []string{"edge0"}, calicoWorkloads: true}
				key := calicoTestKey(source, destination, 18888, 18889)
				path := "/sys/fs/bpf/tc/globals/" + mapName
				// Size, type and map name must all be checked before decoding a map.
				for _, bad := range []struct {
					name             string
					key, value, kind uint32
					mapName          string
				}{{"key", keySize + 4, valueSize, 9, mapName}, {"value", keySize, valueSize + 8, 9, mapName}, {"type", keySize, valueSize, 1, mapName}, {"name", keySize, valueSize, 9, "unrelated"}} {
					t.Run("reject-"+bad.name, func(t *testing.T) {
						fd := createCalicoTestMap(t, bad.mapName, bad.key, bad.value, bad.kind)
						pinCalicoTestMap(t, fd, path)
						_, err := openCalicoConntrack(ipv6)
						require.ErrorContains(t, err, "unsupported Calico conntrack map ABI")
						require.NoError(t, os.Remove(path))
					})
				}
				fd := createCalicoTestMap(t, mapName, keySize, valueSize, 9)
				pinCalicoTestMap(t, fd, path)
				readOnly, err := openCalicoConntrack(ipv6)
				require.NoError(t, err)
				defer unix.Close(readOnly)
				value := make([]byte, valueSize)
				value[16] = 2
				// The observed v4 NAT_REV has workload approved+workload (0x50),
				// peer approved+opener (0x30), and original local NodePort destination.
				nl.NativeEndian().PutUint32(value[40:], 0x50)
				nl.NativeEndian().PutUint32(value[44:], uint32(workload.Index))
				nl.NativeEndian().PutUint32(value[64:], 0x30)
				nl.NativeEndian().PutUint32(value[68:], uint32(uplink.Index))
				length := len(original.AsSlice())
				copy(value[origOffset:], original.AsSlice())
				nl.NativeEndian().PutUint16(value[origOffset+length:], 30081)
				copy(value[origOffset+length+4:], destination.AsSlice())
				cases := []struct {
					name   string
					change func([]byte, *calicoServiceFlow)
					want   calicoFlowAction
				}{
					{"native-reply", func([]byte, *calicoServiceFlow) {}, calicoNativeReply},
					{"normal", func(v []byte, _ *calicoServiceFlow) { v[16] = 0 }, calicoTunnel},
					{"nat-forward", func(v []byte, _ *calicoServiceFlow) { v[16] = 1 }, calicoTunnel},
					{"unknown-type", func(v []byte, _ *calicoServiceFlow) { v[16] = 3 }, calicoUnclassified},
					{"pod-opener", func(v []byte, _ *calicoServiceFlow) { nl.NativeEndian().PutUint32(v[40:], 0x70) }, calicoTunnel},
					{"wrong-input", func(_ []byte, f *calicoServiceFlow) { f.input = uint32(uplink.Index) }, calicoUnclassified},
					{"foreign-service", func(v []byte, _ *calicoServiceFlow) { v[origOffset] ^= 1 }, calicoUnclassified},
					{"wrong-original-source", func(v []byte, _ *calicoServiceFlow) { v[origOffset+length+4] ^= 1 }, calicoUnclassified},
					{"nonzero-ctmark", func(_ []byte, f *calicoServiceFlow) { f.mark = 0x80000000 }, calicoUnclassified},
				}
				for _, tc := range cases {
					t.Run(tc.name, func(t *testing.T) {
						v := append([]byte(nil), value...)
						f := flow
						tc.change(v, &f)
						require.Equal(t, unix.Errno(0), updateCalicoTestMap(t, fd, key, v))
						require.Equal(t, tc.want, f.classifyCalicoFlow(readOnly, scope))
						require.Equal(t, unix.EPERM, updateCalicoTestMap(t, readOnly, key, v))
					})
				}
				t.Run("reverse-key-native-reply", func(t *testing.T) {
					reverseKey := calicoTestKey(destination, source, 18889, 18888)
					reversed := append([]byte(nil), value...)
					copy(reversed[24:48], value[48:72])
					copy(reversed[48:72], value[24:48])
					// Require the second lookup direction, with both legs exchanged.
					del := struct {
						FD, Pad uint32
						Key     uint64
					}{FD: uint32(fd), Key: uint64(uintptr(unsafe.Pointer(&key[0])))}
					_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_DELETE_ELEM, uintptr(unsafe.Pointer(&del)), unsafe.Sizeof(del))
					runtime.KeepAlive(key)
					require.Equal(t, unix.Errno(0), errno)
					require.Equal(t, unix.Errno(0), updateCalicoTestMap(t, fd, reverseKey, reversed))
					require.Equal(t, calicoNativeReply, flow.classifyCalicoFlow(readOnly, scope))
				})
				missing := flow
				missing.destinationPort++
				require.Equal(t, calicoUnclassified, missing.classifyCalicoFlow(readOnly, scope))
			})
		})
	}
}
