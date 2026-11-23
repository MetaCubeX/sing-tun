//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestCalicoTUNReplyWithStrictRPFilter(t *testing.T) {
	for _, backend := range []string{"nftables", "legacy"} {
		t.Run(backend, func(t *testing.T) {
			runCalicoIntegration(t, func() {
				setupForwardingPeers(t, "cali-backend")
				runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-backend")
				runTestIP(t, "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
				runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
				require.NoError(t, os.WriteFile(ipv4ConfPath+"/all/rp_filter", []byte("0"), 0))
				require.NoError(t, os.WriteFile(ipv4ConfPath+"/default/rp_filter", []byte("1"), 0))

				tdev := startTestAutoRoute(t, 0)
				if backend == "legacy" {
					tdev.routeAccess.Lock()
					useLegacyServiceFirewall(t, tdev.dnatBypass)
					err := tdev.refreshServiceRoutes()
					tdev.routeAccess.Unlock()
					require.NoError(t, err)
				}
				require.True(t, tdev.dnatBypass.calicoClassifierReady(0))
				filter, err := os.ReadFile(ipv4ConfPath + "/test-tun/rp_filter")
				require.NoError(t, err)
				require.Equal(t, "1", strings.TrimSpace(string(filter)))

				// Reproduce the SNAT and conntrack mark seen on the live workload flow.
				cmd := exec.Command("nft", "-f", "-")
				cmd.Stdin = strings.NewReader(fmt.Sprintf(`table ip reply_test {
chain post { type nat hook postrouting priority srcnat;
  oifname "test-tun" ip saddr 10.85.1.27 udp dport 53 ct mark set %#x snat to 198.18.0.1
}
}`, tdev.dnatBypass.forwardedInputMark()))
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))

				const request = "dns-request"
				const response = "dns-reply"
				cmd = exec.Command("ip", "netns", "exec", "backend", "python3", "-c", `
import socket
s=socket.socket(type=socket.SOCK_DGRAM)
s.settimeout(2)
s.bind(('10.85.1.27', 18888))
s.connect(('203.0.113.7', 53))
s.send(b'dns-request')
assert s.recv(256) == b'dns-reply'
print('workload received reply')
`)
				var output strings.Builder
				cmd.Stdout, cmd.Stderr = &output, &output
				require.NoError(t, cmd.Start())
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				readCalicoTestTUN(t, tdev, request)
				udp := make([]byte, 8+len(response))
				binary.BigEndian.PutUint16(udp, 53)
				binary.BigEndian.PutUint16(udp[2:], 18888)
				binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
				copy(udp[8:], response)
				packet := transportPacket(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("198.18.0.1"), unix.IPPROTO_UDP, udp)
				size, err := tdev.Write(packet)
				require.NoError(t, err)
				require.Equal(t, len(packet), size)
				err = cmd.Wait()
				require.NoError(t, err, "TUN reply did not reach the workload: %s", output.String())
				require.Contains(t, output.String(), "workload received reply")
			})
		})
	}
}
