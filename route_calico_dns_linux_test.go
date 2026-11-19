//go:build linux

package tun

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCalicoLocalPodDNS(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "cali-dns")
		runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
		runTestIP(t, "route", "add", "10.85.1.27/32", "dev", "cali-dns")
		runTestIP(t, "-6", "route", "add", "fd52:1::27/128", "dev", "cali-dns")
		runTestIP(t, "-6", "route", "add", "fd52:1::28/128", "via", "fd52:1::27", "dev", "cali-dns")
		runTestIP(t, "-6", "route", "add", "fd52:2::/64", "dev", "cali-dns")
		runTestIP(t, "-6", "route", "add", "fd51:1::55/128", "dev", "edge0")
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
		}, 4*time.Second, 20*time.Millisecond, "link-local addresses must finish duplicate-address detection")

		const query = "9c13010000010000000000000374756e04746573740000010001"
		const answer = "9c13818000010001000000000374756e04746573740000010001c00c000100010000003c0004c000022a"
		server := exec.Command("ip", "netns", "exec", "backend", "python3", "-u", "-c", `
import selectors, socket, sys
query, answer = map(bytes.fromhex, sys.argv[1:])
selector = selectors.DefaultSelector()
for family, address in [(socket.AF_INET, "10.85.1.27"), (socket.AF_INET6, "fd52:1::27")]:
    for transport in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
        listener = socket.socket(family, transport)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, 53))
        if transport == socket.SOCK_STREAM:
            listener.listen()
        selector.register(listener, selectors.EVENT_READ)
print("ready")
while True:
    for key, _ in selector.select():
        listener = key.fileobj
        if listener.type == socket.SOCK_DGRAM:
            request, address = listener.recvfrom(512)
            assert request == query
            listener.sendto(answer, address)
        else:
            conn, _ = listener.accept()
            with conn, conn.makefile("rb") as stream:
                conn.settimeout(2)
                assert stream.read(2) == len(query).to_bytes(2, "big")
                assert stream.read(len(query)) == query
                conn.sendall(len(answer).to_bytes(2, "big") + answer)
`, query, answer)
		server.Stderr = os.Stderr
		stdout, err := server.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, server.Start())
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
		line := bufio.NewScanner(stdout)
		require.True(t, line.Scan())
		require.Equal(t, "ready", line.Text())

		checkDNS := func(stage string) {
			t.Helper()
			for _, address := range []string{"10.85.1.27", "fd52:1::27"} {
				for _, transport := range []string{"udp", "tcp"} {
					cmd := exec.Command("ip", "netns", "exec", "client", "python3", "-c", `
import socket, sys
address, transport, query = sys.argv[1:]
query = bytes.fromhex(query)
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM) as conn:
    conn.settimeout(2)
    conn.connect((address, 53))
    if transport == "tcp":
        conn.sendall(len(query).to_bytes(2, "big") + query)
        with conn.makefile("rb") as stream:
            response = stream.read(int.from_bytes(stream.read(2), "big"))
    else:
        conn.send(query)
        response = conn.recv(512)
    print(response.hex())
`, address, transport, query)
					out, err := cmd.CombinedOutput()
					require.NoError(t, err, "%s %s DNS to %s: %s", stage, transport, address, out)
					require.Equal(t, answer, strings.TrimSpace(string(out)))
				}
			}
		}
		checkDNS("before TUN")
		startTestAutoRoute(t, 0)
		checkDNS("with TUN")
		rules := runTestIP(t, "-6", "rule", "show")
		require.Contains(t, rules, "to fd52:1::27")
		for _, dst := range []string{"fd52:1::28", "fd52:2::/64", "fd51:1::55"} {
			require.NotContains(t, rules, "to "+dst)
		}
		runTestIP(t, "-6", "route", "del", "fd52:1::27/128", "dev", "cali-dns")
		require.Eventually(t, func() bool {
			return !strings.Contains(runTestIP(t, "-6", "rule", "show"), "to fd52:1::27")
		}, 8*time.Second, 100*time.Millisecond)
	})
}
