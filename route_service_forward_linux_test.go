//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/stretchr/testify/require"
)

func TestCalicoServiceQueueFollowsConsumers(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "cali-backend")
		runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
		runTestIP(t, "-4", "route", "add", "10.85.1.27/32", "dev", "cali-backend")
		runTestIP(t, "-6", "route", "add", "fd52:1::27/128", "dev", "cali-backend")
		n := startTestAutoRoute(t, 0)
		n.routeAccess.Lock()
		defer n.routeAccess.Unlock()
		b := n.dnatBypass
		require.NotNil(t, b)
		queueNumber := fmt.Sprint(uint16(b.options.IPRoute2TableIndex))
		queueBound := func() bool {
			t.Helper()
			data, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
			if os.IsNotExist(err) {
				return false
			}
			require.NoError(t, err)
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && fields[0] == queueNumber {
					return true
				}
			}
			return false
		}
		require.False(t, queueBound(), "no family has an uplink")
		runTestIP(t, "-4", "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
		runTestIP(t, "-6", "route", "add", "default", "via", "fd51:1::2", "dev", "edge0")
		require.NoError(t, n.refreshServiceRoutes())
		require.True(t, queueBound())
		queue := b.calicoQueue
		runTestIP(t, "-4", "route", "del", "10.85.1.27/32", "dev", "cali-backend")
		require.NoError(t, n.refreshServiceRoutes())
		require.True(t, queueBound(), "IPv6 still consumes the queue")
		require.Same(t, queue, b.calicoQueue)
		runTestIP(t, "-6", "route", "del", "fd52:1::27/128", "dev", "cali-backend")
		require.NoError(t, n.refreshServiceRoutes())
		require.False(t, queueBound(), "the last classifier was removed")
		require.Nil(t, b.calicoQueue)
		select {
		case <-queue.done:
		default:
			t.Fatal("queue reader is still running")
		}
		runTestIP(t, "-4", "route", "add", "10.85.1.31/32", "dev", "cali-backend")
		require.NoError(t, n.refreshServiceRoutes())
		require.True(t, queueBound(), "a new workload rebinds the queue")
		require.NotSame(t, queue, b.calicoQueue)
	})
}

// Address changes must refresh the classifier even when the same interface
// and backends remain in the firewall.
func TestCalicoQueueRefreshesUplinkAddresses(t *testing.T) {
	runCalicoIntegration(t, func() {
		setupForwardingPeers(t, "cali-backend")
		runTestIP(t, "link", "add", "bpfin.cali", "type", "veth", "peer", "name", "bpfout.cali")
		runTestIP(t, "-4", "route", "add", "10.85.1.27/32", "dev", "cali-backend")
		runTestIP(t, "-4", "route", "add", "default", "via", "192.0.2.2", "dev", "edge0")
		n := startTestAutoRoute(t, 0)
		workload, err := netlink.LinkByName("cali-backend")
		require.NoError(t, err)
		uplink, err := netlink.LinkByName("edge0")
		require.NoError(t, err)
		index := uplink.Attrs().Index
		source := workload.Attrs().Index
		addr := netip.MustParseAddr("192.0.2.91")
		snapshot := func() *calicoTopology {
			n.routeAccess.Lock()
			defer n.routeAccess.Unlock()
			return n.dnatBypass.forwardScopes[0].calico
		}
		old := snapshot()
		require.NotNil(t, old)
		runTestIP(t, "addr", "add", addr.String()+"/32", "dev", "edge0")
		require.Eventually(t, func() bool {
			current := snapshot()
			return current != nil && current.generation != old.generation &&
				current.version.Load() == current.generation &&
				(serviceForwardScope{calico: current}).matchesCalicoInterfaces(source, index, addr)
		}, 3*time.Second, 20*time.Millisecond)
		runTestIP(t, "addr", "del", addr.String()+"/32", "dev", "edge0")
		require.Eventually(t, func() bool {
			current := snapshot()
			return current != nil && current.version.Load() == current.generation &&
				!(serviceForwardScope{calico: current}).matchesCalicoInterfaces(source, index, addr)
		}, 3*time.Second, 20*time.Millisecond)
	})
}
