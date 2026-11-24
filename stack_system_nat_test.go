package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func fillTCPNat(tb testing.TB) (*TCPNat, netip.AddrPort, netip.AddrPort) {
	tb.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(cancel)
	nat := NewNat(ctx, time.Hour)
	source := netip.MustParseAddrPort("[2001:db8::1]:9999")
	destination := netip.MustParseAddrPort("[2001:db8::2]:443")
	for port := 10000; port <= 65535; port++ {
		mapped, err := nat.Lookup(netip.AddrPortFrom(source.Addr(), uint16(port)), destination)
		if err != nil || int(mapped) != port {
			tb.Fatalf("allocating port %d: got %d, %v", port, mapped, err)
		}
	}
	return nat, source, destination
}

func TestTCPNatPortExhaustion(t *testing.T) {
	nat, source, destination := fillTCPNat(t)
	if port, err := nat.Lookup(source, destination); port != 0 || err == nil {
		t.Fatalf("lookup with a full NAT table: got %d, %v", port, err)
	}

	const activePort = 10000
	active := netip.AddrPortFrom(source.Addr(), activePort)
	if port, err := nat.Lookup(active, destination); port != activePort || err != nil {
		t.Fatalf("existing mapping with a full NAT table: got %d, %v", port, err)
	}

	const expiredPort = 65535
	session := nat.LookupBack(expiredPort)
	if session == nil {
		t.Fatal("missing reverse mapping")
	}
	session.Lock()
	session.LastActive = time.Now().Add(-2 * time.Hour)
	session.Unlock()
	nat.checkTimeout()
	if port, err := nat.Lookup(source, destination); port != expiredPort || err != nil {
		t.Fatalf("lookup after a mapping expired: got %d, %v", port, err)
	}
}

func BenchmarkTCPNatExhaustedLookup(b *testing.B) {
	nat, source, destination := fillTCPNat(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if port, err := nat.Lookup(source, destination); port != 0 || err == nil {
			b.Fatalf("lookup with a full NAT table: got %d, %v", port, err)
		}
	}
}
