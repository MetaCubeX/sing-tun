package tun

import "net/netip"

type DNSHijackRule struct {
	Network string
	Address netip.AddrPort
}
