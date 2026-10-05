//go:build ios

package systemconfiguration

import "net/netip"

// DNSRegistration is a no-op on iOS, where NetworkExtension owns DNS configuration.
type DNSRegistration struct{}

// RegisterDNS leaves DNS configuration to NetworkExtension on iOS.
func RegisterDNS(_ string, _ []netip.Addr) (*DNSRegistration, error) {
	return &DNSRegistration{}, nil
}

func (*DNSRegistration) Close() error {
	return nil
}
