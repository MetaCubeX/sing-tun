//go:build linux

package tun

import (
	"github.com/metacubex/nftables"
)

func (r *autoRedirect) nftablesCreateConfiguredDNSHijackRules(nft *nftables.Conn, table *nftables.Table, chain *nftables.Chain) error {
	for _, family := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		if family == nftables.TableFamilyIPv4 && !r.enableIPv4 || family == nftables.TableFamilyIPv6 && !r.enableIPv6 {
			continue
		}
		setID, setName := uint32(5), "inet4_local_address_set"
		if family == nftables.TableFamilyIPv6 {
			setID, setName = 6, "inet6_local_address_set"
		}
		if r.tunOptions.DNSHijack == nil {
			if err := r.nftablesCreateDNSHijackRulesForFamily(nft, table, chain, family, setID, setName, nil); err != nil {
				return err
			}
			continue
		}
		for _, destination := range r.tunOptions.DNSHijack {
			address := destination.Address.Addr()
			if address.Zone() != "" {
				continue
			}
			if !address.IsUnspecified() && address.Is4() != (family == nftables.TableFamilyIPv4) {
				continue
			}
			if err := r.nftablesCreateDNSHijackRulesForFamily(nft, table, chain, family, setID, setName, &destination); err != nil {
				return err
			}
		}
	}
	return nil
}
