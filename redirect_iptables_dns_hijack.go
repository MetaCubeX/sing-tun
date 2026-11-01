//go:build linux

package tun

import (
	"net/netip"
	"strings"
)

func (r *autoRedirect) iptablesCreateDNSHijackRules(path, chain string, routeAddress []netip.Prefix) error {
	rules := r.tunOptions.DNSHijack
	if rules == nil {
		rules = []DNSHijackRule{{Network: "udp", Address: netip.AddrPortFrom(netip.IPv4Unspecified(), 53)}}
	}
	getServers := r.tunOptions.Inet4DNSAddress
	if path != r.iptablesPath {
		getServers = r.tunOptions.Inet6DNSAddress
	}
	var target string
	for _, rule := range rules {
		address := rule.Address.Addr()
		if address.Zone() != "" || rule.Network == "tcp" || !address.IsUnspecified() && address.Is4() != (path == r.iptablesPath) {
			continue
		}
		var selectors []string
		destination := ""
		if !address.IsUnspecified() {
			allowed := len(routeAddress) == 0
			for _, prefix := range routeAddress {
				allowed = allowed || prefix.Contains(address)
			}
			if !allowed {
				continue
			}
			destination = "-d " + address.String()
		}
		if len(routeAddress) > 0 && destination == "" {
			for _, prefix := range routeAddress {
				selectors = append(selectors, "-d "+prefix.String())
			}
		} else if len(routeAddress) == 0 && (len(r.tunOptions.IncludeInterface) > 0 || len(r.tunOptions.IncludeUID) > 0) {
			for _, name := range r.tunOptions.IncludeInterface {
				selectors = append(selectors, destination+" -i "+name)
			}
		} else {
			selectors = []string{destination}
		}
		for _, selector := range selectors {
			if target == "" {
				servers, err := getServers()
				if err != nil || len(servers) == 0 {
					return err
				}
				target = servers[0].String()
				if r.tunOptions.DNSHijack != nil {
					target = netip.AddrPortFrom(servers[0], 53).String()
				}
			}
			command := []any{path, "-t nat -A", chain}
			if selector = strings.TrimSpace(selector); selector != "" {
				command = append(command, selector)
			}
			command = append(command, "-p udp --dport", rule.Address.Port(), "-j DNAT --to", target)
			if err := r.runShell(command...); err != nil {
				return err
			}
		}
	}
	return nil
}
