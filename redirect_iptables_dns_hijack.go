//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

func (r *autoRedirect) iptablesDNSHijackRules(path string, routeAddress []netip.Prefix, localPeers []string) ([]string, error) {
	rules := r.tunOptions.DNSHijack
	if rules == nil {
		rules = []DNSHijackRule{{Network: "udp", Address: netip.AddrPortFrom(netip.IPv4Unspecified(), 53)}}
	}
	getServers := r.tunOptions.Inet4DNSAddress
	if path != r.iptablesPath {
		getServers = r.tunOptions.Inet6DNSAddress
	}
	var target string
	var commands []string
	for _, rule := range rules {
		address := rule.Address.Addr()
		if !address.IsValid() || rule.Address.Port() == 0 || address.Zone() != "" || rule.Network == "tcp" || !address.IsUnspecified() && address.Is4() != (path == r.iptablesPath) {
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
		} else if localPeers == nil && len(routeAddress) == 0 && (len(r.tunOptions.IncludeInterface) > 0 || len(r.tunOptions.IncludeUID) > 0) {
			for _, name := range r.tunOptions.IncludeInterface {
				selectors = append(selectors, destination+" -i "+name)
			}
		} else {
			selectors = []string{destination}
		}
		if localPeers != nil {
			var scoped []string
			for _, peer := range localPeers {
				for _, selector := range selectors {
					scoped = append(scoped, selector+" "+peer)
				}
			}
			selectors = scoped
		}
		for _, selector := range selectors {
			if target == "" {
				servers, err := getServers()
				if err != nil || len(servers) == 0 {
					return nil, err
				}
				target = servers[0].String()
				if r.tunOptions.DNSHijack != nil {
					target = netip.AddrPortFrom(servers[0], 53).String()
				}
			}
			command := strings.TrimSpace(selector)
			if command != "" {
				command += " "
			}
			commands = append(commands, fmt.Sprintf("%s-p udp --dport %d -j DNAT --to %s", command, rule.Address.Port(), target))
		}
	}
	return commands, nil
}

// Only directly connected peers may have local gateway DNS intercepted.
func (r *autoRedirect) iptablesLocalDNSPeers(ipv4 bool) ([]string, error) {
	if r.interfaceFinder == nil {
		return nil, nil
	}
	if err := r.interfaceFinder.Update(); err != nil {
		return nil, err
	}
	if len(r.tunOptions.IncludeUID) > 0 && len(r.tunOptions.IncludeInterface) == 0 {
		return nil, nil
	}
	var selectors []string
	for _, iface := range r.interfaceFinder.Interfaces() {
		if iface.Name == "lo" || iface.Name == r.tunOptions.Name ||
			len(r.tunOptions.IncludeInterface) != 0 && !slices.Contains(r.tunOptions.IncludeInterface, iface.Name) {
			continue
		}
		for _, addr := range iface.Addresses {
			if addr.Addr().Is4() == ipv4 && addr.Addr().IsGlobalUnicast() && !addr.IsSingleIP() {
				selectors = append(selectors, "-i "+strconv.Quote(iface.Name)+" -s "+addr.Masked().String()+" -m addrtype --dst-type LOCAL")
			}
		}
	}
	return selectors, nil
}

func (r *autoRedirect) syncIPTablesLocalDNS(path string, routeAddress []netip.Prefix) error {
	i := 0
	if path != r.iptablesPath {
		i = 1
	}
	peers, err := r.iptablesLocalDNSPeers(i == 0)
	if err != nil {
		return err
	}
	var rules []string
	if len(peers) > 0 {
		rules, err = r.iptablesDNSHijackRules(path, routeAddress, peers)
		if err != nil {
			return err
		}
	}
	if slices.Equal(r.legacyDNSRules[i], rules) {
		return nil
	}
	chain := r.tableName + "-local-dns"
	var program strings.Builder
	fmt.Fprintf(&program, "*nat\n-F %s\n", chain)
	for _, rule := range rules {
		fmt.Fprintf(&program, "-A %s %s\n", chain, rule)
	}
	program.WriteString("COMMIT\n")
	cmd := exec.Command(path+"-restore", "--wait", "5", "--noflush")
	cmd.Stdin = strings.NewReader(program.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("refresh legacy gateway DNS: %w: %s", err, out)
	}
	r.legacyDNSRules[i] = rules
	return nil
}

func (r *autoRedirect) refreshIPTablesLocalDNS() {
	r.legacyDNSAccess.Lock()
	defer r.legacyDNSAccess.Unlock()
	if !r.legacyDNSActive {
		return
	}
	for i, path := range []string{r.iptablesPath, r.ip6tablesPath} {
		if path == "" {
			continue
		}
		routes := r.tunOptions.Inet4RouteAddress
		if i == 1 {
			routes = r.tunOptions.Inet6RouteAddress
		}
		if err := r.syncIPTablesLocalDNS(path, routes); err != nil && r.logger != nil {
			r.logger.Error("refresh legacy gateway DNS: ", err)
		}
	}
}
