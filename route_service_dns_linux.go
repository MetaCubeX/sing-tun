//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

type serviceRoute struct {
	prefix netip.Prefix
}

// Socket load balancing can translate a DNS Service to a backend before
// the first route lookup. Calico can instead route the Service itself to
// its BPF ingress device. Neither path carries a netfilter DNAT status.
func (t *NativeTun) refreshServiceRoutes() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	gateways := make(map[int]bool)
	workloads := make(map[int]string)
	var calicoBPF bool
	for _, link := range links {
		if link.Type() != "veth" {
			continue
		}
		a := link.Attrs()
		switch {
		case a.Name == "cilium_host" || a.Name == "bpfin.cali":
			gateways[a.Index] = true
			calicoBPF = calicoBPF || a.Name == "bpfin.cali"
		case strings.HasPrefix(a.Name, "cali"):
			workloads[a.Index] = a.Name
		}
	}
	next := make(map[serviceRoute]bool)
	if len(gateways) > 0 {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if route.Dst == nil || route.Type != unix.RTN_UNICAST || route.LinkIndex == 0 ||
				(route.Family == unix.AF_INET && len(t.options.Inet4Address) == 0) ||
				(route.Family == unix.AF_INET6 && len(t.options.Inet6Address) == 0) {
				continue
			}
			hostBits, bits := route.Dst.Mask.Size()
			viaGateway := gateways[route.LinkIndex] && route.Gw != nil
			localBackend := calicoBPF && workloads[route.LinkIndex] != "" && hostBits == bits
			if route.Family == unix.AF_INET6 {
				// IPv6 on-link routes are reported with universe scope.
				localBackend = localBackend && bits == 128 && len(route.Gw) == 0 && route.Via == nil && len(route.MultiPath) == 0
			} else {
				localBackend = localBackend && route.Scope == netlink.SCOPE_LINK
			}
			if !viaGateway && !localBackend {
				continue
			}
			dst, err := netip.ParsePrefix(route.Dst.String())
			if err != nil {
				return err
			}
			if dst.Bits() == 0 {
				continue
			}
			next[serviceRoute{prefix: dst.Masked()}] = true
		}
	}
	if t.serviceRoutes == nil {
		t.serviceRoutes = make(map[serviceRoute]bool)
	}
	for path := range t.serviceRoutes {
		if !next[path] {
			if err := deleteAutoRouteRule(t.serviceRouteRule(path)); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
				return err
			}
			delete(t.serviceRoutes, path)
		}
	}
	for path := range next {
		if t.serviceRoutes[path] {
			continue
		}
		if err := addAutoRouteRule(t.serviceRouteRule(path)); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		t.serviceRoutes[path] = true
	}
	return nil
}

func (t *NativeTun) serviceRouteRule(path serviceRoute) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	if path.prefix.Addr().Is6() {
		rule.Family = unix.AF_INET6
	}
	rule.Priority = t.options.IPRoute2RuleIndex
	if t.dnatBypass != nil {
		rule.Priority++
	}
	rule.Dst = path.prefix
	rule.Dport = netlink.NewRulePortRange(53, 53)
	rule.Table = unix.RT_TABLE_MAIN
	// Never fall through to a broader main-table route during an update.
	rule.SuppressPrefixlen = path.prefix.Bits() - 1
	return rule
}
