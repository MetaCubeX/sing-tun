//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/sagernet/netlink"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

type serviceForwardAction uint8

const (
	noServiceForwardAction serviceForwardAction = iota
	ciliumReply
)

type serviceRoute struct {
	prefix  netip.Prefix
	iif     string
	forward serviceForwardAction
}

// Socket load balancing can translate a DNS Service to a backend before
// the first route lookup. Calico can instead route the Service itself to
// its BPF ingress device. Neither path carries a netfilter DNAT status.
func (t *NativeTun) refreshServiceRoutes() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	gateways := make(map[int]string)
	workloads := make(map[int]string)
	var calicoBPF bool
	for _, link := range links {
		if link.Type() != "veth" {
			continue
		}
		a := link.Attrs()
		switch {
		case a.Name == "cilium_host" || a.Name == "bpfin.cali":
			gateways[a.Index] = a.Name
			calicoBPF = calicoBPF || a.Name == "bpfin.cali"
		case strings.HasPrefix(a.Name, "cali"):
			workloads[a.Index] = a.Name
		}
	}
	next := make(map[serviceRoute]bool)
	var forward [2]serviceForwardScope
	if len(gateways) > 0 {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if route.Type != unix.RTN_UNICAST || route.LinkIndex == 0 ||
				(route.Family == unix.AF_INET && len(t.options.Inet4Address) == 0) ||
				(route.Family == unix.AF_INET6 && len(t.options.Inet6Address) == 0) {
				continue
			}
			i := 0
			if route.Family == unix.AF_INET6 {
				i = 1
			}
			scope := &forward[i]
			if route.Dst == nil {
				link, err := netlink.LinkByIndex(route.LinkIndex)
				if err != nil {
					return err
				}
				// BPF reverse NAT performs a new unmarked FIB lookup at
				// the uplink with an address owned by that same device.
				addrs, err := netlink.AddrList(link, route.Family)
				if err != nil {
					return err
				}
				for _, a := range addrs {
					ip, ok := netip.AddrFromSlice(a.IP)
					ip = ip.Unmap()
					if ok && ip.IsGlobalUnicast() {
						next[serviceRoute{prefix: netip.PrefixFrom(ip, ip.BitLen()), iif: link.Attrs().Name}] = true
						if !slices.Contains(scope.uplinks, link.Attrs().Name) {
							scope.uplinks = append(scope.uplinks, link.Attrs().Name)
						}
					}
				}
				continue
			}
			hostBits, bits := route.Dst.Mask.Size()
			viaGateway := gateways[route.LinkIndex] != "" && route.Gw != nil
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
			if gateways[route.LinkIndex] == "cilium_host" && t.dnatBypass != nil {
				scope.backends = append(scope.backends, dst.Masked())
				scope.cilium = true
				next[serviceRoute{prefix: dst.Masked(), forward: ciliumReply}] = true
			}
		}
	}
	if t.serviceRoutes == nil {
		t.serviceRoutes = make(map[serviceRoute]bool)
	}
	for path := range next {
		if path.forward != ciliumReply {
			continue
		}
		i := 0
		if path.prefix.Addr().Is6() {
			i = 1
		}
		if len(forward[i].uplinks) == 0 {
			delete(next, path)
		}
	}
	for path := range t.serviceRoutes {
		if !next[path] {
			if err := t.removeServiceRoute(path); err != nil {
				return err
			}
		}
	}
	var forwardErr error
	if t.dnatBypass != nil {
		forwardErr = t.dnatBypass.syncServiceForward(forward)
	}
	for path := range next {
		if t.serviceRoutes[path] || (path.forward != noServiceForwardAction && forwardErr != nil) {
			continue
		}
		if err := addAutoRouteRule(t.serviceRouteRule(path)); err != nil && !errors.Is(err, unix.EEXIST) {
			return errors.Join(forwardErr, err)
		}
		t.serviceRoutes[path] = true
	}
	return forwardErr
}

func (t *NativeTun) removeServiceRoute(path serviceRoute) error {
	if err := deleteAutoRouteRule(t.serviceRouteRule(path)); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
		return err
	}
	delete(t.serviceRoutes, path)
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
	if path.forward == ciliumReply {
		rule.Src = path.prefix
		rule.MarkSet, rule.Mark, rule.Mask = true, ciliumRoutedIdentity, ciliumMarkMask
		rule.Goto = t.options.IPRoute2RuleIndex + 10
		return rule
	}
	if path.iif != "" {
		rule.IifName = path.iif
		allBits := ^uint32(0)
		rule.MarkSet, rule.Mask = true, int(allBits)
		rule.Src = path.prefix
		rule.Goto = t.options.IPRoute2RuleIndex + 10
		return rule
	}
	rule.Dst = path.prefix
	rule.Dport = netlink.NewRulePortRange(53, 53)
	rule.Table = unix.RT_TABLE_MAIN
	// Never fall through to a broader main-table route during an update.
	rule.SuppressPrefixlen = path.prefix.Bits() - 1
	return rule
}
