//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/sagernet/netlink"
	"go4.org/netipx"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

type serviceForwardAction uint8

const (
	noServiceForwardAction serviceForwardAction = iota
	calicoWorkloadProbe
	calicoUplinkProbe
	ciliumReply
)

type serviceRoute struct {
	prefix     netip.Prefix
	iif        string
	forward    serviceForwardAction
	lookupBits int
}

func (r serviceRoute) family() int {
	if r.prefix.Addr().Is6() {
		return 1
	}
	return 0
}

func (r serviceRoute) isCalicoProbe() bool {
	return r.forward == calicoWorkloadProbe || r.forward == calicoUplinkProbe
}

type serviceRoutePlan struct {
	routes       map[serviceRoute]bool
	uplinks      []string
	calico       *calicoTopology
	discoveryErr error
}

func (t *NativeTun) refreshServiceRoutes() error {
	next, err := t.discoverServiceRoutes()
	if err != nil {
		if b := t.dnatBypass; b != nil && !b.calicoQueue.running() {
			err = errors.Join(err, t.removeCalicoProbeRules())
		}
		return err
	}

	return t.syncServicePlans(next)
}

func (t *NativeTun) syncServicePlans(next [2]serviceRoutePlan) error {
	var err error
	var needsQueue bool
	var markPaths map[string]struct{}
	var markReady bool
	for i, family := range next {
		if family.discoveryErr != nil {
			err = errors.Join(err, family.discoveryErr)
			continue
		}
		ingress := family.prepareProbes()
		if b := t.dnatBypass; b != nil && i == 0 && len(b.options.Inet4Address) > 0 {
			var sourceErr error
			markPaths, sourceErr = b.srcValidMarks.requireForRPF(ipv4ConfPath, ingress)
			markReady = sourceErr == nil
			if sourceErr != nil {
				for path := range family.routes {
					if path.isCalicoProbe() {
						delete(family.routes, path)
					}
				}
				ingress = nil
				err = errors.Join(err, sourceErr)
			}
		}
		needsQueue = needsQueue || len(ingress) > 0
	}
	if b := t.dnatBypass; b != nil {
		err = errors.Join(err, b.prepareCalicoQueue(needsQueue))
		defer b.closeUnusedCalicoQueue()
	}
	for i, family := range next {
		if family.discoveryErr != nil {
			if b := t.dnatBypass; b != nil && !b.calicoClassifierReady(i) {
				err = errors.Join(err, t.removeCalicoFamilyProbeRules(i))
			}
			continue
		}
		syncErr := t.syncServiceRoutes(i, family)
		err = errors.Join(err, syncErr)
		if syncErr == nil && i == 0 && markReady {
			err = errors.Join(err, t.dnatBypass.srcValidMarks.releaseExcept(markPaths))
		}
	}
	return err
}

// Socket load balancing can translate DNS to a backend before the first
// lookup. Calico can route the Service itself to its BPF ingress device.
func (t *NativeTun) discoverServiceRoutes() ([2]serviceRoutePlan, error) {
	var next [2]serviceRoutePlan
	for i := range next {
		next[i].routes = make(map[serviceRoute]bool)
	}
	var generation uint64
	if t.ipvsDNSBypass != nil {
		generation = t.ipvsDNSBypass.topologyVersion.Load()
	}
	links, err := netlink.LinkList()
	if err != nil {
		return next, err
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
	if len(gateways) == 0 {
		return next, nil
	}
	if calicoBPF && t.ipvsDNSBypass != nil {
		for i := range next {
			next[i].calico = &calicoTopology{
				generation: generation,
				version:    &t.ipvsDNSBypass.topologyVersion,
				workloads:  workloads,
				uplinks:    make(map[int][]netip.Addr),
			}
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return next, err
	}
	dns := make(map[netip.Prefix]serviceDNSRoute)
	for _, route := range routes {
		if (route.Family == unix.AF_INET && len(t.options.Inet4Address) == 0) ||
			(route.Family == unix.AF_INET6 && len(t.options.Inet6Address) == 0) {
			continue
		}
		var i int
		switch route.Family {
		case unix.AF_INET:
		case unix.AF_INET6:
			i = 1
		default:
			continue
		}
		family := &next[i]
		var prefixLength int
		if route.Dst != nil {
			prefixLength, _ = route.Dst.Mask.Size()
		}
		if prefixLength == 0 {
			if route.Type != unix.RTN_UNICAST {
				continue
			}
			if route.LinkIndex != 0 {
				family.discoveryErr = errors.Join(family.discoveryErr, family.addUplink(route.LinkIndex, route.Family))
			}
			for _, hop := range route.MultiPath {
				if hop.LinkIndex != 0 {
					family.discoveryErr = errors.Join(family.discoveryErr, family.addUplink(hop.LinkIndex, route.Family))
				}
			}
			continue
		}
		dst, err := netip.ParsePrefix(route.Dst.String())
		if err != nil {
			family.discoveryErr = errors.Join(family.discoveryErr, err)
			continue
		}
		dst = dst.Masked()
		if dst.Bits() == 0 {
			continue
		}

		device := gateways[route.LinkIndex]
		viaGateway := route.Type == unix.RTN_UNICAST && device != "" && route.Gw != nil
		localBackend := route.Type == unix.RTN_UNICAST && calicoBPF && workloads[route.LinkIndex] != "" && dst.IsSingleIP()
		if route.Family == unix.AF_INET6 {
			// IPv6 on-link routes are reported with universe scope.
			localBackend = localBackend && len(route.Gw) == 0 && route.Via == nil && len(route.MultiPath) == 0
		} else {
			localBackend = localBackend && route.Scope == netlink.SCOPE_LINK
		}
		isService := viaGateway || localBackend
		previous, exists := dns[dst]
		if !exists || route.Priority < previous.metric || (route.Priority == previous.metric && !isService) {
			dns[dst] = serviceDNSRoute{metric: route.Priority, service: isService}
		}
		if t.dnatBypass != nil {
			if viaGateway && device == "cilium_host" {
				family.routes[serviceRoute{prefix: dst, forward: ciliumReply}] = true
			}
			if localBackend {
				family.routes[serviceRoute{prefix: dst, iif: workloads[route.LinkIndex], forward: calicoWorkloadProbe}] = true
			}
		}
	}
	return next, addServiceDNSRoutes(next, dns)
}

func (f *serviceRoutePlan) addUplink(index, family int) error {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return err
	}
	// BPF reverse NAT does a new unmarked lookup using an address on this device.
	name := link.Attrs().Name
	var addresses []netip.Addr
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if f.calico != nil {
			addresses = append(addresses, ip)
		}
		if ip.IsGlobalUnicast() {
			f.routes[serviceRoute{prefix: netip.PrefixFrom(ip, ip.BitLen()), iif: name}] = true
			if !slices.Contains(f.uplinks, name) {
				f.uplinks = append(f.uplinks, name)
			}
		}
	}
	if f.calico != nil && slices.Contains(f.uplinks, name) {
		f.calico.uplinks[index] = addresses
	}
	return nil
}

type serviceDNSRoute struct {
	metric  int
	service bool
}

// Subtract each prefix's immediate children. Each address then belongs only
// to its longest main-table match, including a CNI route nested in a LAN route.
func addServiceDNSRoutes(next [2]serviceRoutePlan, routes map[netip.Prefix]serviceDNSRoute) error {
	children := make(map[netip.Prefix][]netip.Prefix)
	for prefix := range routes {
		for bits := prefix.Bits() - 1; bits > 0; bits-- {
			parent, _ := prefix.Addr().Prefix(bits)
			if route, ok := routes[parent]; ok {
				if route.service {
					children[parent] = append(children[parent], prefix)
				}
				break
			}
		}
	}
	for prefix, route := range routes {
		if !route.service {
			continue
		}
		path := serviceRoute{prefix: prefix, lookupBits: prefix.Bits()}
		plan := next[path.family()]
		if len(children[prefix]) == 0 {
			plan.routes[path] = true
			continue
		}
		var builder netipx.IPSetBuilder
		builder.AddPrefix(prefix)
		for _, child := range children[prefix] {
			builder.RemovePrefix(child)
		}
		allowed, err := builder.IPSet()
		if err != nil {
			return err
		}
		for _, part := range allowed.Prefixes() {
			path.prefix = part
			plan.routes[path] = true
		}
	}
	return nil
}

func (f serviceRoutePlan) prepareProbes() map[string]struct{} {
	if len(f.uplinks) == 0 {
		for path := range f.routes {
			if path.forward != noServiceForwardAction {
				delete(f.routes, path)
			}
		}
		return nil
	}
	ingress := make(map[string]struct{})
	for path := range f.routes {
		if path.forward != calicoWorkloadProbe {
			continue
		}
		ingress[path.iif] = struct{}{}
		for _, uplink := range f.uplinks {
			f.routes[serviceRoute{prefix: path.prefix, iif: uplink, forward: calicoUplinkProbe}] = true
			ingress[uplink] = struct{}{}
		}
	}
	return ingress
}

func (t *NativeTun) syncServiceRoutes(i int, next serviceRoutePlan) error {
	if t.serviceRoutes[i] == nil {
		t.serviceRoutes[i] = make(map[serviceRoute]bool)
	}
	installed := t.serviceRoutes[i]
	b := t.dnatBypass
	var err error
	var keepClassifier bool
	// Withdraw dependent rules before retiring or changing their classifier.
	for path := range installed {
		if next.routes[path] && (!path.isCalicoProbe() || b != nil && b.calicoClassifierReady(i)) {
			continue
		}
		if removeErr := t.removeServiceRoute(path); removeErr != nil {
			err = errors.Join(err, removeErr)
			keepClassifier = keepClassifier || path.forward != noServiceForwardAction
		}
	}
	if b != nil && !keepClassifier {
		var scope serviceForwardScope
		queue := b.calicoQueue
		for path := range next.routes {
			switch {
			case path.forward == ciliumReply:
				scope.cilium = true
			case path.forward == calicoWorkloadProbe && queue.running():
				scope.calicoWorkloads = true
				scope.queueNumber = queue.number
				scope.calico = next.calico
			default:
				continue
			}
			scope.backends = append(scope.backends, path.prefix)
		}
		if len(scope.backends) != 0 {
			scope.uplinks = next.uplinks
		}
		err = errors.Join(err, b.syncServiceForward(i, scope))
	}
	// An unsuccessful replacement leaves the previous classifier in service.
	for path := range next.routes {
		if installed[path] || path.forward != noServiceForwardAction && (b == nil || !b.serviceClassifierReady(i, path)) {
			continue
		}
		if addErr := addAutoRouteRule(t.serviceRouteRule(path)); addErr != nil && !errors.Is(addErr, unix.EEXIST) {
			err = errors.Join(err, addErr)
			continue
		}
		installed[path] = true
	}
	return err
}

func (t *NativeTun) removeServiceRoute(path serviceRoute) error {
	if err := deleteAutoRouteRule(t.serviceRouteRule(path)); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
		return err
	}
	delete(t.serviceRoutes[path.family()], path)
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
		if path.forward == calicoUplinkProbe {
			// Direct BPF delivery to a local workload skips host conntrack.
			// Fall back before even the specific DNS backend lookup.
			rule.Priority = t.options.IPRoute2RuleIndex
			rule.Dst = path.prefix
			rule.Type = unix.FR_ACT_UNREACHABLE
			return rule
		}
		rule.Src = path.prefix
		if path.forward == calicoWorkloadProbe {
			// Calico stamps packets handed to the kernel, but its BPF FIB
			// probe has no skb mark. A userspace TUN cannot fast-forward
			// that ambiguous tuple. Let BPF fall back to the IP stack,
			// where conntrack distinguishes a service reply from pod egress.
			index := 0
			if path.prefix.Addr().Is6() {
				index = 1
			}
			rule.Priority = t.forwardPriority[index]
			rule.Type = unix.FR_ACT_UNREACHABLE
			return rule
		}
		rule.Goto = t.options.IPRoute2RuleIndex + 10
		return rule
	}
	rule.Dst = path.prefix
	rule.Dport = netlink.NewRulePortRange(53, 53)
	rule.Table = unix.RT_TABLE_MAIN
	// Check against the original CNI route even when the rule covers a fragment.
	rule.SuppressPrefixlen = path.lookupBits - 1
	return rule
}
