//go:build linux

package tun

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

const (
	ipvsTablePath          = "/proc/net/ip_vs"
	ipvsDNSRefreshInterval = 5 * time.Second
)

type ipvsSnapshot struct {
	destinations []ipvsDNSDestination
	hasServices  [2]bool
}

type autoRouteIPVSDNSBypass struct {
	path string

	topologyVersion atomic.Uint64
	access          sync.RWMutex
	destinations    []ipvsDNSDestination
	hasServices     [2]bool
	started         bool
	closeOnce       sync.Once
	events          chan struct{}
	stop            chan struct{}
	done            chan struct{}
}

type ipvsDNSDestination struct {
	protocol int
	endpoint netip.AddrPort
}

func newAutoRouteIPVSDNSBypass(path string) (*autoRouteIPVSDNSBypass, error) {
	bypass := &autoRouteIPVSDNSBypass{
		path:   path,
		events: make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	snapshot, err := bypass.LoadSnapshot()
	if err == nil {
		bypass.destinations = snapshot.destinations
		bypass.hasServices = snapshot.hasServices
	}
	return bypass, err
}

func subscribeAutoRouteNetlink(protocol int, groups ...uint) (*nl.NetlinkSocket, error) {
	// The pinned Subscribe implementation does not set SOCK_CLOEXEC.
	// Prevent an iptables child from keeping a closed queue or watcher alive.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	socket, err := nl.Subscribe(protocol, groups...)
	if err == nil {
		unix.CloseOnExec(socket.GetFd())
	}
	return socket, err
}

func (b *autoRouteIPVSDNSBypass) Start(update func()) error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.started {
		return nil
	}
	routes, err := subscribeAutoRouteNetlink(unix.NETLINK_ROUTE, unix.RTNLGRP_IPV4_ROUTE, unix.RTNLGRP_IPV6_ROUTE,
		unix.RTNLGRP_LINK, unix.RTNLGRP_IPV4_IFADDR, unix.RTNLGRP_IPV6_IFADDR)
	if err != nil {
		return err
	}
	var listeners sync.WaitGroup
	listeners.Add(1)
	go func() {
		defer listeners.Done()
		notify := func() {
			select {
			case b.events <- struct{}{}:
			default:
			}
		}
		for {
			messages, from, err := routes.Receive()
			if errors.Is(err, unix.ENOBUFS) {
				// Rebuild from a complete snapshot after lost route events.
				b.topologyVersion.Add(1)
				notify()
				continue
			}
			if err != nil {
				b.topologyVersion.Add(1)
				return
			}
			if from.Pid != nl.PidKernel {
				continue
			}
			var routeChanged, topologyChanged bool
			for _, message := range messages {
				switch message.Header.Type {
				case unix.RTM_NEWLINK, unix.RTM_DELLINK, unix.RTM_NEWADDR, unix.RTM_DELADDR:
					topologyChanged = true
				case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
					routeChanged = true
				}
			}
			if topologyChanged {
				b.topologyVersion.Add(1)
			}
			if topologyChanged || routeChanged {
				notify()
			}
		}
	}()
	b.started = true
	go func() {
		defer close(b.done)
		defer func() { routes.Close(); listeners.Wait() }()
		ticker := time.NewTicker(ipvsDNSRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-b.stop:
				return
			default:
			}
			select {
			case <-b.events:
				update()
			case <-ticker.C:
				update()
			case <-b.stop:
				return
			}
		}
	}()
	return nil
}

func (b *autoRouteIPVSDNSBypass) Close() {
	b.access.RLock()
	started := b.started
	b.access.RUnlock()
	if !started {
		return
	}
	b.closeOnce.Do(func() { close(b.stop) })
	<-b.done
}

func (b *autoRouteIPVSDNSBypass) Load() ([]ipvsDNSDestination, error) {
	snapshot, err := b.LoadSnapshot()
	return snapshot.destinations, err
}

func (b *autoRouteIPVSDNSBypass) LoadSnapshot() (ipvsSnapshot, error) {
	snapshot, err := readIPVSSnapshot(b.path)
	if os.IsNotExist(err) {
		return ipvsSnapshot{}, nil
	}
	return snapshot, err
}

func (b *autoRouteIPVSDNSBypass) Destinations() []ipvsDNSDestination {
	b.access.RLock()
	defer b.access.RUnlock()
	return append([]ipvsDNSDestination(nil), b.destinations...)
}

func (b *autoRouteIPVSDNSBypass) Replace(destinations []ipvsDNSDestination) {
	b.access.Lock()
	b.destinations = append([]ipvsDNSDestination(nil), destinations...)
	b.access.Unlock()
}

func (b *autoRouteIPVSDNSBypass) setHasServices(hasServices [2]bool) {
	b.access.Lock()
	b.hasServices = hasServices
	b.access.Unlock()
}

func (b *autoRouteIPVSDNSBypass) serviceActive(family int) bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	active := b.hasServices[family]
	b.access.RUnlock()
	return active
}

func (t *NativeTun) enableAutoRouteIPVSDNSBypass(path string) {
	bypass, err := newAutoRouteIPVSDNSBypass(path)
	t.ipvsDNSBypass = bypass
	if t.dnatBypass != nil {
		t.dnatBypass.serviceEvents = bypass.events
	}
	if err != nil && t.options.Logger != nil {
		t.options.Logger.Warn(E.Cause(err, "read initial IPVS DNS backends; retrying on refresh"))
	}
}

func (t *NativeTun) refreshIPVSDNSBypass() {
	t.routeAccess.Lock()
	defer t.routeAccess.Unlock()

	if b := t.dnatBypass; b != nil && b.useNFTables {
		if err := b.refreshLocalDNATDestinations(); err != nil && t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(err, "refresh published port destinations"))
		}
	}
	if t.options.AutoRedirectMarkMode {
		if b := t.dnatBypass; b != nil && len(b.options.Inet4Address) > 0 {
			if err := b.srcValidMarks.syncForRPF(ipv4ConfPath, nil); err != nil && t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(err, "refresh src_valid_mark"))
			}
		}
		return
	}
	if err := t.refreshServiceRoutes(); err != nil && t.options.Logger != nil {
		t.options.Logger.Warn(E.Cause(err, "refresh eBPF service routes"))
	}
	snapshot, err := t.ipvsDNSBypass.LoadSnapshot()
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(err, "refresh auto-route IPVS DNS bypass"))
		}
		return
	}
	t.ipvsDNSBypass.setHasServices(snapshot.hasServices)
	oldDestinations := t.ipvsDNSBypass.Destinations()
	installed, err := t.updateIPVSDNSRules(oldDestinations, snapshot.destinations, addIPVSDNSRule, deleteIPVSDNSRule)
	t.ipvsDNSBypass.Replace(installed)
	if err != nil && t.options.Logger != nil {
		t.options.Logger.Error(E.Cause(err, "update auto-route IPVS DNS bypass"))
	}
}

type ipvsDNSRuleOperation func(*netlink.Rule) error

func ipvsDNSDestinationsByFamily(destinations []ipvsDNSDestination) [2][]ipvsDNSDestination {
	var families [2][]ipvsDNSDestination
	for _, destination := range destinations {
		family := 0
		if destination.endpoint.Addr().Is6() {
			family = 1
		}
		families[family] = append(families[family], destination)
	}
	return families
}

func (t *NativeTun) updateIPVSDNSRules(
	oldDestinations, newDestinations []ipvsDNSDestination,
	addRule, deleteRule ipvsDNSRuleOperation,
) ([]ipvsDNSDestination, error) {
	oldFamilies := ipvsDNSDestinationsByFamily(oldDestinations)
	newFamilies := ipvsDNSDestinationsByFamily(newDestinations)
	var installed []ipvsDNSDestination
	var err error
	for family, next := range newFamilies {
		current, familyErr := t.updateIPVSDNSFamily(family, oldFamilies[family], next, addRule, deleteRule)
		installed = append(installed, current...)
		err = errors.Join(err, familyErr)
	}
	return installed, err
}

func (t *NativeTun) updateIPVSDNSFamily(
	family int,
	oldDestinations, newDestinations []ipvsDNSDestination,
	addRule, deleteRule ipvsDNSRuleOperation,
) ([]ipvsDNSDestination, error) {
	active := t.ipvsDNSBypass.serviceActive(family)
	if len(t.ipvsDNSPending) == 0 && slices.Equal(oldDestinations, newDestinations) {
		// Retry the firewall even when all policy rules are already installed.
		if t.dnatBypass != nil {
			return oldDestinations, t.dnatBypass.updateIPVSDNSOutput(family, newDestinations, active)
		}
		return oldDestinations, nil
	}
	currentDestinations := make(map[ipvsDNSDestination]struct{}, len(oldDestinations))
	for _, destination := range oldDestinations {
		currentDestinations[destination] = struct{}{}
	}
	for _, destination := range newDestinations {
		if _, installed := currentDestinations[destination]; installed && !t.ipvsDNSPending[destination] {
			continue
		}
		for i, rule := range t.ipvsDNSRules(destination) {
			if err := addRule(rule); err != nil {
				if i != 0 {
					currentDestinations[destination] = struct{}{}
					t.markIPVSDNSPending(destination)
				}
				return sortedIPVSDNSDestinations(currentDestinations), E.Cause(err, "add IPVS DNS bypass rule for ", destination.endpoint)
			}
		}
		currentDestinations[destination] = struct{}{}
		delete(t.ipvsDNSPending, destination)
	}
	// Only re-route packets after their lookup rules exist. Keep the old rules
	// until the firewall has stopped selecting those endpoints.
	if t.dnatBypass != nil {
		if err := t.dnatBypass.updateIPVSDNSOutput(family, newDestinations, active); err != nil {
			return sortedIPVSDNSDestinations(currentDestinations), E.Cause(err, "replace IPVS DNS output rules")
		}
	}
	for _, destination := range ipvsDNSDestinationDifference(oldDestinations, newDestinations) {
		rules := t.ipvsDNSRules(destination)
		for i := len(rules) - 1; i >= 0; i-- {
			if err := deleteRule(rules[i]); err != nil {
				t.markIPVSDNSPending(destination)
				return sortedIPVSDNSDestinations(currentDestinations), E.Cause(err, "delete IPVS DNS bypass rule for ", destination.endpoint)
			}
		}
		delete(t.ipvsDNSPending, destination)
		delete(currentDestinations, destination)
	}
	return sortedIPVSDNSDestinations(currentDestinations), nil
}

// A partially applied pair remains in Destinations so refresh can finish
// installing it, or remove it if the backend disappears before the retry.
func (t *NativeTun) markIPVSDNSPending(destination ipvsDNSDestination) {
	if t.ipvsDNSPending == nil {
		t.ipvsDNSPending = make(map[ipvsDNSDestination]bool)
	}
	t.ipvsDNSPending[destination] = true
}

func (t *NativeTun) ipvsDNSRules(destination ipvsDNSDestination) []*netlink.Rule {
	rule := netlink.NewRule()
	if destination.endpoint.Addr().Is4() {
		if len(t.options.Inet4Address) == 0 {
			return nil
		}
		rule.Family = unix.AF_INET
	} else {
		if len(t.options.Inet6Address) == 0 {
			return nil
		}
		rule.Family = unix.AF_INET6
	}
	rule.Priority = t.options.IPRoute2RuleIndex
	if t.dnatBypass != nil {
		rule.Priority++
	}
	rule.Dst = netip.PrefixFrom(destination.endpoint.Addr(), destination.endpoint.Addr().BitLen())
	rule.IPProto = destination.protocol
	rule.Dport = netlink.NewRulePortRange(destination.endpoint.Port(), destination.endpoint.Port())
	mark, mask := t.options.translatedDNSRoutingMark()
	rule.IifName = "lo"
	rule.Mark, rule.Mask, rule.MarkSet = mark, int(mask), true
	rule.Table = unix.RT_TABLE_MAIN
	rule.SuppressPrefixlen = 0
	fallback := *rule
	fallback.Table = t.options.IPRoute2TableIndex
	fallback.SuppressPrefixlen = -1
	return []*netlink.Rule{rule, &fallback}
}

func (o *Options) translatedDNSRoutingMark() (uint32, uint32) {
	mark, mask := o.autoRouteDNATBypassMark(), o.autoRouteDNATBypassMask()
	free := ^mask
	bit := free & -free
	return (mark ^ (mark & -mark)) | bit, mask | bit
}

func addIPVSDNSRule(rule *netlink.Rule) error {
	err := addAutoRouteRule(rule)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func deleteIPVSDNSRule(rule *netlink.Rule) error {
	err := deleteAutoRouteRule(rule)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func readIPVSSnapshot(path string) (ipvsSnapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return ipvsSnapshot{}, err
	}
	defer file.Close()
	return parseIPVSSnapshot(file)
}

func parseIPVSDNSDestinations(reader io.Reader) ([]ipvsDNSDestination, error) {
	snapshot, err := parseIPVSSnapshot(reader)
	return snapshot.destinations, err
}

func parseIPVSSnapshot(reader io.Reader) (ipvsSnapshot, error) {
	var snapshot ipvsSnapshot
	destinationSet := make(map[ipvsDNSDestination]struct{})
	var dnsProtocol int
	serviceFamily := -1
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "TCP", "UDP":
			dnsProtocol = 0
			serviceFamily = -1
			if len(fields) < 2 {
				continue
			}
			addr, port, parseErr := parseIPVSAddressPort(fields[1])
			if parseErr == nil {
				if addr.Is6() {
					serviceFamily = 1
				} else {
					serviceFamily = 0
				}
				if port == 53 {
					if fields[0] == "TCP" {
						dnsProtocol = unix.IPPROTO_TCP
					} else {
						dnsProtocol = unix.IPPROTO_UDP
					}
				}
			}
		case "->":
			if serviceFamily < 0 || len(fields) < 2 {
				continue
			}
			address, port, parseErr := parseIPVSAddressPort(fields[1])
			if parseErr == nil {
				snapshot.hasServices[serviceFamily] = true
				if dnsProtocol != 0 {
					if port == 0 {
						port = 53
					} // IPVS retains the virtual port when no backend port is set.
					destinationSet[ipvsDNSDestination{protocol: dnsProtocol, endpoint: netip.AddrPortFrom(address, port)}] = struct{}{}
				}
			}
		default:
			dnsProtocol = 0
			serviceFamily = -1
		}
	}
	if err := scanner.Err(); err != nil {
		return ipvsSnapshot{}, err
	}
	snapshot.destinations = sortedIPVSDNSDestinations(destinationSet)
	return snapshot, nil
}

func sortedIPVSDNSDestinations(destinationSet map[ipvsDNSDestination]struct{}) []ipvsDNSDestination {
	destinations := make([]ipvsDNSDestination, 0, len(destinationSet))
	for destination := range destinationSet {
		destinations = append(destinations, destination)
	}
	sort.Slice(destinations, func(i, j int) bool {
		addressCompare := destinations[i].endpoint.Addr().Compare(destinations[j].endpoint.Addr())
		if addressCompare != 0 {
			return addressCompare < 0
		}
		if destinations[i].protocol != destinations[j].protocol {
			return destinations[i].protocol < destinations[j].protocol
		}
		return destinations[i].endpoint.Port() < destinations[j].endpoint.Port()
	})
	return destinations
}

func parseIPVSAddressPort(value string) (netip.Addr, uint16, error) {
	separator := strings.LastIndexByte(value, ':')
	if separator == -1 {
		return netip.Addr{}, 0, strconv.ErrSyntax
	}
	portValue, err := strconv.ParseUint(value[separator+1:], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addressValue := strings.Trim(value[:separator], "[]")
	if len(addressValue) == 8 && !strings.ContainsRune(addressValue, ':') {
		addressBytes, decodeErr := hex.DecodeString(addressValue)
		if decodeErr != nil {
			return netip.Addr{}, 0, decodeErr
		}
		return netip.AddrFrom4([4]byte(addressBytes)), uint16(portValue), nil
	}
	address, err := netip.ParseAddr(addressValue)
	return address, uint16(portValue), err
}

func ipvsDNSDestinationDifference(destinations, excluded []ipvsDNSDestination) []ipvsDNSDestination {
	excludedSet := make(map[ipvsDNSDestination]struct{}, len(excluded))
	for _, destination := range excluded {
		excludedSet[destination] = struct{}{}
	}
	difference := make([]ipvsDNSDestination, 0, len(destinations))
	for _, destination := range destinations {
		if _, exists := excludedSet[destination]; !exists {
			difference = append(difference, destination)
		}
	}
	return difference
}
