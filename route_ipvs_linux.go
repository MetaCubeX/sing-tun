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
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"
)

const (
	ipvsTablePath          = "/proc/net/ip_vs"
	ipvsDNSRefreshInterval = 5 * time.Second
)

type autoRouteIPVSDNSBypass struct {
	path string

	access       sync.RWMutex
	destinations []ipvsDNSDestination
	started      bool
	closeOnce    sync.Once
	stop         chan struct{}
	done         chan struct{}
}

type ipvsDNSDestination struct {
	protocol int
	endpoint netip.AddrPort
}

func newAutoRouteIPVSDNSBypass(path string) (*autoRouteIPVSDNSBypass, error) {
	bypass := &autoRouteIPVSDNSBypass{
		path: path,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	destinations, err := bypass.Load()
	if err != nil {
		return nil, err
	}
	bypass.destinations = destinations
	return bypass, nil
}

func (b *autoRouteIPVSDNSBypass) Start(update func()) {
	b.access.Lock()
	if b.started {
		b.access.Unlock()
		return
	}
	b.started = true
	b.access.Unlock()
	go func() {
		defer close(b.done)
		ticker := time.NewTicker(ipvsDNSRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				update()
			case <-b.stop:
				return
			}
		}
	}()
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
	destinations, err := readIPVSDNSDestinations(b.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return destinations, err
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

func (t *NativeTun) enableAutoRouteIPVSDNSBypass(path string) {
	bypass, err := newAutoRouteIPVSDNSBypass(path)
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(err, "auto-route IPVS DNS bypass unavailable; continuing without IPVS DNS protection"))
		}
		return
	}
	t.ipvsDNSBypass = bypass
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
	newDestinations, err := t.ipvsDNSBypass.Load()
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(err, "refresh auto-route IPVS DNS bypass"))
		}
		return
	}
	oldDestinations := t.ipvsDNSBypass.Destinations()
	installed, err := t.updateIPVSDNSRules(oldDestinations, newDestinations, addIPVSDNSRule, deleteIPVSDNSRule)
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
	if len(t.ipvsDNSPending) == 0 && slices.Equal(oldDestinations, newDestinations) {
		// Retry the firewall even when all policy rules are already installed.
		if t.dnatBypass != nil {
			return oldDestinations, t.dnatBypass.updateIPVSDNSOutput(family, newDestinations)
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
		if err := t.dnatBypass.updateIPVSDNSOutput(family, newDestinations); err != nil {
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

func readIPVSDNSDestinations(path string) ([]ipvsDNSDestination, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseIPVSDNSDestinations(file)
}

func parseIPVSDNSDestinations(reader io.Reader) ([]ipvsDNSDestination, error) {
	destinationSet := make(map[ipvsDNSDestination]struct{})
	var dnsProtocol int
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "TCP", "UDP":
			dnsProtocol = 0
			if len(fields) < 2 {
				continue
			}
			_, port, parseErr := parseIPVSAddressPort(fields[1])
			if parseErr == nil && port == 53 {
				if fields[0] == "TCP" {
					dnsProtocol = unix.IPPROTO_TCP
				} else {
					dnsProtocol = unix.IPPROTO_UDP
				}
			}
		case "->":
			if dnsProtocol == 0 || len(fields) < 2 {
				continue
			}
			address, port, parseErr := parseIPVSAddressPort(fields[1])
			if parseErr == nil {
				if port == 0 {
					port = 53
				} // IPVS retains the virtual port when no backend port is set.
				destinationSet[ipvsDNSDestination{protocol: dnsProtocol, endpoint: netip.AddrPortFrom(address, port)}] = struct{}{}
			}
		default:
			dnsProtocol = 0
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sortedIPVSDNSDestinations(destinationSet), nil
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
