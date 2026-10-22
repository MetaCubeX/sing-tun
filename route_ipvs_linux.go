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
	address  netip.Addr
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
	newDestinations, err := t.ipvsDNSBypass.Load()
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(err, "refresh auto-route IPVS DNS bypass"))
		}
		return
	}
	oldDestinations := t.ipvsDNSBypass.Destinations()
	if !ipvsDNSDestinationsChanged(oldDestinations, newDestinations) {
		return
	}
	updatedDestinations, err := t.updateIPVSDNSRules(oldDestinations, newDestinations, addIPVSDNSRule, deleteIPVSDNSRule)
	t.ipvsDNSBypass.Replace(updatedDestinations)
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Error(E.Cause(err, "update auto-route IPVS DNS bypass"))
		}
		return
	}
}

type ipvsDNSRuleOperation func(*netlink.Rule) error

func (t *NativeTun) updateIPVSDNSRules(
	oldDestinations, newDestinations []ipvsDNSDestination,
	addRule, deleteRule ipvsDNSRuleOperation,
) ([]ipvsDNSDestination, error) {
	currentDestinations := make(map[ipvsDNSDestination]struct{}, len(oldDestinations))
	for _, destination := range oldDestinations {
		currentDestinations[destination] = struct{}{}
	}
	for _, destination := range ipvsDNSDestinationDifference(newDestinations, oldDestinations) {
		rule := t.ipvsDNSRule(destination)
		if rule != nil {
			if err := addRule(rule); err != nil {
				return sortedIPVSDNSDestinations(currentDestinations), E.Cause(err, "add IPVS DNS bypass rule for ", destination.address)
			}
		}
		currentDestinations[destination] = struct{}{}
	}
	for _, destination := range ipvsDNSDestinationDifference(oldDestinations, newDestinations) {
		rule := t.ipvsDNSRule(destination)
		if rule != nil {
			if err := deleteRule(rule); err != nil {
				return sortedIPVSDNSDestinations(currentDestinations), E.Cause(err, "delete IPVS DNS bypass rule for ", destination.address)
			}
		}
		delete(currentDestinations, destination)
	}
	return sortedIPVSDNSDestinations(currentDestinations), nil
}

func (t *NativeTun) ipvsDNSRule(destination ipvsDNSDestination) *netlink.Rule {
	rule := netlink.NewRule()
	if destination.address.Is4() {
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
	rule.Dst = netip.PrefixFrom(destination.address, destination.address.BitLen())
	rule.IPProto = destination.protocol
	rule.Dport = netlink.NewRulePortRange(53, 53)
	rule.Goto = t.options.IPRoute2RuleIndex + 10
	return rule
}

func addIPVSDNSRule(rule *netlink.Rule) error {
	err := netlink.RuleAdd(rule)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func deleteIPVSDNSRule(rule *netlink.Rule) error {
	err := netlink.RuleDel(rule)
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
			if parseErr == nil && port == 53 {
				destinationSet[ipvsDNSDestination{protocol: dnsProtocol, address: address}] = struct{}{}
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
		addressCompare := destinations[i].address.Compare(destinations[j].address)
		if addressCompare == 0 {
			return destinations[i].protocol < destinations[j].protocol
		}
		return addressCompare < 0
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

func ipvsDNSDestinationsChanged(oldDestinations, newDestinations []ipvsDNSDestination) bool {
	if len(oldDestinations) != len(newDestinations) {
		return true
	}
	for index := range oldDestinations {
		if oldDestinations[index] != newDestinations[index] {
			return true
		}
	}
	return false
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
