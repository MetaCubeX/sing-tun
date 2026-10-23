package tun

import (
	"net/netip"
	"sync"

	"github.com/metacubex/sing-tun/internal/winipcfg"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	"github.com/metacubex/sing/common/x/list"

	"golang.org/x/sys/windows"
)

// zeroTierFakeGatewayIp from
// https://github.com/zerotier/ZeroTierOne/blob/1.8.6/osdep/WindowsEthernetTap.cpp#L994
var zeroTierFakeGatewayIp = netip.MustParseAddr("25.255.255.254")

type defaultRouteCandidate struct {
	index  int
	alias  string
	metric uint32
}

func selectDefaultRouteCandidate(candidates []defaultRouteCandidate, previousIndex int) (defaultRouteCandidate, bool) {
	if len(candidates) == 0 {
		return defaultRouteCandidate{}, false
	}

	best := candidates[0]
	bestIsPrevious := best.index == previousIndex

	for _, candidate := range candidates[1:] {
		switch {
		case candidate.metric < best.metric:
			best = candidate
			bestIsPrevious = candidate.index == previousIndex
		case candidate.metric == best.metric && !bestIsPrevious && candidate.index == previousIndex:
			best = candidate
			bestIsPrevious = true
		}
	}

	return best, true
}

type networkUpdateMonitor struct {
	routeListener     *winipcfg.RouteChangeCallback
	interfaceListener *winipcfg.InterfaceChangeCallback
	errorHandler      E.Handler

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	return &networkUpdateMonitor{
		logger: logger,
	}, nil
}

func (m *networkUpdateMonitor) Start() error {
	routeListener, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		m.emit()
	})
	if err != nil {
		return err
	}
	m.routeListener = routeListener
	interfaceListener, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		m.emit()
	})
	if err != nil {
		routeListener.Unregister()
		return err
	}
	m.interfaceListener = interfaceListener
	return nil
}

func (m *networkUpdateMonitor) Close() error {
	if m.routeListener != nil {
		m.routeListener.Unregister()
		m.routeListener = nil
	}
	if m.interfaceListener != nil {
		m.interfaceListener.Unregister()
		m.interfaceListener = nil
	}
	return nil
}

func (m *defaultInterfaceMonitor) checkUpdate() error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}

	previousIndex := 0
	if oldInterface := m.defaultInterface.Load(); oldInterface != nil {
		previousIndex = oldInterface.Index
	}

	candidatesByIndex := map[int]defaultRouteCandidate{}

	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}

		if row.NextHop.Addr() == zeroTierFakeGatewayIp {
			continue
		}

		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		if ifrow.Type == winipcfg.IfTypePropVirtual || ifrow.Type == winipcfg.IfTypeSoftwareLoopback {
			continue
		}

		iface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}

		if !iface.Connected {
			continue
		}

		metric := row.Metric + iface.Metric

		candidate := defaultRouteCandidate{
			index:  int(ifrow.InterfaceIndex),
			alias:  ifrow.Alias(),
			metric: metric,
		}
		if existing, ok := candidatesByIndex[candidate.index]; !ok || candidate.metric < existing.metric {
			candidatesByIndex[candidate.index] = candidate
		}
	}

	candidates := make([]defaultRouteCandidate, 0, len(candidatesByIndex))
	for _, candidate := range candidatesByIndex {
		candidates = append(candidates, candidate)
	}

	selected, ok := selectDefaultRouteCandidate(candidates, previousIndex)
	if !ok {
		return ErrNoRoute
	}

	newInterface, err := m.interfaceFinder.ByIndex(selected.index)
	if err != nil {
		return E.Cause(err, "find updated interface: ", selected.alias)
	}
	oldInterface := m.defaultInterface.Swap(newInterface)
	if oldInterface != nil && oldInterface.Equals(*newInterface) {
		return nil
	}
	m.emit(newInterface, 0)
	return nil
}
