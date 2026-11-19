//go:build linux

package tun

import (
	"strconv"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	"golang.org/x/sys/unix"
)

func addAutoRouteRule(rule *netlink.Rule) error {
	if needsWideMarkRule(rule) {
		return writeWideMarkRule(rule, unix.RTM_NEWRULE)
	}
	return netlink.RuleAdd(rule)
}

func deleteAutoRouteRule(rule *netlink.Rule) error {
	if needsWideMarkRule(rule) {
		return writeWideMarkRule(rule, unix.RTM_DELRULE)
	}
	return netlink.RuleDel(rule)
}

func needsWideMarkRule(rule *netlink.Rule) bool {
	return strconv.IntSize == 32 && rule.MarkSet && (rule.Mask < -1 || rule.Mask == -1 && (rule.Src.IsValid() || rule.Dst.IsValid()) && rule.IifName != "")
}

// The pinned netlink library represents Mask as int and omits negative masks.
func writeWideMarkRule(rule *netlink.Rule, command int) error {
	flags := unix.NLM_F_ACK
	if command == unix.RTM_NEWRULE {
		flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	req := nl.NewNetlinkRequest(command, flags)
	msg := nl.NewRtMsg()
	msg.Family = uint8(rule.Family)
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = unix.FR_ACT_TO_TBL
	if rule.Type == unix.FR_ACT_UNREACHABLE {
		msg.Type = unix.FR_ACT_UNREACHABLE
	} else if rule.Goto >= 0 {
		msg.Type = unix.FR_ACT_GOTO
	}
	if rule.Src.IsValid() {
		msg.Src_len = uint8(rule.Src.Bits())
	}
	if rule.Dst.IsValid() {
		msg.Dst_len = uint8(rule.Dst.Bits())
	}
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(uint32(rule.Priority))))
	req.AddData(nl.NewRtAttr(nl.FRA_FWMARK, nl.Uint32Attr(rule.Mark)))
	req.AddData(nl.NewRtAttr(nl.FRA_FWMASK, nl.Uint32Attr(uint32(rule.Mask))))
	if rule.Goto >= 0 {
		req.AddData(nl.NewRtAttr(nl.FRA_GOTO, nl.Uint32Attr(uint32(rule.Goto))))
	} else if rule.Type != unix.FR_ACT_UNREACHABLE {
		req.AddData(nl.NewRtAttr(nl.FRA_TABLE, nl.Uint32Attr(uint32(rule.Table))))
		if rule.SuppressPrefixlen >= 0 {
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_PREFIXLEN, nl.Uint32Attr(uint32(rule.SuppressPrefixlen))))
		}
	}
	if rule.IPProto > 0 {
		req.AddData(nl.NewRtAttr(nl.FRA_IP_PROTO, []byte{byte(rule.IPProto)}))
	}
	if rule.Dport != nil {
		ports := append(nl.Uint16Attr(rule.Dport.Start), nl.Uint16Attr(rule.Dport.End)...)
		req.AddData(nl.NewRtAttr(nl.FRA_DPORT_RANGE, ports))
	}
	if rule.Sport != nil {
		ports := append(nl.Uint16Attr(rule.Sport.Start), nl.Uint16Attr(rule.Sport.End)...)
		req.AddData(nl.NewRtAttr(nl.FRA_SPORT_RANGE, ports))
	}
	if rule.Src.IsValid() {
		req.AddData(nl.NewRtAttr(unix.RTA_SRC, rule.Src.Addr().AsSlice()))
	}
	if rule.Dst.IsValid() {
		req.AddData(nl.NewRtAttr(unix.RTA_DST, rule.Dst.Addr().AsSlice()))
	}
	if rule.IifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_IIFNAME, nl.ZeroTerminated(rule.IifName)))
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}
