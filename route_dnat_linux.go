//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
)

const conntrackStatusDNAT = 1 << 5

const (
	ipv4ConfPath     = "/proc/sys/net/ipv4/conf"
	srcValidMarkPath = ipv4ConfPath + "/all/src_valid_mark"
)

type autoRouteDNATBypass struct {
	options       *Options
	tableName     string
	chainName     string
	useNFTables   bool
	iptablesPath  string
	ip6tablesPath string
	srcValidMark  *srcValidMarkState
}

type srcValidMarkState struct {
	path string
}

func (t *NativeTun) enableAutoRouteDNATBypass(
	prepare func(*Options) (*autoRouteDNATBypass, error),
) {
	bypass, err := prepare(&t.options)
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Warn(E.Cause(
				err,
				"auto-route DNAT bypass unavailable; continuing without Docker DNAT protection",
			))
		}
		return
	}
	t.dnatBypass = bypass
}

func prepareAutoRouteDNATBypass(options *Options) (*autoRouteDNATBypass, error) {
	bypass, err := newAutoRouteDNATBypass(options)
	if err != nil {
		return nil, E.Cause(err, "initialize auto-route DNAT bypass")
	}
	err = bypass.Start()
	if err != nil {
		return nil, E.Cause(err, "start auto-route DNAT bypass")
	}
	return bypass, nil
}

func newAutoRouteDNATBypass(options *Options) (*autoRouteDNATBypass, error) {
	bypass := &autoRouteDNATBypass{
		options:   options,
		tableName: "sing-tun-route-" + strconv.Itoa(options.IPRoute2TableIndex),
		chainName: "STUN-DNAT-" + strconv.Itoa(options.IPRoute2TableIndex),
	}
	var err error
	nft, nftErr := nftables.New()
	if nftErr == nil {
		_, nftErr = nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
		_ = nft.CloseLasting()
	}
	if nftErr == nil {
		bypass.useNFTables = true
		return bypass, nil
	}
	if len(options.Inet4Address) > 0 {
		bypass.iptablesPath, err = exec.LookPath("iptables")
		if err != nil {
			return nil, E.Cause(err, "iptables is required for auto-route DNAT bypass")
		}
	}
	if len(options.Inet6Address) > 0 {
		bypass.ip6tablesPath, err = exec.LookPath("ip6tables")
		if err != nil {
			return nil, E.Cause(err, "ip6tables is required for auto-route DNAT bypass")
		}
	}
	return bypass, nil
}

func (o *Options) autoRouteDNATBypassMark() uint32 {
	if o.AutoRedirectOutputMark != 0 {
		return o.AutoRedirectOutputMark
	}
	return DefaultAutoRedirectOutputMark
}

func (b *autoRouteDNATBypass) Start() error {
	var err error
	if len(b.options.Inet4Address) > 0 {
		b.srcValidMark, err = enableSrcValidMark(ipv4ConfPath, b.options.Logger)
		if err != nil {
			return E.Cause(err, "enable src_valid_mark for auto-route DNAT bypass")
		}
	}
	if b.useNFTables {
		b.cleanupNFTables()
		err = b.setupNFTables()
	} else {
		b.cleanupIPTables()
		err = b.setupIPTables()
	}
	if err != nil {
		return E.Errors(err, b.Close())
	}
	return nil
}

func (b *autoRouteDNATBypass) Close() error {
	if b.useNFTables {
		b.cleanupNFTables()
	} else {
		b.cleanupIPTables()
	}
	if b.srcValidMark == nil {
		return nil
	}
	err := b.srcValidMark.Close()
	b.srcValidMark = nil
	return err
}

func enableSrcValidMark(confPath string, log logger.Logger) (*srcValidMarkState, error) {
	strictRPFilter, err := hasStrictRPFilter(confPath)
	if err != nil {
		return nil, err
	}
	if !strictRPFilter {
		return nil, nil
	}
	path := filepath.Join(confPath, "all", "src_valid_mark")
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value = bytes.TrimSpace(value)
	if bytes.Equal(value, []byte("1")) {
		return nil, nil
	}
	if !bytes.Equal(value, []byte("0")) {
		return nil, E.New("invalid src_valid_mark value: ", string(value))
	}
	err = os.WriteFile(path, []byte("1"), 0)
	if err != nil {
		return nil, err
	}
	if log != nil {
		log.Warn("changed net.ipv4.conf.all.src_valid_mark from 0 to 1 for auto-route DNAT bypass; will restore it on close")
	}
	return &srcValidMarkState{
		path: path,
	}, nil
}

func (s *srcValidMarkState) Close() error {
	if s == nil || s.path == "" {
		return nil
	}
	path := s.path
	s.path = ""
	value, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(value), []byte("1")) {
		return nil
	}
	return os.WriteFile(path, []byte("0"), 0)
}

func hasStrictRPFilter(confPath string) (bool, error) {
	allValue, err := readRPFilter(filepath.Join(confPath, "all", "rp_filter"))
	if err != nil {
		return false, err
	}
	entries, err := os.ReadDir(confPath)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "all" {
			continue
		}
		value, readErr := readRPFilter(filepath.Join(confPath, entry.Name(), "rp_filter"))
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return false, readErr
		}
		effectiveValue := allValue
		if value > effectiveValue {
			effectiveValue = value
		}
		if effectiveValue == 1 {
			return true, nil
		}
	}
	return false, nil
}

func readRPFilter(path string) (int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(string(bytes.TrimSpace(content)))
	if err != nil {
		return 0, err
	}
	if value < 0 || value > 2 {
		return 0, E.New("invalid rp_filter value: ", value)
	}
	return value, nil
}

func (b *autoRouteDNATBypass) setupNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	table := nft.AddTable(&nftables.Table{
		Name:   b.tableName,
		Family: nftables.TableFamilyINet,
	})
	chain := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 2),
		Type:     nftables.ChainTypeFilter,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: dnatMarkExpressions(b.options),
	})
	return nft.Flush()
}

func (b *autoRouteDNATBypass) cleanupNFTables() {
	nft, err := nftables.New()
	if err != nil {
		return
	}
	nft.DelTable(&nftables.Table{
		Name:   b.tableName,
		Family: nftables.TableFamilyINet,
	})
	_ = nft.Flush()
	_ = nft.CloseLasting()
}

func dnatMarkExpressions(options *Options) []expr.Any {
	expressions := nftablesDNATStatusExpressions()
	if options.AutoRedirectMarkMode {
		expressions = append(expressions,
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(options.AutoRedirectInputMark),
			},
		)
	}
	return append(expressions,
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(options.autoRouteDNATBypassMark()),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			Register:       1,
			SourceRegister: true,
		},
		&expr.Counter{},
	)
}

func (b *autoRouteDNATBypass) setupIPTables() error {
	for _, path := range []string{b.iptablesPath, b.ip6tablesPath} {
		if path == "" {
			continue
		}
		if err := b.runIPTables(path, "-t", "mangle", "-N", b.chainName); err != nil {
			return err
		}
		if err := b.runIPTables(
			path, "-t", "mangle", "-A", b.chainName,
			"-m", "addrtype", "--dst-type", "LOCAL",
			"-j", "MARK", "--set-mark", strconv.FormatUint(uint64(b.options.autoRouteDNATBypassMark()), 10),
		); err != nil {
			return err
		}
		if err := b.runIPTables(
			path, "-t", "mangle", "-A", b.chainName,
			"-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "REPLY",
			"-j", "MARK", "--set-mark", strconv.FormatUint(uint64(b.options.autoRouteDNATBypassMark()), 10),
		); err != nil {
			return err
		}
		if err := b.runIPTables(path, "-t", "mangle", "-I", "PREROUTING", "-j", b.chainName); err != nil {
			return err
		}
	}
	return nil
}

func (b *autoRouteDNATBypass) cleanupIPTables() {
	for _, path := range []string{b.iptablesPath, b.ip6tablesPath} {
		if path == "" {
			continue
		}
		_ = b.runIPTables(path, "-t", "mangle", "-D", "PREROUTING", "-j", b.chainName)
		_ = b.runIPTables(path, "-t", "mangle", "-F", b.chainName)
		_ = b.runIPTables(path, "-t", "mangle", "-X", b.chainName)
	}
}

func (b *autoRouteDNATBypass) runIPTables(path string, args ...string) error {
	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return E.Extend(err, fmt.Sprintf("%s %v: %s", path, args, output))
	}
	return nil
}

func nftablesDNATStatusExpressions() []expr.Any {
	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATUS,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(conntrackStatusDNAT),
			Xor:            make([]byte, 4),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(conntrackStatusDNAT),
		},
	}
}
