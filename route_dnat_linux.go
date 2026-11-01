//go:build linux

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
)

const (
	conntrackStatusDNAT = 1 << 5
	// Reserve the low 12 bits for the bypass mark and preserve marks owned by other network components.
	autoRouteDNATBypassMarkFieldMask = 0xFFF
)

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
	outputMark := o.AutoRedirectOutputMark
	if outputMark == 0 {
		outputMark = DefaultAutoRedirectOutputMark
	}
	return outputMark & o.autoRouteDNATBypassMask()
}

func (o *Options) autoRouteDNATBypassMask() uint32 {
	outputMark := o.AutoRedirectOutputMark
	if outputMark == 0 {
		outputMark = DefaultAutoRedirectOutputMark
	}
	mask := uint32(autoRouteDNATBypassMarkFieldMask)
	if outputMark&mask == 0 {
		mask = outputMark
	}
	if o.AutoRedirectMarkMode {
		difference := o.AutoRedirectInputMark ^ outputMark
		if difference&mask == 0 {
			// Add one distinguishing bit without touching the other mark fields.
			mask |= difference & -difference
		}
	}
	return mask
}

func (b *autoRouteDNATBypass) Start() error {
	var err error
	if len(b.options.Inet4Address) > 0 {
		err = enableSrcValidMark(ipv4ConfPath, b.options.Logger)
		if err != nil {
			return E.Cause(err, "enable src_valid_mark for auto-route DNAT bypass")
		}
	}
	// Remove stale rules from an interrupted instance before reusing this table.
	if err = b.Close(); err != nil {
		return err
	}
	if b.useNFTables {
		err = b.setupNFTables()
	} else {
		err = b.setupIPTables()
	}
	if err != nil {
		return E.Errors(err, b.Close())
	}
	return nil
}

func (b *autoRouteDNATBypass) Close() error {
	if b.useNFTables {
		return b.cleanupNFTables()
	}
	return b.cleanupIPTables()
}

func enableSrcValidMark(confPath string, log logger.Logger) error {
	strictRPFilter, err := hasStrictRPFilter(confPath)
	if err != nil {
		return err
	}
	if !strictRPFilter {
		return nil
	}
	path := filepath.Join(confPath, "all", "src_valid_mark")
	value, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	value = bytes.TrimSpace(value)
	if bytes.Equal(value, []byte("1")) {
		return nil
	}
	if !bytes.Equal(value, []byte("0")) {
		return E.New("invalid src_valid_mark value: ", string(value))
	}
	err = os.WriteFile(path, []byte("1"), 0)
	if err != nil {
		return err
	}
	if log != nil {
		log.Warn("changed net.ipv4.conf.all.src_valid_mark from 0 to 1 for auto-route DNAT bypass; will remain enabled after close")
	}
	return nil
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

func (b *autoRouteDNATBypass) cleanupNFTables() error {
	return deleteRouteNFTTable(nftables.TableFamilyINet, b.tableName)
}

func deleteRouteNFTTable(family nftables.TableFamily, name string) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	nft.DelTable(&nftables.Table{Name: name, Family: family})
	err = nft.Flush()
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func dnatMarkExpressions(options *Options) []expr.Any {
	expressions := nftablesDNATStatusExpressions()
	markMask := options.autoRouteDNATBypassMask()
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
		&expr.Meta{
			Key:      expr.MetaKeyMARK,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^markMask),
			Xor:            binaryutil.NativeEndian.PutUint32(options.autoRouteDNATBypassMark()),
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
	markMask := b.options.autoRouteDNATBypassMask()
	for _, path := range []string{b.iptablesPath, b.ip6tablesPath} {
		if path == "" {
			continue
		}
		if err := runIPTables(path, "-t", "mangle", "-N", b.chainName); err != nil {
			return err
		}
		if err := runIPTables(
			path, "-t", "mangle", "-A", b.chainName,
			"-m", "addrtype", "--dst-type", "LOCAL",
			"-j", "MARK", "--set-xmark", fmt.Sprintf("%#x/%#x", b.options.autoRouteDNATBypassMark(), markMask),
		); err != nil {
			return err
		}
		if err := runIPTables(
			path, "-t", "mangle", "-A", b.chainName,
			"-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "REPLY",
			"-j", "MARK", "--set-xmark", fmt.Sprintf("%#x/%#x", b.options.autoRouteDNATBypassMark(), markMask),
		); err != nil {
			return err
		}
		if err := runIPTables(path, "-t", "mangle", "-I", "PREROUTING", "-j", b.chainName); err != nil {
			return err
		}
	}
	return nil
}

func (b *autoRouteDNATBypass) cleanupIPTables() error {
	var errs []error
	for _, path := range []string{b.iptablesPath, b.ip6tablesPath} {
		if path != "" {
			errs = append(errs, cleanupIPTablesChain(path, "mangle", "PREROUTING", b.chainName))
		}
	}
	return errors.Join(errs...)
}

func cleanupIPTablesChain(path, table, hook, chain string) error {
	list, err := outputIPTables(path, "-t", table, "-S")
	if err != nil {
		return err
	}
	chainExists := false
	for _, line := range strings.Split(string(list), "\n") {
		switch line {
		case "-N " + chain:
			chainExists = true
		case "-A " + hook + " -j " + chain:
			if err := runIPTables(path, "-t", table, "-D", hook, "-j", chain); err != nil {
				return err
			}
		}
	}
	if !chainExists {
		return nil
	}
	if err := runIPTables(path, "-t", table, "-F", chain); err != nil {
		return err
	}
	return runIPTables(path, "-t", table, "-X", chain)
}

func outputIPTables(path string, args ...string) ([]byte, error) {
	output, err := exec.Command(path, append([]string{"-w", "5"}, args...)...).CombinedOutput()
	if err != nil {
		return nil, E.Extend(err, fmt.Sprintf("%s %v: %s", path, args, output))
	}
	return output, nil
}

func runIPTables(path string, args ...string) error {
	_, err := outputIPTables(path, args...)
	return err
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
