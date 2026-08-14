//go:build linux

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/binaryutil"
	"github.com/metacubex/nftables/expr"
	"github.com/metacubex/sing/common/logger"
	"github.com/stretchr/testify/require"
)

type warningRecorder struct {
	logger.Logger
	warnings []string
}

func (r *warningRecorder) Warn(args ...any) {
	r.warnings = append(r.warnings, fmt.Sprint(args...))
}

func TestAutoRouteDNATBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		dnatBypass: &autoRouteDNATBypass{},
		options: Options{
			AutoRoute:              true,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2RuleIndex:      DefaultIPRoute2RuleIndex,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet4RouteAddress:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
	}

	rules := nativeTun.rules()
	require.NotEmpty(t, rules)
	require.Equal(t, DefaultIPRoute2RuleIndex, rules[0].Priority)
	require.True(t, rules[0].MarkSet)
	require.Equal(t, uint32(DefaultAutoRedirectOutputMark), rules[0].Mark)
	require.Equal(t, DefaultIPRoute2RuleIndex+10, rules[0].Goto)
}

func TestAutoRouteWithoutDNATBypassRule(t *testing.T) {
	nativeTun := &NativeTun{
		options: Options{
			AutoRoute:              true,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2RuleIndex:      DefaultIPRoute2RuleIndex,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet4RouteAddress:      []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		},
	}

	for _, rule := range nativeTun.rules() {
		require.False(t,
			rule.MarkSet &&
				rule.Mark == DefaultAutoRedirectOutputMark &&
				rule.Goto == DefaultIPRoute2RuleIndex+10,
			"DNAT bypass rule must not be installed without an active firewall backend",
		)
	}
}

func TestEnableAutoRouteDNATBypassDegradesOnUnavailableBackend(t *testing.T) {
	testLogger := &warningRecorder{Logger: logger.NOP()}
	nativeTun := &NativeTun{
		options: Options{Logger: testLogger},
	}

	nativeTun.enableAutoRouteDNATBypass(func(*Options) (*autoRouteDNATBypass, error) {
		return nil, errors.New("no firewall backend")
	})

	require.Nil(t, nativeTun.dnatBypass)
	require.Len(t, testLogger.warnings, 1)
	require.True(t, strings.Contains(testLogger.warnings[0], "continuing without Docker DNAT protection"))
}

func TestDNATMarkExpressions(t *testing.T) {
	options := &Options{AutoRedirectOutputMark: DefaultAutoRedirectOutputMark}
	expressions := dnatMarkExpressions(options)
	require.Len(t, expressions, 6)

	status, loaded := expressions[0].(*expr.Ct)
	require.True(t, loaded)
	require.Equal(t, expr.CtKeySTATUS, status.Key)

	mark, loaded := expressions[3].(*expr.Immediate)
	require.True(t, loaded)
	require.Equal(t, binaryutil.NativeEndian.PutUint32(DefaultAutoRedirectOutputMark), mark.Data)

	meta, loaded := expressions[4].(*expr.Meta)
	require.True(t, loaded)
	require.Equal(t, expr.MetaKeyMARK, meta.Key)
	require.True(t, meta.SourceRegister)
}

func TestDNATMarkExpressionsExcludeAutoRedirectInputMark(t *testing.T) {
	options := &Options{
		AutoRedirectMarkMode:  true,
		AutoRedirectInputMark: DefaultAutoRedirectInputMark,
	}
	expressions := dnatMarkExpressions(options)
	require.Len(t, expressions, 8)
	mark, loaded := expressions[3].(*expr.Meta)
	require.True(t, loaded)
	require.Equal(t, expr.MetaKeyMARK, mark.Key)
	compare, loaded := expressions[4].(*expr.Cmp)
	require.True(t, loaded)
	require.Equal(t, expr.CmpOpNeq, compare.Op)
}

func TestAutoRouteDNATBypassUsesDefaultMark(t *testing.T) {
	options := Options{}
	require.Equal(t, uint32(DefaultAutoRedirectOutputMark), options.autoRouteDNATBypassMark())
}

func TestAutoRedirectDisablesNFTables(t *testing.T) {
	options := &Options{}
	redirect, err := NewAutoRedirect(AutoRedirectOptions{
		TunOptions:      options,
		DisableNFTables: true,
	})
	require.NoError(t, err)
	require.False(t, redirect.(*autoRedirect).useNFTables)
}

func TestEnsureSrcValidMarkWithStrictRPFilter(t *testing.T) {
	confPath := createIPv4Conf(t, "1", "0", "0")
	testLogger := &warningRecorder{Logger: logger.NOP()}

	state, err := enableSrcValidMark(confPath, testLogger)
	require.NoError(t, err)
	require.NotNil(t, state)
	value, err := os.ReadFile(confPath + "/all/src_valid_mark")
	require.NoError(t, err)
	require.Equal(t, "1", string(value))
	require.Len(t, testLogger.warnings, 1)
	require.True(t, strings.Contains(testLogger.warnings[0], "will restore it on close"))

	require.NoError(t, state.Close())
	value, err = os.ReadFile(confPath + "/all/src_valid_mark")
	require.NoError(t, err)
	require.Equal(t, "0", string(value))
}

func TestEnsureSrcValidMarkSkipsNonStrictRPFilter(t *testing.T) {
	confPath := createIPv4Conf(t, "0", "0", "2")
	require.NoError(t, os.Remove(confPath+"/all/src_valid_mark"))

	state, err := enableSrcValidMark(confPath, logger.NOP())
	require.NoError(t, err)
	require.Nil(t, state)
	_, err = os.Stat(confPath + "/all/src_valid_mark")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestEnsureSrcValidMarkPreservesEnabledValue(t *testing.T) {
	confPath := createIPv4Conf(t, "1", "0", "0")
	require.NoError(t, os.WriteFile(confPath+"/all/src_valid_mark", []byte("1"), 0o600))

	state, err := enableSrcValidMark(confPath, logger.NOP())
	require.NoError(t, err)
	require.Nil(t, state)
	value, err := os.ReadFile(confPath + "/all/src_valid_mark")
	require.NoError(t, err)
	require.Equal(t, "1", string(value))
}

func TestEnsureSrcValidMarkAllowsConcurrentBypass(t *testing.T) {
	confPath := createIPv4Conf(t, "1", "0", "0")

	firstState, err := enableSrcValidMark(confPath, logger.NOP())
	require.NoError(t, err)
	require.NotNil(t, firstState)

	secondState, err := enableSrcValidMark(confPath, logger.NOP())
	require.NoError(t, err)
	require.Nil(t, secondState)

	require.NoError(t, firstState.Close())
	value, err := os.ReadFile(confPath + "/all/src_valid_mark")
	require.NoError(t, err)
	require.Equal(t, "0", string(value))
}

func createIPv4Conf(t *testing.T, allRPFilter string, defaultRPFilter string, interfaceRPFilter string) string {
	t.Helper()
	confPath := t.TempDir()
	for name, rpFilter := range map[string]string{
		"all":     allRPFilter,
		"default": defaultRPFilter,
		"eth0":    interfaceRPFilter,
	} {
		path := confPath + "/" + name
		require.NoError(t, os.MkdirAll(path, 0o700))
		require.NoError(t, os.WriteFile(path+"/rp_filter", []byte(rpFilter), 0o600))
	}
	require.NoError(t, os.WriteFile(confPath+"/all/src_valid_mark", []byte("0"), 0o600))
	return confPath
}

func TestHasStrictRPFilter(t *testing.T) {
	for name, testCase := range map[string]struct {
		all       string
		defaultIf string
		eth0      string
		expected  bool
	}{
		"interface strict": {all: "0", defaultIf: "0", eth0: "1", expected: true},
		"default strict":   {all: "0", defaultIf: "1", eth0: "0", expected: true},
		"all strict":       {all: "1", defaultIf: "0", eth0: "0", expected: true},
		"all loose":        {all: "2", defaultIf: "0", eth0: "0", expected: false},
		"interfaces loose": {all: "1", defaultIf: "2", eth0: "2", expected: false},
	} {
		t.Run(name, func(t *testing.T) {
			confPath := createIPv4Conf(t, testCase.all, testCase.defaultIf, testCase.eth0)
			strict, err := hasStrictRPFilter(confPath)
			require.NoError(t, err)
			require.Equal(t, testCase.expected, strict)
		})
	}
}

func TestAutoRouteDNATBypassNFTables(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a Linux network namespace with CAP_NET_ADMIN")
	}
	bypass := &autoRouteDNATBypass{
		options: &Options{
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2TableIndex:     DefaultIPRoute2TableIndex,
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		},
		tableName:   "sing-tun-route-test",
		useNFTables: true,
	}
	originalSrcValidMark, err := os.ReadFile(srcValidMarkPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.WriteFile(srcValidMarkPath, originalSrcValidMark, 0) })
	strictRPFilter, err := hasStrictRPFilter(ipv4ConfPath)
	require.NoError(t, err)
	require.NoError(t, bypass.Start())
	currentSrcValidMark, err := os.ReadFile(srcValidMarkPath)
	require.NoError(t, err)
	if strictRPFilter {
		require.Equal(t, "1", string(bytes.TrimSpace(currentSrcValidMark)))
	} else {
		require.Equal(t, string(bytes.TrimSpace(originalSrcValidMark)), string(bytes.TrimSpace(currentSrcValidMark)))
	}
	require.NoError(t, bypass.Close())
	afterCloseSrcValidMark, err := os.ReadFile(srcValidMarkPath)
	require.NoError(t, err)
	require.Equal(t, string(bytes.TrimSpace(originalSrcValidMark)), string(bytes.TrimSpace(afterCloseSrcValidMark)))

	nft, err := nftables.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = nft.CloseLasting() })
	_, err = nft.ListTableOfFamily(bypass.tableName, nftables.TableFamilyINet)
	require.Error(t, err)
}

func TestAutoRouteDNATBypassIPTables(t *testing.T) {
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires a Linux network namespace with CAP_NET_ADMIN")
	}
	iptablesPath, err := exec.LookPath("iptables")
	if err != nil {
		t.Skip("iptables is unavailable")
	}
	bypass := &autoRouteDNATBypass{
		options: &Options{
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			IPRoute2TableIndex:     DefaultIPRoute2TableIndex,
		},
		chainName:    "STUN-DNAT-TEST",
		iptablesPath: iptablesPath,
	}
	require.NoError(t, bypass.Start())
	require.NoError(t, bypass.Close())

	output, err := exec.Command(iptablesPath, "-t", "mangle", "-S", bypass.chainName).CombinedOutput()
	require.Error(t, err, string(output))
}
