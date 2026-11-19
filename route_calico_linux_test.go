//go:build linux

package tun

import (
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func runCalicoIntegration(t *testing.T, test func()) {
	t.Helper()
	if os.Getenv("SING_TUN_INTEGRATION") != "1" {
		t.Skip("requires privileged Linux network and mount namespaces")
	}
	if os.Getenv("SING_TUN_CALICO_CHILD") == t.Name() {
		current, err := os.Readlink("/proc/self/ns/mnt")
		require.NoError(t, err)
		require.NotEqual(t, os.Getenv("SING_TUN_CALICO_PARENT_MNT"), current, "private mount namespace required")
		require.NoError(t, os.MkdirAll("/run/netns", 0755))
		out, err := exec.Command("mount", "-t", "tmpfs", "tmpfs", "/run/netns").CombinedOutput()
		require.NoError(t, err, string(out))
		test()
		return
	}
	require.Equal(t, 0, os.Geteuid())
	for _, tool := range []string{"unshare", "mount", "ip", "nft", "iptables-legacy", "ip6tables-legacy", "conntrack", "python3"} {
		_, err := exec.LookPath(tool)
		require.NoError(t, err, "required integration tool %s", tool)
	}
	parent, err := os.Readlink("/proc/self/ns/mnt")
	require.NoError(t, err)
	cmd := exec.Command("unshare", "--mount", "--net", "--propagation", "private", os.Args[0], "-test.v", "-test.timeout=30s", "-test.run=^"+regexp.QuoteMeta(t.Name())+"$")
	cmd.Env = append(os.Environ(), "SING_TUN_CALICO_CHILD="+t.Name(), "SING_TUN_CALICO_PARENT_MNT="+parent)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Log(string(out))
}
