//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	"github.com/metacubex/sing/common/shell"
	"github.com/stretchr/testify/require"
)

// TestSetSearchDomainForSystemdResolvedLogsFailure checks that a failed
// resolvectl write is reported to the logger.
//
// The writes are issued from a detached goroutine, so the caller cannot observe
// their result, which makes the logger the only place the failure can surface.
// Before this was handled, the exit status was dropped and the child's stderr
// went to /dev/null (shell.Exec is used without Attach(), so Stderr stays nil),
// and a machine with no working systemd-resolved came up resolving nothing while
// configure() reported success.
//
// resolvectl is replaced by a stub on PATH so both failure modes are reproduced
// deterministically, without depending on whether the host runs systemd-resolved
// or how its polkit is configured.
func TestSetSearchDomainForSystemdResolvedLogsFailure(t *testing.T) {
	const interfaceName = "tun0"
	expectedInvocations := []string{
		"resolvectl domain " + interfaceName + " ~.",
		"resolvectl default-route " + interfaceName + " true",
		"resolvectl dns " + interfaceName + " 198.18.0.2 fdfe:dcba:9876::2",
	}

	for _, testCase := range []struct {
		name   string
		stderr string
	}{
		{
			// systemd-resolved is not running; resolvectl is still installed, so
			// exec.LookPath succeeds and every D-Bus call fails on connect.
			name: "systemd_resolved_absent",
			stderr: "Failed to set domain configuration: Failed to connect to service " +
				"/run/systemd/resolve/io.systemd.Resolve: No such file or directory\n",
		},
		{
			// systemd-resolved is reachable, but polkit denies the write because
			// no authentication agent is registered yet, as when a client starts
			// at login before the desktop agent is up.
			name: "polkit_denied",
			stderr: "Failed to set domain configuration: Access denied as the requested " +
				"operation requires interactive authentication. However, interactive " +
				"authentication has not been enabled by the calling program.\n",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			invocationLog := stubResolvectl(t, testCase.stderr)
			recorder := newRecordingLogger()

			nativeTun := &NativeTun{options: testOptions(interfaceName, recorder)}

			err := nativeTun.setSearchDomainForSystemdResolved()
			require.NoError(t, err,
				"the return value cannot report a failure from the detached goroutine, "+
					"so configure() cannot distinguish a working DNS takeover from a dead one")

			// The write attempted with the argv sing-tun builds. resolvectl is
			// found through PATH, so the stub proves the call site, not just the
			// configuration.
			require.Equal(t, expectedInvocations, waitInvocations(t, invocationLog, 3))

			// The message existed: replaying one command with stderr captured
			// returns the text that was previously discarded.
			captured, captureErr := witnessResolvectl("domain", interfaceName, "~.")
			require.Error(t, captureErr)
			require.Contains(t, captured, "Failed to set domain configuration",
				"resolvectl explained the failure; it was the reporting that was missing")

			// The failure now reaches the logger, with the explanation included.
			records := strings.Join(recorder.records(), "\n")
			require.NotEmpty(t, records,
				"a failed resolvectl write was not reported to the logger")
			require.Contains(t, records, testCase.stderr[:len(testCase.stderr)-1],
				"the logged entry should carry resolvectl's own explanation")
		})
	}
}

// stubResolvectl installs an executable named resolvectl at the front of PATH. It
// appends every invocation to a log file, writes stderr to stderr and exits 1,
// replaying one failure mode. It returns the path of the invocation log.
func stubResolvectl(t *testing.T, stderr string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "invocations.log")
	stderrPath := filepath.Join(dir, "stderr.txt")
	require.NoError(t, os.WriteFile(stderrPath, []byte(stderr), 0o644))
	script := "#!/bin/sh\n" +
		"printf 'resolvectl %s\\n' \"$*\" >> '" + logPath + "'\n" +
		"cat '" + stderrPath + "' >&2\n" +
		"exit 1\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "resolvectl"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// waitInvocations blocks until resolvectl has been run count times and returns
// the recorded command lines. The writes happen in a detached goroutine, so the
// test has to wait for them rather than assume they completed.
func waitInvocations(t *testing.T, logPath string, count int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var lines []string
		content, err := os.ReadFile(logPath)
		switch {
		case err == nil:
			if trimmed := strings.TrimRight(string(content), "\n"); trimmed != "" {
				lines = strings.Split(trimmed, "\n")
			}
		case !os.IsNotExist(err):
			t.Fatalf("read invocation log: %v", err)
		}
		if len(lines) >= count {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolvectl was invoked %d time(s), want %d: %q", len(lines), count, lines)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// witnessResolvectl runs one command with stderr captured and the exit error
// kept, which is exactly the information the write path used to discard.
func witnessResolvectl(args ...string) (string, error) {
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return "", err
	}
	return shell.Exec(ctlPath, args...).Read()
}

// testOptions is the TUN configuration for a fake-ip range of 198.18.0.0/15,
// whose DNS addresses are 198.18.0.2 and fdfe:dcba:9876::2.
func testOptions(interfaceName string, log logger.Logger) Options {
	return Options{
		Name:         interfaceName,
		AutoRoute:    true,
		DNSMode:      DNSModeHijack,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		Logger:       log,
	}
}

// recordingLogger records every entry so a test can assert what was logged.
type recordingLogger struct {
	access sync.Mutex
	lines  []string
}

func newRecordingLogger() *recordingLogger {
	return &recordingLogger{}
}

func (l *recordingLogger) record(level string, args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	l.lines = append(l.lines, level+": "+fmt.Sprint(args...))
}

func (l *recordingLogger) Trace(args ...any) { l.record("trace", args...) }
func (l *recordingLogger) Debug(args ...any) { l.record("debug", args...) }
func (l *recordingLogger) Info(args ...any)  { l.record("info", args...) }
func (l *recordingLogger) Warn(args ...any)  { l.record("warn", args...) }
func (l *recordingLogger) Error(args ...any) { l.record("error", args...) }
func (l *recordingLogger) Fatal(args ...any) { l.record("fatal", args...) }
func (l *recordingLogger) Panic(args ...any) { l.record("panic", args...) }

func (l *recordingLogger) records() []string {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string(nil), l.lines...)
}
