package tun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func TestFlushDNSCacheReapsChild(t *testing.T) {
	for _, exitCode := range []string{"0", "1"} {
		t.Run("exit_"+exitCode, func(t *testing.T) {
			dir := t.TempDir()
			pidFile := filepath.Join(dir, "pid")
			fifo := filepath.Join(dir, "release")
			require.NoError(t, syscall.Mkfifo(fifo, 0o600))
			release, err := os.OpenFile(fifo, os.O_RDWR, 0)
			require.NoError(t, err)
			defer release.Close()
			script := "#!/bin/sh\necho $$ > \"$FLUSH_TEST_PID\"\nread line < \"$FLUSH_TEST_FIFO\"\nexit " + exitCode + "\n"
			require.NoError(t, os.WriteFile(filepath.Join(dir, "dscacheutil"), []byte(script), 0o700))
			t.Setenv("PATH", dir)
			t.Setenv("FLUSH_TEST_PID", pidFile)
			t.Setenv("FLUSH_TEST_FIFO", fifo)

			log := &flushTestLogger{warnings: make(chan string, 1)}
			returned := make(chan struct{})
			go func() {
				flushDNSCache(log)
				close(returned)
			}()
			var pid int
			require.Eventually(t, func() bool {
				b, err := os.ReadFile(pidFile)
				if err != nil {
					return false
				}
				pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
				return err == nil && pid > 0
			}, 5*time.Second, 10*time.Millisecond)
			defer func() {
				// Reap the child even when testing the old, broken implementation.
				_, _ = release.WriteString("exit\n")
				_, _ = syscall.Wait4(pid, nil, 0, nil)
			}()
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("DNS cache flush blocked its caller until the subprocess exited")
			}
			require.NoError(t, syscall.Kill(pid, 0))
			_, err = release.WriteString("exit\n")
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
			}, 5*time.Second, 10*time.Millisecond, "exited DNS cache flush child was not reaped")

			if exitCode != "0" {
				select {
				case warning := <-log.warnings:
					require.Contains(t, warning, "flush DNS cache")
					require.Contains(t, warning, "exit status 1")
				case <-time.After(5 * time.Second):
					t.Fatal("subprocess failure was not reported")
				}
			}
		})
	}
}

type flushTestLogger struct {
	logger.Logger
	warnings chan string
}

func (l *flushTestLogger) Warn(args ...any) {
	l.warnings <- fmt.Sprint(args...)
}

func TestFlushDNSCacheReportsStartFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	log := &flushTestLogger{warnings: make(chan string, 1)}
	flushDNSCache(log)
	select {
	case warning := <-log.warnings:
		require.Contains(t, warning, "flush DNS cache")
		require.Contains(t, warning, "executable file not found")
	case <-time.After(5 * time.Second):
		t.Fatal("subprocess start failure was not reported")
	}
}
