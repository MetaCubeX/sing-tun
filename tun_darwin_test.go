package tun

import (
	"errors"
	"os"
	"testing"

	"github.com/metacubex/sing-tun/internal/rawfile_darwin"
	"github.com/metacubex/sing-tun/internal/stopfd_darwin"
	E "github.com/metacubex/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

func newBatchReadTestTun(t *testing.T, fd int, stop stopfd.StopFD) *NativeTun {
	t.Helper()
	tun := &NativeTun{
		tunFd:     fd,
		batchSize: 1,
		iovecs:    []iovecBuffer{newIovecBuffer(1500)},
		msgHdrs:   make([]rawfile.MsgHdrX, 1),
		stopFd:    stop,
	}
	t.Cleanup(func() {
		for _, iovec := range tun.iovecs {
			if iovec.buffer != nil {
				iovec.buffer.Release()
			}
		}
	})
	return tun
}

func TestNativeTunBatchReadClosedDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "reused-fd")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	for name, fd := range map[string]int{
		"invalid descriptor":               -1,
		"descriptor reused for non-socket": int(file.Fd()),
	} {
		t.Run(name, func(t *testing.T) {
			tun := newBatchReadTestTun(t, fd, stopfd.StopFD{ReadFD: -1, WriteFD: -1})
			buffers, err := tun.BatchRead()
			if len(buffers) != 0 {
				t.Fatalf("BatchRead returned %d buffers for an invalid TUN descriptor", len(buffers))
			}
			if !errors.Is(err, os.ErrClosed) || !E.IsClosed(err) {
				t.Fatalf("BatchRead error = %v; stack loops need a closed error to stop retrying", err)
			}
		})
	}
}

func TestNativeTunBatchReadStopped(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	stop, err := stopfd.New()
	if err != nil {
		t.Fatal(err)
	}
	defer stop.Close()
	stop.Stop()
	tun := newBatchReadTestTun(t, fds[0], stop)
	_, err = tun.BatchRead()
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("BatchRead error = %v, want os.ErrClosed after stop", err)
	}
}
