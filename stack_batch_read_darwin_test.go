//go:build with_gvisor

package tun

import (
	"os"
	"testing"

	"github.com/metacubex/sing-tun/internal/stopfd_darwin"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
)

type countingBatchReader struct {
	*NativeTun
	reads int
}

func (r *countingBatchReader) BatchRead() ([]*buf.Buffer, error) {
	r.reads++
	// Make a regression fail deterministically instead of spinning forever.
	if r.reads > 1 {
		return nil, os.ErrClosed
	}
	return r.NativeTun.BatchRead()
}

type countingBatchLogger struct {
	logger.Logger
	errors int
}

func (l *countingBatchLogger) Error(...any) {
	l.errors++
}

func TestDarwinStacksExitOnInvalidBatchDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "reused-fd")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	for name, fd := range map[string]int{"EBADF": -1, "ENOTSOCK": int(file.Fd())} {
		t.Run(name, func(t *testing.T) {
			log := &countingBatchLogger{Logger: logger.NOP()}
			for name, loop := range map[string]func(DarwinTUN){
				"system":   (&System{logger: log}).batchLoopDarwin,
				"mixed":    (&Mixed{System: &System{logger: log}}).batchLoopDarwin,
				"mipstack": (&Mipstack{logger: log}).batchLoopDarwin,
			} {
				t.Run(name, func(t *testing.T) {
					log.errors = 0
					reader := &countingBatchReader{NativeTun: newBatchReadTestTun(t, fd, stopfd.StopFD{ReadFD: -1, WriteFD: -1})}
					loop(reader)
					if reader.reads != 1 || log.errors != 0 {
						t.Fatalf("read attempts = %d, logged errors = %d; want one read and no error flood", reader.reads, log.errors)
					}
				})
			}
		})
	}
}
