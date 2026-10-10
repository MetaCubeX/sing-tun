//go:build windows && (amd64 || 386)

/* SPDX-License-Identifier: MIT */

package memmod

import (
	"errors"
	"sync"
	"sync/atomic"
)

// The replacement for kernelbase.dll's import of RtlPcToFileHeader is reached from every
// GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) in the process, including the ones system DLLs make
// from DllMain, with the loader lock held. A Go callback there needs a P, the scheduler may have to start a
// thread to free one, and Windows does not let a thread start while a DLL is being loaded: the process deadlocks.
// So the replacement is rtlPcToFileHeaderThunk, a leaf assembly routine that never enters the Go runtime. It
// reads the variables below directly, hence the fixed-size table and the absence of a lock on the read side.

const maxLoadedAddressRanges = 32

var (
	// Entries below loadedAddressRangesCount are immutable; the count is published after the entry is written.
	loadedAddressRanges             [maxLoadedAddressRanges]addressRange
	loadedAddressRangesCount        uintptr
	loadedAddressRangesMu           sync.Mutex // serializes writers only
	hookedOriginalRtlPcToFileHeader uintptr
)

// rtlPcToFileHeaderThunkAddr returns the address of rtlPcToFileHeaderThunk, see hook_windows_$GOARCH.s.
func rtlPcToFileHeaderThunkAddr() uintptr

func registerAddressRange(r addressRange) error {
	loadedAddressRangesMu.Lock()
	defer loadedAddressRangesMu.Unlock()
	n := loadedAddressRangesCount
	for i := uintptr(0); i < n; i++ {
		if loadedAddressRanges[i] == r {
			return nil
		}
	}
	if n == maxLoadedAddressRanges {
		return errors.New("Too many memory modules")
	}
	loadedAddressRanges[n] = r
	atomic.StoreUintptr(&loadedAddressRangesCount, n+1)
	return nil
}

// newRtlPcToFileHeaderHook returns the replacement for kernelbase.dll's import of RtlPcToFileHeader.
func newRtlPcToFileHeaderHook(original uintptr, _ *uintptr) uintptr {
	hookedOriginalRtlPcToFileHeader = original
	return rtlPcToFileHeaderThunkAddr()
}
