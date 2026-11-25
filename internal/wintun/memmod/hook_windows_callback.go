//go:build windows && (arm || arm64)

/* SPDX-License-Identifier: MIT */

package memmod

import (
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	loadedAddressRanges   []addressRange
	loadedAddressRangesMu sync.RWMutex
)

func registerAddressRange(r addressRange) error {
	loadedAddressRangesMu.Lock()
	loadedAddressRanges = append(loadedAddressRanges, r)
	loadedAddressRangesMu.Unlock()
	return nil
}

// newRtlPcToFileHeaderHook returns the replacement for kernelbase.dll's import of RtlPcToFileHeader.
//
// On these architectures it is still a Go callback, so a DllMain that calls
// GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) enters the Go runtime with the loader lock held, which
// can deadlock the process (see hook_windows_native.go). They need the same assembly thunk amd64 and 386 have.
func newRtlPcToFileHeaderHook(original uintptr, thunk *uintptr) uintptr {
	return windows.NewCallback(func(pcValue uintptr, baseOfImage *uintptr) uintptr {
		loadedAddressRangesMu.RLock()
		for i := range loadedAddressRanges {
			if pcValue >= loadedAddressRanges[i].start && pcValue < loadedAddressRanges[i].end {
				pcValue = *thunk
				break
			}
		}
		loadedAddressRangesMu.RUnlock()
		ret, _, _ := syscall.SyscallN(original, pcValue, uintptr(unsafe.Pointer(baseOfImage)))
		return ret
	})
}
