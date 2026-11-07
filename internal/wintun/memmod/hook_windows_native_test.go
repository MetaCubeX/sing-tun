//go:build windows && (amd64 || 386)

/* SPDX-License-Identifier: MIT */

package memmod

import (
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/metacubex/sing-tun/internal/wintun/memmod/internal/foreignthread"

	"golang.org/x/sys/windows"
)

var (
	modkernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procCreateThread        = modkernel32.NewProc("CreateThread")
	procGetModuleHandleExW  = modkernel32.NewProc("GetModuleHandleExW")
	procGetCurrentProcessId = modkernel32.NewProc("GetCurrentProcessId")
	procRtlPcToFileHeader   = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlPcToFileHeader")
)

const testPageSize = 0x1000

var registeredTestRange uintptr

// reserveTestRange returns the start of the middle page of three reserved pages. Nothing is committed: the hook only
// compares addresses. The registered range is one for the whole test binary, since ranges are never unregistered.
func reserveTestRange(t *testing.T, register bool) uintptr {
	t.Helper()
	if register && registeredTestRange != 0 {
		return registeredTestRange
	}
	mem, err := windows.VirtualAlloc(0, 3*testPageSize, windows.MEM_RESERVE, windows.PAGE_NOACCESS)
	if err != nil {
		t.Fatal(err)
	}
	start := mem + testPageSize
	if register {
		err = registerAddressRange(addressRange{start, start + testPageSize})
		if err != nil {
			t.Fatal(err)
		}
		registeredTestRange = start
	}
	return start
}

func ownModule(t *testing.T) uintptr {
	t.Helper()
	var module, base uintptr
	module, _, _ = syscall.SyscallN(procRtlPcToFileHeader.Addr(), rtlPcToFileHeaderThunkAddr(), uintptr(unsafe.Pointer(&base)))
	if module == 0 {
		t.Fatal("the thunk is not inside a loaded module")
	}
	return module
}

func TestRtlPcToFileHeaderThunk(t *testing.T) {
	thunk := newRtlPcToFileHeaderHook(procRtlPcToFileHeader.Addr(), nil)
	lookup := func(pc uintptr) uintptr {
		base := ^uintptr(0)
		ret, _, _ := syscall.SyscallN(thunk, pc, uintptr(unsafe.Pointer(&base)))
		if ret != base {
			t.Fatalf("pc %#x: returned %#x but stored %#x", pc, ret, base)
		}
		return ret
	}
	self := ownModule(t)
	system := procGetCurrentProcessId.Addr()
	var systemModule uintptr
	syscall.SyscallN(procRtlPcToFileHeader.Addr(), system, uintptr(unsafe.Pointer(&systemModule)))
	if systemModule == 0 || systemModule == self {
		t.Fatalf("control: kernel32 resolves to %#x, own module is %#x", systemModule, self)
	}

	unregistered := reserveTestRange(t, false)
	if got := lookup(unregistered); got != 0 {
		t.Fatalf("control: an unregistered address resolves to %#x", got)
	}
	start := reserveTestRange(t, true)
	for _, c := range []struct {
		name string
		pc   uintptr
		want uintptr
	}{
		{"first byte of the range", start, self},
		{"last byte of the range", start + testPageSize - 1, self},
		{"byte before the range", start - 1, 0},
		{"byte after the range", start + testPageSize, 0},
		{"unregistered address", unregistered, 0},
		{"system module", system, systemModule},
	} {
		if got := lookup(c.pc); got != c.want {
			t.Errorf("%s: got module %#x, want %#x", c.name, got, c.want)
		}
	}

	// The same range again takes no new slot; the table refuses to overflow instead of dropping a module.
	count := loadedAddressRangesCount
	if err := registerAddressRange(addressRange{start, start + testPageSize}); err != nil || loadedAddressRangesCount != count {
		t.Fatalf("registering a known range: err=%v, count %d -> %d", err, count, loadedAddressRangesCount)
	}
}

// The hook as LoadLibrary installs it, asked through the real kernelbase.dll.
func TestHookedGetModuleHandleEx(t *testing.T) {
	haveHookedRtlPcToFileHeader.Do(func() {
		hookRtlPcToFileHeaderResult = hookRtlPcToFileHeader()
	})
	if hookRtlPcToFileHeaderResult != nil {
		t.Fatal(hookRtlPcToFileHeaderResult)
	}
	fromAddress := func(pc uintptr) (module uintptr, ok bool) {
		const flags = windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
		r, _, _ := procGetModuleHandleExW.Call(flags, pc, uintptr(unsafe.Pointer(&module)))
		return module, r != 0
	}
	self := ownModule(t)
	if module, ok := fromAddress(reserveTestRange(t, false)); ok {
		t.Fatalf("control: an unregistered address resolves to %#x", module)
	}
	if module, ok := fromAddress(reserveTestRange(t, true)); !ok || module != self {
		t.Fatalf("a memory module address resolves to %#x (ok=%v), want %#x", module, ok, self)
	}
	var kernel32 windows.Handle
	err := windows.GetModuleHandleEx(0, windows.StringToUTF16Ptr("kernel32.dll"), &kernel32)
	if err != nil {
		t.Fatal(err)
	}
	if module, ok := fromAddress(procGetCurrentProcessId.Addr()); !ok || module != uintptr(kernel32) {
		t.Fatalf("a kernel32 address resolves to %#x (ok=%v), want %#x", module, ok, kernel32)
	}
}

// callWithoutP calls fn(pc, &base) from a thread the Go runtime does not know while this goroutine holds the only P
// in assembly, and reports whether fn returned within the given number of spins.
func callWithoutP(t *testing.T, fn, pc uintptr, spins uintptr) (call *foreignthread.Call, base *uintptr, returned bool) {
	t.Helper()
	base = new(uintptr)
	call = &foreignthread.Call{Fn: fn, Arg0: pc, Arg1: uintptr(unsafe.Pointer(base))}
	thread, _, err := procCreateThread.Call(0, 0, foreignthread.ThreadProcAddr(), uintptr(unsafe.Pointer(call)), 0, 0)
	if thread == 0 {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		windows.WaitForSingleObject(windows.Handle(thread), windows.INFINITE)
		windows.CloseHandle(windows.Handle(thread))
		runtime.KeepAlive(call)
		runtime.KeepAlive(base)
	})
	returned = foreignthread.SpinUntilDone(call, spins)
	return
}

// The loader lock case reduced to its cause: the hook is entered on a foreign thread while no P is free. A Go
// callback cannot return then (the control); the thunk must.
func TestRtlPcToFileHeaderThunkNeedsNoP(t *testing.T) {
	thunk := newRtlPcToFileHeaderHook(procRtlPcToFileHeader.Addr(), nil)
	self := ownModule(t)
	start := reserveTestRange(t, true)
	original := procRtlPcToFileHeader.Addr()
	goHook := windows.NewCallback(func(pcValue uintptr, baseOfImage *uintptr) uintptr {
		ret, _, _ := syscall.SyscallN(original, pcValue, uintptr(unsafe.Pointer(baseOfImage)))
		return ret
	})
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	control, _, returned := callWithoutP(t, goHook, original, 1<<24)
	if returned {
		t.Fatal("control: a Go callback returned while no P was free; the test cannot tell the two hooks apart")
	}
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadUint32(&control.Done) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if control.Done == 0 || control.Result == 0 {
		t.Fatalf("control: the Go callback did not work once a P was free (done=%d, result=%#x)", control.Done, control.Result)
	}

	call, base, returned := callWithoutP(t, thunk, start, 1<<30)
	if !returned {
		t.Fatal("the thunk did not return while no P was free")
	}
	if call.Result != self || *base != self {
		t.Fatalf("got module %#x (stored %#x), want %#x", call.Result, *base, self)
	}
}
