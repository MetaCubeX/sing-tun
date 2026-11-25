//go:build windows && (amd64 || 386)

/* SPDX-License-Identifier: MIT */

// Package foreignthread is a test helper: it makes one call from a thread the Go runtime has never seen, while
// the calling goroutine keeps its P in assembly, where it cannot be preempted. A callee that needs the Go runtime
// cannot complete under these conditions, which is what a routine called under the Windows loader lock must survive.
package foreignthread

// Call is the argument of the thread routine. It must not move while the thread runs.
type Call struct {
	Fn     uintptr // called as Fn(Arg0, Arg1) with the system calling convention
	Arg0   uintptr
	Arg1   uintptr
	Result uintptr
	Go     uint32 // set by SpinUntilDone: the thread waits for it before it calls Fn
	Done   uint32 // set by the thread after Fn returned
}

// ThreadProcAddr returns an LPTHREAD_START_ROUTINE whose parameter is a *Call.
func ThreadProcAddr() uintptr

// SpinUntilDone lets the thread go and spins, without ever yielding the P, until the thread reports that Fn
// returned or the given number of iterations has passed. It reports whether Fn returned.
func SpinUntilDone(call *Call, iterations uintptr) bool
