/* SPDX-License-Identifier: MIT */

#include "textflag.h"

// func rtlPcToFileHeaderThunkAddr() uintptr
TEXT ·rtlPcToFileHeaderThunkAddr(SB),NOSPLIT,$0-4
	MOVL	$rtlPcToFileHeaderThunk<>(SB), AX
	MOVL	AX, ret+0(FP)
	RET

// PVOID NTAPI rtlPcToFileHeaderThunk(PVOID PcValue, PVOID *BaseOfImage)
//
// Called by kernelbase.dll in place of ntdll!RtlPcToFileHeader, possibly with the loader lock held and on a
// thread Go has never seen. It must stay a leaf that touches no Go runtime state: no stack check, no g, no calls.
// A PcValue inside a memory module is replaced with the address of this routine, so that the lookup returns the
// module containing it, then the original is tail-called with the caller's frame untouched.
// stdcall: PcValue at 4(SP), BaseOfImage at 8(SP), the original pops both; AX, CX and DX are volatile.
TEXT rtlPcToFileHeaderThunk<>(SB),NOSPLIT,$0-0
	MOVL	4(SP), AX
	MOVL	·loadedAddressRangesCount(SB), CX
	MOVL	$·loadedAddressRanges(SB), DX
loop:
	TESTL	CX, CX
	JZ	forward
	CMPL	AX, 0(DX)
	JCS	next	// PcValue < start
	CMPL	AX, 4(DX)
	JCC	next	// PcValue >= end
	MOVL	$rtlPcToFileHeaderThunk<>(SB), AX
	MOVL	AX, 4(SP)
	JMP	forward
next:
	ADDL	$8, DX
	DECL	CX
	JMP	loop
forward:
	MOVL	·hookedOriginalRtlPcToFileHeader(SB), AX
	JMP	AX
