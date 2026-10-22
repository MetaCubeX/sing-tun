/* SPDX-License-Identifier: MIT */

#include "textflag.h"

// func rtlPcToFileHeaderThunkAddr() uintptr
TEXT ·rtlPcToFileHeaderThunkAddr(SB),NOSPLIT,$0-8
	LEAQ	rtlPcToFileHeaderThunk<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// PVOID rtlPcToFileHeaderThunk(PVOID PcValue, PVOID *BaseOfImage)
//
// Called by kernelbase.dll in place of ntdll!RtlPcToFileHeader, possibly with the loader lock held and on a
// thread Go has never seen. It must stay a leaf that touches no Go runtime state: no stack check, no g, no calls.
// A PcValue inside a memory module is replaced with the address of this routine, so that the lookup returns the
// module containing it, then the original is tail-called with the caller's frame untouched.
// Windows x64 ABI: PcValue in CX, BaseOfImage in DX; AX and R8 are volatile.
TEXT rtlPcToFileHeaderThunk<>(SB),NOSPLIT|NOFRAME,$0-0
	MOVQ	·loadedAddressRangesCount(SB), AX
	LEAQ	·loadedAddressRanges(SB), R8
loop:
	TESTQ	AX, AX
	JZ	forward
	CMPQ	CX, 0(R8)
	JCS	next	// PcValue < start
	CMPQ	CX, 8(R8)
	JCC	next	// PcValue >= end
	LEAQ	rtlPcToFileHeaderThunk<>(SB), CX
	JMP	forward
next:
	ADDQ	$16, R8
	DECQ	AX
	JMP	loop
forward:
	MOVQ	·hookedOriginalRtlPcToFileHeader(SB), AX
	JMP	AX
