/* SPDX-License-Identifier: MIT */

#include "textflag.h"

// func ThreadProcAddr() uintptr
TEXT ·ThreadProcAddr(SB),NOSPLIT,$0-4
	MOVL	$threadProc<>(SB), AX
	MOVL	AX, ret+0(FP)
	RET

// DWORD WINAPI threadProc(LPVOID call)
TEXT threadProc<>(SB),NOSPLIT,$0-0
	MOVL	4(SP), CX
wait:
	CMPL	16(CX), $0	// call.Go
	JNE	run
	PAUSE
	JMP	wait
run:
	SUBL	$8, SP
	MOVL	8(CX), AX	// call.Arg1
	MOVL	AX, 4(SP)
	MOVL	4(CX), AX	// call.Arg0
	MOVL	AX, 0(SP)
	MOVL	0(CX), AX	// call.Fn
	CALL	AX	// stdcall: Fn pops its two arguments
	MOVL	4(SP), CX
	MOVL	AX, 12(CX)	// call.Result
	MOVL	$1, 20(CX)	// call.Done
	// Return 0 and pop the single parameter.
	MOVL	0(SP), AX
	ADDL	$4, SP
	MOVL	AX, 0(SP)
	XORL	AX, AX
	RET

// func SpinUntilDone(call *Call, iterations uintptr) bool
TEXT ·SpinUntilDone(SB),NOSPLIT,$0-9
	MOVL	call+0(FP), AX
	MOVL	iterations+4(FP), CX
	MOVL	$1, 16(AX)	// call.Go
loop:
	CMPL	20(AX), $0	// call.Done
	JNE	done
	PAUSE
	DECL	CX
	JNZ	loop
	MOVB	$0, ret+8(FP)
	RET
done:
	MOVB	$1, ret+8(FP)
	RET
