/* SPDX-License-Identifier: MIT */

#include "textflag.h"

// func ThreadProcAddr() uintptr
TEXT ·ThreadProcAddr(SB),NOSPLIT,$0-8
	LEAQ	threadProc<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// DWORD WINAPI threadProc(LPVOID call)
TEXT threadProc<>(SB),NOSPLIT|NOFRAME,$0-0
	SUBQ	$40, SP	// shadow space and alignment; 32(SP) keeps call
	MOVQ	CX, 32(SP)
wait:
	CMPL	32(CX), $0	// call.Go
	JNE	run
	PAUSE
	JMP	wait
run:
	MOVQ	0(CX), AX	// call.Fn
	MOVQ	16(CX), DX	// call.Arg1
	MOVQ	8(CX), CX	// call.Arg0
	CALL	AX
	MOVQ	32(SP), CX
	MOVQ	AX, 24(CX)	// call.Result
	MOVL	$1, 36(CX)	// call.Done
	XORL	AX, AX
	ADDQ	$40, SP
	RET

// func SpinUntilDone(call *Call, iterations uintptr) bool
TEXT ·SpinUntilDone(SB),NOSPLIT,$0-17
	MOVQ	call+0(FP), AX
	MOVQ	iterations+8(FP), CX
	MOVL	$1, 32(AX)	// call.Go
loop:
	CMPL	36(AX), $0	// call.Done
	JNE	done
	PAUSE
	DECQ	CX
	JNZ	loop
	MOVB	$0, ret+16(FP)
	RET
done:
	MOVB	$1, ret+16(FP)
	RET
