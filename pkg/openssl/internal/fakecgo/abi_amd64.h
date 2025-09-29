// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Macros for transitioning from the host ABI to Go ABI0.
//
// These save the frame pointer, so in general, functions that use
// these should have zero frame size to suppress the automatic frame
// pointer, though it's harmless to not do this.

#define REGS_HOST_TO_ABI0_STACK (6*8)

// SysV MXCSR matches the Go ABI, so we don't have to set that,
// and Go doesn't modify it, so we don't have to save it.
// Both SysV and Go require DF to be cleared, so that's already clear.
// The SysV and Go frame pointer conventions are compatible.
#define PUSH_REGS_HOST_TO_ABI0()	\
	ADJSP	$(REGS_HOST_TO_ABI0_STACK)	\
	MOVQ	BP, (5*8)(SP)	\
	LEAQ	(5*8)(SP), BP	\
	MOVQ	BX, (0*8)(SP)	\
	MOVQ	R12, (1*8)(SP)	\
	MOVQ	R13, (2*8)(SP)	\
	MOVQ	R14, (3*8)(SP)	\
	MOVQ	R15, (4*8)(SP)

#define POP_REGS_HOST_TO_ABI0()	\
	MOVQ	(0*8)(SP), BX	\
	MOVQ	(1*8)(SP), R12	\
	MOVQ	(2*8)(SP), R13	\
	MOVQ	(3*8)(SP), R14	\
	MOVQ	(4*8)(SP), R15	\
	MOVQ	(5*8)(SP), BP	\
	ADJSP	$-(REGS_HOST_TO_ABI0_STACK)
