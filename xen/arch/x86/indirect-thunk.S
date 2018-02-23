/*
 * Implement __x86_indirect_thunk_* symbols for use with compatbile compilers
 * and the -mindirect-branch=thunk-extern -mindirect-branch-register options.
 *
 * Copyright (c) 2017-2018 Citrix Systems Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */
        .file __FILE__

#include <asm/asm_defns.h>

.macro IND_THUNK_RETPOLINE reg:req
        call 2f
1:
        lfence
        jmp 1b
2:
        mov %\reg, (%rsp)
        ret
.endm

.macro IND_THUNK_LFENCE reg:req
        lfence
        jmp *%\reg
.endm

.macro IND_THUNK_JMP reg:req
        jmp *%\reg
.endm

/*
 * Build the __x86_indirect_thunk_* symbols.  Execution lands on an
 * alternative patch point which implements one of the above THUNK_*'s
 */
.macro GEN_INDIRECT_THUNK reg:req
        .section .text.__x86_indirect_thunk_\reg, "ax", @progbits

ENTRY(__x86_indirect_thunk_\reg)
        ALTERNATIVE_2 __stringify(IND_THUNK_RETPOLINE \reg),              \
        __stringify(IND_THUNK_LFENCE \reg), X86_FEATURE_IND_THUNK_LFENCE, \
        __stringify(IND_THUNK_JMP \reg),    X86_FEATURE_IND_THUNK_JMP

        .size __x86_indirect_thunk_\reg, . - __x86_indirect_thunk_\reg
        .type __x86_indirect_thunk_\reg, @function
.endm

/* Instantiate GEN_INDIRECT_THUNK for each register except %rsp. */
.irp reg, ax, cx, dx, bx, bp, si, di, 8, 9, 10, 11, 12, 13, 14, 15
        GEN_INDIRECT_THUNK reg=r\reg
.endr
