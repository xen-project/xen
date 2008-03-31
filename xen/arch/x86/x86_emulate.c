/******************************************************************************
 * x86_emulate.c
 * 
 * Wrapper for generic x86 instruction decoder and emulator.
 * 
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
 */

#include <asm/x86_emulate.h>

#undef cmpxchg

#define __emulate_fpu_insn(_op)                 \
do{ int _exn;                                   \
    asm volatile (                              \
        "1: " _op "\n"                          \
        "2: \n"                                 \
        ".section .fixup,\"ax\"\n"              \
        "3: mov $1,%0\n"                        \
        "   jmp 2b\n"                           \
        ".previous\n"                           \
        ".section __ex_table,\"a\"\n"           \
        "   "__FIXUP_ALIGN"\n"                  \
        "   "__FIXUP_WORD" 1b,3b\n"             \
        ".previous"                             \
        : "=r" (_exn) : "0" (0) );              \
    generate_exception_if(_exn, EXC_MF, -1);    \
} while (0)

#include "x86_emulate/x86_emulate.c"
