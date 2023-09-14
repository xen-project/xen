/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_PPC_BUG_H
#define _ASM_PPC_BUG_H

#include <xen/stringify.h>
#include <asm/processor.h>

/*
 * Power ISA guarantees that an instruction consisting of all zeroes is
 * illegal.
 */
#define BUG_OPCODE  0x00000000

#define BUG_INSTR ".long " __stringify(BUG_OPCODE)

#define BUG_FN_REG r0

/* TODO: implement this properly */
#define BUG() do { \
    die(); \
} while (0)

/* TODO: implement this properly */
#define BUG_FRAME(type, line, ptr, second_frame, msg) do { } while (0)

#endif /* _ASM_PPC_BUG_H */
