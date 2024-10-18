/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2021-2023 Vates
 *
 */
#ifndef ASM__RISCV__BUG_H
#define ASM__RISCV__BUG_H

#ifndef __ASSEMBLY__

#define BUG_INSTR "unimp"

/*
 * The base instruction set has a fixed length of 32-bit naturally aligned
 * instructions.
 *
 * There are extensions of variable length ( where each instruction can be
 * any number of 16-bit parcels in length ).
 *
 * Compressed ISA is used now where the instruction length is 16 bit and
 * 'unimp' instruction, in this case, can be either 16 or 32 bit (
 * depending on if compressed ISA is used or not )
 */
#define INSN_LENGTH_MASK        _UL(0x3)
#define INSN_LENGTH_32          _UL(0x3)

#define COMPRESSED_INSN_MASK    _UL(0xffff)

#define GET_INSN_LENGTH(insn)                               \
    (((insn) & INSN_LENGTH_MASK) == INSN_LENGTH_32 ? 4 : 2) \

#endif /* !__ASSEMBLY__ */

#endif /* ASM__RISCV__BUG_H */
