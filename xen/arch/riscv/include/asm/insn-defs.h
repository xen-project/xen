/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM_RISCV_INSN_DEFS_H
#define ASM_RISCV_INSN_DEFS_H

#define HFENCE_VVMA(vaddr, asid) \
    asm volatile ( "hfence.vvma %z0, %z1" \
                  :: "rJ" (vaddr), "rJ" (asid) : "memory" )

#endif /* ASM_RISCV_INSN_DEFS_H */
