/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef RISCV_INSN_DEFS_H
#define RISCV_INSN_DEFS_H

#define HFENCE_VVMA(vaddr, asid) \
    asm volatile ( "hfence.vvma %z0, %z1" \
                  :: "rJ" (vaddr), "rJ" (asid) : "memory" )

#endif /* RISCV_INSN_DEFS_H */
