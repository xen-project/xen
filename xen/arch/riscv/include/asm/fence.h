/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ASM__RISCV__FENCE_H
#define ASM__RISCV__FENCE_H

#define RISCV_ACQUIRE_BARRIER   "\tfence r , rw\n"
#define RISCV_RELEASE_BARRIER   "\tfence rw, w\n"
#define RISCV_FULL_BARRIER      "\tfence rw, rw\n"

#endif	/* ASM__RISCV__FENCE_H */
