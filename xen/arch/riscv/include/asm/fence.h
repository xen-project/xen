/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_RISCV_FENCE_H
#define _ASM_RISCV_FENCE_H

#define RISCV_ACQUIRE_BARRIER   "\tfence r , rw\n"
#define RISCV_RELEASE_BARRIER   "\tfence rw, w\n"
#define RISCV_FULL_BARRIER      "\tfence rw, rw\n"

#endif	/* _ASM_RISCV_FENCE_H */
