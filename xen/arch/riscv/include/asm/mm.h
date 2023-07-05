/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_MM_H
#define _ASM_RISCV_MM_H

#include <asm/page-bits.h>

#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))

void setup_initial_pagetables(void);

void enable_mmu(void);
void cont_after_mmu_is_enabled(void);

#endif /* _ASM_RISCV_MM_H */
