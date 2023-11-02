/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_MM_H
#define _ASM_RISCV_MM_H

#include <asm/page-bits.h>

#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))

extern unsigned char cpu0_boot_stack[];

void setup_initial_pagetables(void);

void enable_mmu(void);

void remove_identity_mapping(void);

unsigned long calc_phys_offset(void);

void turn_on_mmu(unsigned long ra);

#endif /* _ASM_RISCV_MM_H */
