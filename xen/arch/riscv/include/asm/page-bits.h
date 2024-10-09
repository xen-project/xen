/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__PAGE_BITS_H
#define ASM__RISCV__PAGE_BITS_H

#define PAGE_SHIFT              12 /* 4 KiB Pages */
#define PADDR_BITS              56 /* 44-bit PPN */

#ifdef CONFIG_RISCV_64
#define PAGETABLE_ORDER         (9)
#else /* CONFIG_RISCV_32 */
#define PAGETABLE_ORDER         (10)
#endif

#define PAGETABLE_ENTRIES       (1 << PAGETABLE_ORDER)

#define PTE_PPN_SHIFT           10

#endif /* ASM__RISCV__PAGE_BITS_H */
