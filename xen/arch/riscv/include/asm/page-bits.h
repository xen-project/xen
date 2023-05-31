#ifndef __RISCV_PAGE_BITS_H__
#define __RISCV_PAGE_BITS_H__

#define PAGE_SHIFT              12 /* 4 KiB Pages */
#define PADDR_BITS              56 /* 44-bit PPN */

#ifdef CONFIG_RISCV_64
#define PAGETABLE_ORDER         (9)
#else /* CONFIG_RISCV_32 */
#define PAGETABLE_ORDER         (10)
#endif

#define PAGETABLE_ENTRIES       (1 << PAGETABLE_ORDER)

#define PTE_PPN_SHIFT           10

#endif /* __RISCV_PAGE_BITS_H__ */
