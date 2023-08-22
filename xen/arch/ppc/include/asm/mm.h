#ifndef _ASM_PPC_MM_H
#define _ASM_PPC_MM_H

#include <asm/page-bits.h>

#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))

#define virt_to_maddr(va) ((paddr_t)((vaddr_t)(va) & PADDR_MASK))
#define maddr_to_virt(pa) ((void *)((paddr_t)(pa) | XEN_VIRT_START))

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

void setup_initial_pagetables(void);

#endif /* _ASM_PPC_MM_H */
