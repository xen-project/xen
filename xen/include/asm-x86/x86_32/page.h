
#ifndef __X86_32_PAGE_H__
#define __X86_32_PAGE_H__

#define __PAGE_OFFSET           (0xFF000000)
#define __XEN_VIRT_START        __PAGE_OFFSET

#define virt_to_maddr(va) ((unsigned long)(va)-DIRECTMAP_VIRT_START)
#define maddr_to_virt(ma) ((void *)((unsigned long)(ma)+DIRECTMAP_VIRT_START))

#define VADDR_BITS              32
#define VADDR_MASK              (~0UL)

#define is_canonical_address(x) 1

#include <xen/config.h>
#ifdef CONFIG_X86_PAE
# include <asm/x86_32/page-3level.h>
#else
# include <asm/x86_32/page-2level.h>
#endif

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) ((_a) >> L1_PAGETABLE_SHIFT)
#define l2_linear_offset(_a) ((_a) >> L2_PAGETABLE_SHIFT)

#ifndef __ASSEMBLY__
extern unsigned int PAGE_HYPERVISOR;
extern unsigned int PAGE_HYPERVISOR_NOCACHE;
#endif

#define GRANT_PTE_FLAGS \
    (_PAGE_PRESENT|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_GNTTAB)

/*
 * Disallow unused flag bits plus PAT/PSE, PCD, PWT and GLOBAL.
 * Permit the NX bit if the hardware supports it.
 */
#define BASE_DISALLOW_MASK (0xFFFFF198U & ~_PAGE_NX)

#define L1_DISALLOW_MASK (BASE_DISALLOW_MASK | _PAGE_GNTTAB)
#define L2_DISALLOW_MASK (BASE_DISALLOW_MASK)

#endif /* __X86_32_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
