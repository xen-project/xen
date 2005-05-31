
#ifndef __X86_64_PAGE_H__
#define __X86_64_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L4_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L4_PAGETABLE_ENTRIES

#define __PAGE_OFFSET           (0xFFFF830000000000)

/* These are page-table limitations. Current CPUs support only 40-bit phys. */
#define PADDR_BITS              52
#define VADDR_BITS              48
#define PADDR_MASK              ((1UL << PADDR_BITS)-1)
#define VADDR_MASK              ((1UL << VADDR_BITS)-1)

#ifndef __ASSEMBLY__

#include <xen/config.h>
#include <asm/types.h>

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016lx"

typedef struct { intpte_t l1; } l1_pgentry_t;
typedef struct { intpte_t l2; } l2_pgentry_t;
typedef struct { intpte_t l3; } l3_pgentry_t;
typedef struct { intpte_t l4; } l4_pgentry_t;
typedef l4_pgentry_t root_pgentry_t;

#endif /* !__ASSEMBLY__ */

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) (((_a) & VADDR_MASK) >> PAGE_SHIFT)

#define is_guest_l1_slot(_s) (1)
#define is_guest_l2_slot(_t, _s) (1)
#define is_guest_l3_slot(_s) (1)
#define is_guest_l4_slot(_s)                   \
    (((_s) < ROOT_PAGETABLE_FIRST_XEN_SLOT) || \
     ((_s) > ROOT_PAGETABLE_LAST_XEN_SLOT))

#define root_get_pfn              l4e_get_pfn
#define root_get_flags            l4e_get_flags
#define root_get_value            l4e_get_value
#define root_empty                l4e_empty
#define root_create_phys          l4e_create_phys
#define PGT_root_page_table PGT_l4_page_table

#define get_pte_flags(x) ((int)((x) >> 40) | ((int)(x) & 0xFFF))
#define put_pte_flags(x) ((((intpte_t)((x) & ~0xFFF)) << 40) | ((x) & 0xFFF))

#define _PAGE_NX                (cpu_has_nx ? (1U<<23) : 0U)

#define L1_DISALLOW_MASK (0xFFFFF180U & ~_PAGE_NX) /* PAT/GLOBAL */
#define L2_DISALLOW_MASK (0xFFFFF180U & ~_PAGE_NX) /* PSE/GLOBAL */
#define L3_DISALLOW_MASK (0xFFFFF180U & ~_PAGE_NX) /* must-be-zero */
#define L4_DISALLOW_MASK (0xFFFFF180U & ~_PAGE_NX) /* must-be-zero */

#endif /* __X86_64_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
