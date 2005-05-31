#ifndef __X86_32_PAGE_3L_H__
#define __X86_32_PAGE_3L_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L3_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    4
#define ROOT_PAGETABLE_ENTRIES  L3_PAGETABLE_ENTRIES

#define PADDR_BITS              52
#define PADDR_MASK              ((1ULL << PADDR_BITS)-1)

#ifndef __ASSEMBLY__

#include <asm/types.h>

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016llx"

typedef struct { intpte_t l1; } l1_pgentry_t;
typedef struct { intpte_t l2; } l2_pgentry_t;
typedef struct { intpte_t l3; } l3_pgentry_t;
typedef l3_pgentry_t root_pgentry_t;

#endif /* !__ASSEMBLY__ */

/* root table */
#define root_get_pfn              l3e_get_pfn
#define root_get_flags            l3e_get_flags
#define root_get_value            l3e_get_value
#define root_empty                l3e_empty
#define root_init_phys            l3e_create_phys
#define PGT_root_page_table       PGT_l3_page_table

/* misc */
#define is_guest_l1_slot(_s)    (1)
#define is_guest_l2_slot(_t,_s) \
    ((3 != (((_t) & PGT_va_mask) >> PGT_va_shift)) || \
     ((_s) < (L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES-1))))
#define is_guest_l3_slot(_s)    (1)

#define get_pte_flags(x) ((int)((x) >> 40) | ((int)(x) & 0xFFF))
#define put_pte_flags(x) ((((intpte_t)((x) & ~0xFFF)) << 40) | ((x) & 0xFFF))

#define L1_DISALLOW_MASK (0xFFFFF180U & ~_PAGE_NX) /* PAT/GLOBAL */
#define L2_DISALLOW_MASK (0xFFFFF180U & ~_PAGE_NX) /* PSE/GLOBAL */
#define L3_DISALLOW_MASK (0xFFFFF1E6U)             /* must-be-zero */

#endif /* __X86_32_PAGE_3L_H__ */
