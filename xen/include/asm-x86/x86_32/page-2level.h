#ifndef __X86_32_PAGE_2LEVEL_H__
#define __X86_32_PAGE_2LEVEL_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      22
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L2_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         10
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L2_PAGETABLE_ENTRIES

#define PADDR_BITS              32
#define PADDR_MASK              (~0UL)

#ifndef __ASSEMBLY__

#include <asm/types.h>

/* read access (should only be used for debug printk's) */
typedef u32 intpte_t;
#define PRIpte "08x"

typedef struct { intpte_t l1; } l1_pgentry_t;
typedef struct { intpte_t l2; } l2_pgentry_t;
typedef l2_pgentry_t root_pgentry_t;

#endif /* !__ASSEMBLY__ */

#define pte_read_atomic(ptep)       (*(ptep))
#define pte_write_atomic(ptep, pte) (*(ptep) = (pte))
#define pte_write(ptep, pte)        (*(ptep) = (pte))

/* root table */
#define root_get_pfn              l2e_get_pfn
#define root_get_flags            l2e_get_flags
#define root_get_intpte           l2e_get_intpte
#define root_empty                l2e_empty
#define root_from_paddr           l2e_from_paddr
#define PGT_root_page_table       PGT_l2_page_table

/* misc */
#define is_guest_l1_slot(_s)    (1)
#define is_guest_l2_slot(_d, _t,_s) ((_s) < L2_PAGETABLE_FIRST_XEN_SLOT)

/*
 * PTE pfn and flags:
 *  20-bit pfn   = (pte[31:12])
 *  12-bit flags = (pte[11:0])
 */

#define _PAGE_NX_BIT            0U
#define _PAGE_NX                0U

/* Extract flags into 12-bit integer, or turn 12-bit flags into a pte mask. */
#define get_pte_flags(x) ((int)(x) & 0xFFF)
#define put_pte_flags(x) ((intpte_t)((x) & 0xFFF))

#endif /* __X86_32_PAGE_2LEVEL_H__ */
