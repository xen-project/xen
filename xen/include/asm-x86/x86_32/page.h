
#ifndef __X86_32_PAGE_H__
#define __X86_32_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      22
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L2_PAGETABLE_SHIFT

#define L1_PAGETABLE_ENTRIES    1024
#define L2_PAGETABLE_ENTRIES    1024
#define ROOT_PAGETABLE_ENTRIES  L2_PAGETABLE_ENTRIES

#define __PAGE_OFFSET           (0xFC400000)

#define PADDR_BITS              32
#define VADDR_BITS              32
#define PADDR_MASK              (~0UL)
#define VADDR_MASK              (~0UL)

#ifndef __ASSEMBLY__
#include <xen/config.h>
typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;
typedef l2_pgentry_t root_pgentry_t;
#endif /* !__ASSEMBLY__ */

/* Strip type from a table entry. */
#define l1_pgentry_val(_x)   ((_x).l1_lo)
#define l2_pgentry_val(_x)   ((_x).l2_lo)
#define root_pgentry_val(_x) (l2_pgentry_val(_x))

/* Add type to a table entry. */
#define mk_l1_pgentry(_x)   ( (l1_pgentry_t) { (_x) } )
#define mk_l2_pgentry(_x)   ( (l2_pgentry_t) { (_x) } )
#define mk_root_pgentry(_x) (mk_l2_pgentry(_x))

/* Turn a typed table entry into a physical address. */
#define l1_pgentry_to_phys(_x)   (l1_pgentry_val(_x) & PAGE_MASK)
#define l2_pgentry_to_phys(_x)   (l2_pgentry_val(_x) & PAGE_MASK)
#define root_pgentry_to_phys(_x) (l2_pgentry_to_phys(_x))

/* Turn a typed table entry into a page index. */
#define l1_pgentry_to_pfn(_x)   (l1_pgentry_val(_x) >> PAGE_SHIFT) 
#define l2_pgentry_to_pfn(_x)   (l2_pgentry_val(_x) >> PAGE_SHIFT)
#define root_pgentry_to_pfn(_x) (l2_pgentry_to_pfn(_x))

/* Pagetable walking. */
#define l2_pgentry_to_l1(_x) \
  ((l1_pgentry_t *)__va(l2_pgentry_to_phys(_x)))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(_a) \
  ((_a) >> L2_PAGETABLE_SHIFT)

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) ((_a) >> PAGE_SHIFT)

#define is_guest_l1_slot(_s) (1)
#define is_guest_l2_slot(_s) ((_s) < ROOT_PAGETABLE_FIRST_XEN_SLOT)

#define PGT_root_page_table PGT_l2_page_table

#define _PAGE_NX         0UL

#define L1_DISALLOW_MASK (3UL << 7)
#define L2_DISALLOW_MASK (7UL << 7)
#define L3_DISALLOW_MASK (7UL << 7)
#define L2_DISALLOW_MASK (7UL << 7)

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
