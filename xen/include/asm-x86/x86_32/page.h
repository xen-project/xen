/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */

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
#define l1_pgentry_val(_x) ((_x).l1_lo)
#define l2_pgentry_val(_x) ((_x).l2_lo)

/* Add type to a table entry. */
#define mk_l1_pgentry(_x)  ( (l1_pgentry_t) { (_x) } )
#define mk_l2_pgentry(_x)  ( (l2_pgentry_t) { (_x) } )

/* Turn a typed table entry into a physical address. */
#define l1_pgentry_to_phys(_x) (l1_pgentry_val(_x) & PAGE_MASK)
#define l2_pgentry_to_phys(_x) (l2_pgentry_val(_x) & PAGE_MASK)

/* Turn a typed table entry into a page index. */
#define l1_pgentry_to_pfn(_x) (l1_pgentry_val(_x) >> PAGE_SHIFT) 
#define l2_pgentry_to_pfn(_x) (l2_pgentry_val(_x) >> PAGE_SHIFT)

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

#endif /* __X86_32_PAGE_H__ */
