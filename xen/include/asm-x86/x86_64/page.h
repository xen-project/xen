/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */

#ifndef __X86_64_PAGE_H__
#define __X86_64_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L4_PAGETABLE_SHIFT

#define L1_PAGETABLE_ENTRIES    512
#define L2_PAGETABLE_ENTRIES    512
#define L3_PAGETABLE_ENTRIES    512
#define L4_PAGETABLE_ENTRIES    512
#define ROOT_PAGETABLE_ENTRIES  L4_PAGETABLE_ENTRIES

#define __PAGE_OFFSET           (0xFFFF830000000000)

/* These are page-table limitations. Current CPUs support only 40-bit phys. */
#define PADDR_BITS              52
#define VADDR_BITS              48
#define PADDR_MASK              ((1UL << PADDR_BITS)-1)
#define VADDR_MASK              ((1UL << VADDR_BITS)-1)

#ifndef __ASSEMBLY__
#include <xen/config.h>
typedef struct { unsigned long l1_lo; } l1_pgentry_t;
typedef struct { unsigned long l2_lo; } l2_pgentry_t;
typedef struct { unsigned long l3_lo; } l3_pgentry_t;
typedef struct { unsigned long l4_lo; } l4_pgentry_t;
typedef l4_pgentry_t root_pgentry_t;
#endif /* !__ASSEMBLY__ */

/* Strip type from a table entry. */
#define l1_pgentry_val(_x)   ((_x).l1_lo)
#define l2_pgentry_val(_x)   ((_x).l2_lo)
#define l3_pgentry_val(_x)   ((_x).l3_lo)
#define l4_pgentry_val(_x)   ((_x).l4_lo)
#define root_pgentry_val(_x) (l4_pgentry_val(_x))

/* Add type to a table entry. */
#define mk_l1_pgentry(_x)   ( (l1_pgentry_t) { (_x) } )
#define mk_l2_pgentry(_x)   ( (l2_pgentry_t) { (_x) } )
#define mk_l3_pgentry(_x)   ( (l3_pgentry_t) { (_x) } )
#define mk_l4_pgentry(_x)   ( (l4_pgentry_t) { (_x) } )
#define mk_root_pgentry(_x) (mk_l4_pgentry(_x))

/* Turn a typed table entry into a physical address. */
#define l1_pgentry_to_phys(_x)   (l1_pgentry_val(_x) & (PADDR_MASK&PAGE_MASK))
#define l2_pgentry_to_phys(_x)   (l2_pgentry_val(_x) & (PADDR_MASK&PAGE_MASK))
#define l3_pgentry_to_phys(_x)   (l3_pgentry_val(_x) & (PADDR_MASK&PAGE_MASK))
#define l4_pgentry_to_phys(_x)   (l4_pgentry_val(_x) & (PADDR_MASK&PAGE_MASK))
#define root_pgentry_to_phys(_x) (l4_pgentry_to_phys(_x))

/* Turn a typed table entry into a page index. */
#define l1_pgentry_to_pfn(_x)   (l1_pgentry_val(_x) >> PAGE_SHIFT) 
#define l2_pgentry_to_pfn(_x)   (l2_pgentry_val(_x) >> PAGE_SHIFT)
#define l3_pgentry_to_pfn(_x)   (l3_pgentry_val(_x) >> PAGE_SHIFT)
#define l4_pgentry_to_pfn(_x)   (l4_pgentry_val(_x) >> PAGE_SHIFT)
#define root_pgentry_to_pfn(_x) (l4_pgentry_to_pfn(_x))

/* Pagetable walking. */
#define l2_pgentry_to_l1(_x) \
  ((l1_pgentry_t *)__va(l2_pgentry_to_phys(_x)))
#define l3_pgentry_to_l2(_x) \
  ((l2_pgentry_t *)__va(l3_pgentry_to_phys(_x)))
#define l4_pgentry_to_l3(_x) \
  ((l3_pgentry_t *)__va(l4_pgentry_to_phys(_x)))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#define l3_table_offset(_a) \
  (((_a) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1))
#define l4_table_offset(_a) \
  (((_a) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1))

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) (((_a) & VADDR_MASK) >> PAGE_SHIFT)

#define is_guest_l1_slot(_s) (1)
#define is_guest_l2_slot(_s) (1)
#define is_guest_l3_slot(_s) (1)
#define is_guest_l4_slot(_s)                   \
    (((_s) < ROOT_PAGETABLE_FIRST_XEN_SLOT) || \
     ((_s) > ROOT_PAGETABLE_LAST_XEN_SLOT))

#define PGT_root_page_table PGT_l4_page_table

#define _PAGE_NX         (cpu_has_nx ? (1UL<<63) : 0UL)

#define L1_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (3UL << 7))
#define L2_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (7UL << 7))
#define L3_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (7UL << 7))
#define L4_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (7UL << 7))

#endif /* __X86_64_PAGE_H__ */
