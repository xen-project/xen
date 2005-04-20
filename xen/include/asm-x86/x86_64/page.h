
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

#define _PAGE_NX                (cpu_has_nx ? (1UL<<63) : 0UL)
#define PAGE_FLAG_MASK          0xfff

#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <asm/types.h>
typedef struct { u64 l1_lo; } l1_pgentry_t;
typedef struct { u64 l2_lo; } l2_pgentry_t;
typedef struct { u64 l3_lo; } l3_pgentry_t;
typedef struct { u64 l4_lo; } l4_pgentry_t;
typedef l4_pgentry_t root_pgentry_t;

/* read access (depricated) */
#define l1e_get_value(_x)         ((_x).l1_lo)
#define l2e_get_value(_x)         ((_x).l2_lo)
#define l3e_get_value(_x)         ((_x).l3_lo)
#define l4e_get_value(_x)         ((_x).l4_lo)

/* read access */
#define l1e_get_pfn(_x)           (((_x).l1_lo & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT)
#define l1e_get_phys(_x)          (((_x).l1_lo & (PADDR_MASK&PAGE_MASK)))
#define l1e_get_flags(_x)         ((_x).l1_lo  &  PAGE_FLAG_MASK)

#define l2e_get_pfn(_x)           (((_x).l2_lo & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT)
#define l2e_get_phys(_x)          (((_x).l2_lo & (PADDR_MASK&PAGE_MASK)))
#define l2e_get_flags(_x)         ((_x).l2_lo  &  PAGE_FLAG_MASK)

#define l3e_get_pfn(_x)           (((_x).l3_lo & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT)
#define l3e_get_phys(_x)          (((_x).l3_lo & (PADDR_MASK&PAGE_MASK)))
#define l3e_get_flags(_x)         ((_x).l3_lo  &  PAGE_FLAG_MASK)

#define l4e_get_pfn(_x)           (((_x).l4_lo & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT)
#define l4e_get_phys(_x)          (((_x).l4_lo & (PADDR_MASK&PAGE_MASK)))
#define l4e_get_flags(_x)         ((_x).l4_lo  &  PAGE_FLAG_MASK)

/* write access */
static inline l1_pgentry_t l1e_empty(void)
{
    l1_pgentry_t e = { .l1_lo = 0 };
    return e;
}
static inline l1_pgentry_t l1e_create_pfn(u64 pfn, u64 flags)
{
    l1_pgentry_t e = { .l1_lo = (pfn << PAGE_SHIFT) | flags };
    return e;
}
static inline l1_pgentry_t l1e_create_phys(u64 addr, u64 flags)
{
    l1_pgentry_t e = { .l1_lo = (addr & (PADDR_MASK&PAGE_MASK)) | flags };
    return e;
}
static inline void l1e_add_flags(l1_pgentry_t *e, u64 flags)
{
    e->l1_lo |= flags;
}
static inline void l1e_remove_flags(l1_pgentry_t *e, u64 flags)
{
    e->l1_lo &= ~flags;
}

static inline l2_pgentry_t l2e_empty(void)
{
    l2_pgentry_t e = { .l2_lo = 0 };
    return e;
}
static inline l2_pgentry_t l2e_create_pfn(u64 pfn, u64 flags)
{
    l2_pgentry_t e = { .l2_lo = (pfn << PAGE_SHIFT) | flags };
    return e;
}
static inline l2_pgentry_t l2e_create_phys(u64 addr, u64 flags)
{
    l2_pgentry_t e = { .l2_lo = (addr & (PADDR_MASK&PAGE_MASK)) | flags };
    return e;
}
static inline void l2e_add_flags(l2_pgentry_t *e, u64 flags)
{
    e->l2_lo |= flags;
}
static inline void l2e_remove_flags(l2_pgentry_t *e, u64 flags)
{
    e->l2_lo &= ~flags;
}

static inline l3_pgentry_t l3e_empty(void)
{
    l3_pgentry_t e = { .l3_lo = 0 };
    return e;
}
static inline l3_pgentry_t l3e_create_pfn(u64 pfn, u64 flags)
{
    l3_pgentry_t e = { .l3_lo = (pfn << PAGE_SHIFT) | flags };
    return e;
}
static inline l3_pgentry_t l3e_create_phys(u64 addr, u64 flags)
{
    l3_pgentry_t e = { .l3_lo = (addr & (PADDR_MASK&PAGE_MASK)) | flags };
    return e;
}
static inline void l3e_add_flags(l3_pgentry_t *e, u64 flags)
{
    e->l3_lo |= flags;
}
static inline void l3e_remove_flags(l3_pgentry_t *e, u64 flags)
{
    e->l3_lo &= ~flags;
}

static inline l4_pgentry_t l4e_empty(void)
{
    l4_pgentry_t e = { .l4_lo = 0 };
    return e;
}
static inline l4_pgentry_t l4e_create_pfn(u64 pfn, u64 flags)
{
    l4_pgentry_t e = { .l4_lo = (pfn << PAGE_SHIFT) | flags };
    return e;
}
static inline l4_pgentry_t l4e_create_phys(u64 addr, u64 flags)
{
    l4_pgentry_t e = { .l4_lo = (addr & (PADDR_MASK&PAGE_MASK)) | flags };
    return e;
}
static inline void l4e_add_flags(l4_pgentry_t *e, u64 flags)
{
    e->l4_lo |= flags;
}
static inline void l4e_remove_flags(l4_pgentry_t *e, u64 flags)
{
    e->l4_lo &= ~flags;
}

/* check entries */
static inline int l1e_has_changed(l1_pgentry_t *e1, l1_pgentry_t *e2, u32 flags)
{
    return ((e1->l1_lo ^ e2->l1_lo) & ((PADDR_MASK&PAGE_MASK) | flags)) != 0;
}
static inline int l2e_has_changed(l2_pgentry_t *e1, l2_pgentry_t *e2, u32 flags)
{
    return ((e1->l2_lo ^ e2->l2_lo) & ((PADDR_MASK&PAGE_MASK) | flags)) != 0;
}
static inline int l3e_has_changed(l3_pgentry_t *e1, l3_pgentry_t *e2, u32 flags)
{
    return ((e1->l3_lo ^ e2->l3_lo) & ((PADDR_MASK&PAGE_MASK) | flags)) != 0;
}
static inline int l4e_has_changed(l4_pgentry_t *e1, l4_pgentry_t *e2, u32 flags)
{
    return ((e1->l4_lo ^ e2->l4_lo) & ((PADDR_MASK&PAGE_MASK) | flags)) != 0;
}

#endif /* !__ASSEMBLY__ */

/* Pagetable walking. */
#define l2e_to_l1e(_x) \
  ((l1_pgentry_t *)__va(l2e_get_phys(_x)))
#define l3e_to_l2e(_x) \
  ((l2_pgentry_t *)__va(l3e_get_phys(_x)))
#define l4e_to_l3e(_x) \
  ((l3_pgentry_t *)__va(l4e_get_phys(_x)))

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

#define root_get_pfn              l4e_get_pfn
#define root_get_flags            l4e_get_flags
#define root_get_value            l4e_get_value
#define root_empty                l4e_empty
#define root_create_phys          l4e_create_phys
#define PGT_root_page_table PGT_l4_page_table

#define L1_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (3UL << 7))
#define L2_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (7UL << 7))
#define L3_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (7UL << 7))
#define L4_DISALLOW_MASK ((cpu_has_nx?0:(1UL<<63)) | (7UL << 7))

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
