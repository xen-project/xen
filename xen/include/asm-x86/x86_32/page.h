
#ifndef __X86_32_PAGE_H__
#define __X86_32_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      22
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L2_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         10
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L2_PAGETABLE_ENTRIES

#define __PAGE_OFFSET           (0xFF000000)

#define PADDR_BITS              32
#define VADDR_BITS              32
#define PADDR_MASK              (~0UL)
#define VADDR_MASK              (~0UL)

#define _PAGE_NX                0UL
#define PAGE_FLAG_MASK          0xfff

#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <asm/types.h>
typedef struct { u32 l1_lo; } l1_pgentry_t;
typedef struct { u32 l2_lo; } l2_pgentry_t;
typedef l2_pgentry_t root_pgentry_t;

/* read access (deprecated) */
#define l1e_get_value(_x)      ((unsigned long)((_x).l1_lo))
#define l2e_get_value(_x)      ((unsigned long)((_x).l2_lo))

/* read access */
#define l1e_get_pfn(_x)        ((unsigned long)((_x).l1_lo >> PAGE_SHIFT))
#define l1e_get_phys(_x)       ((unsigned long)((_x).l1_lo &  PAGE_MASK))
#define l1e_get_flags(_x)      ((unsigned long)((_x).l1_lo &  PAGE_FLAG_MASK))

#define l2e_get_pfn(_x)        ((unsigned long)((_x).l2_lo >> PAGE_SHIFT))
#define l2e_get_phys(_x)       ((unsigned long)((_x).l2_lo &  PAGE_MASK))
#define l2e_get_flags(_x)      ((unsigned long)((_x).l2_lo &  PAGE_FLAG_MASK))

/* write access */
static inline l1_pgentry_t l1e_empty(void)
{
    l1_pgentry_t e = { .l1_lo = 0 };
    return e;
}
static inline l1_pgentry_t l1e_create_pfn(u32 pfn, u32 flags)
{
    l1_pgentry_t e = { .l1_lo = (pfn << PAGE_SHIFT) | flags };
    return e;
}
static inline l1_pgentry_t l1e_create_phys(u32 addr, u32 flags)
{
    l1_pgentry_t e = { .l1_lo = (addr & PAGE_MASK) | flags };
    return e;
}
static inline void l1e_add_flags(l1_pgentry_t *e, u32 flags)
{
    e->l1_lo |= flags;
}
static inline void l1e_remove_flags(l1_pgentry_t *e, u32 flags)
{
    e->l1_lo &= ~flags;
}

static inline l2_pgentry_t l2e_empty(void)
{
    l2_pgentry_t e = { .l2_lo = 0 };
    return e;
}
static inline l2_pgentry_t l2e_create_pfn(u32 pfn, u32 flags)
{
    l2_pgentry_t e = { .l2_lo = (pfn << PAGE_SHIFT) | flags };
    return e;
}
static inline l2_pgentry_t l2e_create_phys(u32 addr, u32 flags)
{
    l2_pgentry_t e = { .l2_lo = (addr & PAGE_MASK) | flags };
    return e;
}
static inline void l2e_add_flags(l2_pgentry_t *e, u32 flags)
{
    e->l2_lo |= flags;
}
static inline void l2e_remove_flags(l2_pgentry_t *e, u32 flags)
{
    e->l2_lo &= ~flags;
}

/* check entries */
static inline int l1e_has_changed(l1_pgentry_t *e1, l1_pgentry_t *e2, u32 flags)
{
    return ((e1->l1_lo ^ e2->l1_lo) & (PAGE_MASK | flags)) != 0;
}
static inline int l2e_has_changed(l2_pgentry_t *e1, l2_pgentry_t *e2, u32 flags)
{
    return ((e1->l2_lo ^ e2->l2_lo) & (PAGE_MASK | flags)) != 0;
}

#endif /* !__ASSEMBLY__ */

/* Pagetable walking. */
#define l2e_to_l1e(_x) \
  ((l1_pgentry_t *)__va(l2e_get_phys(_x)))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(_a) \
  ((_a) >> L2_PAGETABLE_SHIFT)

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) ((_a) >> PAGE_SHIFT)

#define is_guest_l1_slot(_s) (1)
#define is_guest_l2_slot(_s) ((_s) < ROOT_PAGETABLE_FIRST_XEN_SLOT)

#define root_get_pfn              l2e_get_pfn
#define root_get_flags            l2e_get_flags
#define root_get_value            l2e_get_value
#define root_empty                l2e_empty
#define root_create_phys          l2e_create_phys
#define PGT_root_page_table       PGT_l2_page_table

#define L1_DISALLOW_MASK (3UL << 7)
#define L2_DISALLOW_MASK (7UL << 7)
#define L3_DISALLOW_MASK (7UL << 7)
#define L4_DISALLOW_MASK (7UL << 7)

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
