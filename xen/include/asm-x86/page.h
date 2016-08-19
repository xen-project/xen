#ifndef __X86_PAGE_H__
#define __X86_PAGE_H__

#include <xen/const.h>

/*
 * It is important that the masks are signed quantities. This ensures that
 * the compiler sign-extends a 32-bit mask to 64 bits if that is required.
 */
#define PAGE_SIZE           (_AC(1,L) << PAGE_SHIFT)
#define PAGE_MASK           (~(PAGE_SIZE-1))
#define PAGE_FLAG_MASK      (~0)

#define PAGE_ORDER_4K       0
#define PAGE_ORDER_2M       9
#define PAGE_ORDER_1G       18

#ifndef __ASSEMBLY__
# include <asm/types.h>
# include <xen/lib.h>
#endif

#include <asm/x86_64/page.h>

/* Read a pte atomically from memory. */
#define l1e_read_atomic(l1ep) \
    l1e_from_intpte(pte_read_atomic(&l1e_get_intpte(*(l1ep))))
#define l2e_read_atomic(l2ep) \
    l2e_from_intpte(pte_read_atomic(&l2e_get_intpte(*(l2ep))))
#define l3e_read_atomic(l3ep) \
    l3e_from_intpte(pte_read_atomic(&l3e_get_intpte(*(l3ep))))
#define l4e_read_atomic(l4ep) \
    l4e_from_intpte(pte_read_atomic(&l4e_get_intpte(*(l4ep))))

/* Write a pte atomically to memory. */
#define l1e_write_atomic(l1ep, l1e) \
    pte_write_atomic(&l1e_get_intpte(*(l1ep)), l1e_get_intpte(l1e))
#define l2e_write_atomic(l2ep, l2e) \
    pte_write_atomic(&l2e_get_intpte(*(l2ep)), l2e_get_intpte(l2e))
#define l3e_write_atomic(l3ep, l3e) \
    pte_write_atomic(&l3e_get_intpte(*(l3ep)), l3e_get_intpte(l3e))
#define l4e_write_atomic(l4ep, l4e) \
    pte_write_atomic(&l4e_get_intpte(*(l4ep)), l4e_get_intpte(l4e))

/*
 * Write a pte safely but non-atomically to memory.
 * The PTE may become temporarily not-present during the update.
 */
#define l1e_write(l1ep, l1e) \
    pte_write(&l1e_get_intpte(*(l1ep)), l1e_get_intpte(l1e))
#define l2e_write(l2ep, l2e) \
    pte_write(&l2e_get_intpte(*(l2ep)), l2e_get_intpte(l2e))
#define l3e_write(l3ep, l3e) \
    pte_write(&l3e_get_intpte(*(l3ep)), l3e_get_intpte(l3e))
#define l4e_write(l4ep, l4e) \
    pte_write(&l4e_get_intpte(*(l4ep)), l4e_get_intpte(l4e))

/* Get direct integer representation of a pte's contents (intpte_t). */
#define l1e_get_intpte(x)          ((x).l1)
#define l2e_get_intpte(x)          ((x).l2)
#define l3e_get_intpte(x)          ((x).l3)
#define l4e_get_intpte(x)          ((x).l4)

/* Get pfn mapped by pte (unsigned long). */
#define l1e_get_pfn(x)             \
    ((unsigned long)(((x).l1 & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))
#define l2e_get_pfn(x)             \
    ((unsigned long)(((x).l2 & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))
#define l3e_get_pfn(x)             \
    ((unsigned long)(((x).l3 & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))
#define l4e_get_pfn(x)             \
    ((unsigned long)(((x).l4 & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))

/* Get physical address of page mapped by pte (paddr_t). */
#define l1e_get_paddr(x)           \
    ((paddr_t)(((x).l1 & (PADDR_MASK&PAGE_MASK))))
#define l2e_get_paddr(x)           \
    ((paddr_t)(((x).l2 & (PADDR_MASK&PAGE_MASK))))
#define l3e_get_paddr(x)           \
    ((paddr_t)(((x).l3 & (PADDR_MASK&PAGE_MASK))))
#define l4e_get_paddr(x)           \
    ((paddr_t)(((x).l4 & (PADDR_MASK&PAGE_MASK))))

/* Get pointer to info structure of page mapped by pte (struct page_info *). */
#define l1e_get_page(x)           (mfn_to_page(l1e_get_pfn(x)))
#define l2e_get_page(x)           (mfn_to_page(l2e_get_pfn(x)))
#define l3e_get_page(x)           (mfn_to_page(l3e_get_pfn(x)))
#define l4e_get_page(x)           (mfn_to_page(l4e_get_pfn(x)))

/* Get pte access flags (unsigned int). */
#define l1e_get_flags(x)           (get_pte_flags((x).l1))
#define l2e_get_flags(x)           (get_pte_flags((x).l2))
#define l3e_get_flags(x)           (get_pte_flags((x).l3))
#define l4e_get_flags(x)           (get_pte_flags((x).l4))

/* Get pte pkeys (unsigned int). */
#define l1e_get_pkey(x)           get_pte_pkey((x).l1)
#define l2e_get_pkey(x)           get_pte_pkey((x).l2)
#define l3e_get_pkey(x)           get_pte_pkey((x).l3)

/* Construct an empty pte. */
#define l1e_empty()                ((l1_pgentry_t) { 0 })
#define l2e_empty()                ((l2_pgentry_t) { 0 })
#define l3e_empty()                ((l3_pgentry_t) { 0 })
#define l4e_empty()                ((l4_pgentry_t) { 0 })

/* Construct a pte from a pfn and access flags. */
#define l1e_from_pfn(pfn, flags)   \
    ((l1_pgentry_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })
#define l2e_from_pfn(pfn, flags)   \
    ((l2_pgentry_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })
#define l3e_from_pfn(pfn, flags)   \
    ((l3_pgentry_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })
#define l4e_from_pfn(pfn, flags)   \
    ((l4_pgentry_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })

/* Construct a pte from a physical address and access flags. */
#ifndef __ASSEMBLY__
static inline l1_pgentry_t l1e_from_paddr(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l1_pgentry_t) { pa | put_pte_flags(flags) };
}
static inline l2_pgentry_t l2e_from_paddr(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l2_pgentry_t) { pa | put_pte_flags(flags) };
}
static inline l3_pgentry_t l3e_from_paddr(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l3_pgentry_t) { pa | put_pte_flags(flags) };
}
static inline l4_pgentry_t l4e_from_paddr(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l4_pgentry_t) { pa | put_pte_flags(flags) };
}
#endif /* !__ASSEMBLY__ */

/* Construct a pte from its direct integer representation. */
#define l1e_from_intpte(intpte)    ((l1_pgentry_t) { (intpte_t)(intpte) })
#define l2e_from_intpte(intpte)    ((l2_pgentry_t) { (intpte_t)(intpte) })
#define l3e_from_intpte(intpte)    ((l3_pgentry_t) { (intpte_t)(intpte) })
#define l4e_from_intpte(intpte)    ((l4_pgentry_t) { (intpte_t)(intpte) })

/* Construct a pte from a page pointer and access flags. */
#define l1e_from_page(page, flags) (l1e_from_pfn(page_to_mfn(page),(flags)))
#define l2e_from_page(page, flags) (l2e_from_pfn(page_to_mfn(page),(flags)))
#define l3e_from_page(page, flags) (l3e_from_pfn(page_to_mfn(page),(flags)))
#define l4e_from_page(page, flags) (l4e_from_pfn(page_to_mfn(page),(flags)))

/* Add extra flags to an existing pte. */
#define l1e_add_flags(x, flags)    ((x).l1 |= put_pte_flags(flags))
#define l2e_add_flags(x, flags)    ((x).l2 |= put_pte_flags(flags))
#define l3e_add_flags(x, flags)    ((x).l3 |= put_pte_flags(flags))
#define l4e_add_flags(x, flags)    ((x).l4 |= put_pte_flags(flags))

/* Remove flags from an existing pte. */
#define l1e_remove_flags(x, flags) ((x).l1 &= ~put_pte_flags(flags))
#define l2e_remove_flags(x, flags) ((x).l2 &= ~put_pte_flags(flags))
#define l3e_remove_flags(x, flags) ((x).l3 &= ~put_pte_flags(flags))
#define l4e_remove_flags(x, flags) ((x).l4 &= ~put_pte_flags(flags))

/* Flip flags in an existing L1 PTE. */
#define l1e_flip_flags(x, flags)    ((x).l1 ^= put_pte_flags(flags))

/* Check if a pte's page mapping or significant access flags have changed. */
#define l1e_has_changed(x,y,flags) \
    ( !!(((x).l1 ^ (y).l1) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )
#define l2e_has_changed(x,y,flags) \
    ( !!(((x).l2 ^ (y).l2) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )
#define l3e_has_changed(x,y,flags) \
    ( !!(((x).l3 ^ (y).l3) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )
#define l4e_has_changed(x,y,flags) \
    ( !!(((x).l4 ^ (y).l4) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )

/* Pagetable walking. */
#define l2e_to_l1e(x)              ((l1_pgentry_t *)__va(l2e_get_paddr(x)))
#define l3e_to_l2e(x)              ((l2_pgentry_t *)__va(l3e_get_paddr(x)))
#define l4e_to_l3e(x)              ((l3_pgentry_t *)__va(l4e_get_paddr(x)))

#define map_l1t_from_l2e(x)        ((l1_pgentry_t *)map_domain_page(_mfn(l2e_get_pfn(x))))
#define map_l2t_from_l3e(x)        ((l2_pgentry_t *)map_domain_page(_mfn(l3e_get_pfn(x))))
#define map_l3t_from_l4e(x)        ((l3_pgentry_t *)map_domain_page(_mfn(l4e_get_pfn(x))))

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(a)         \
    (((a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(a)         \
    (((a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#define l3_table_offset(a)         \
    (((a) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1))
#define l4_table_offset(a)         \
    (((a) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1))

/* Convert a pointer to a page-table entry into pagetable slot index. */
#define pgentry_ptr_to_slot(_p)    \
    (((unsigned long)(_p) & ~PAGE_MASK) / sizeof(*(_p)))

#ifndef __ASSEMBLY__

/* Page-table type. */
typedef struct { u64 pfn; } pagetable_t;
#define pagetable_get_paddr(x)  ((paddr_t)(x).pfn << PAGE_SHIFT)
#define pagetable_get_page(x)   mfn_to_page((x).pfn)
#define pagetable_get_pfn(x)    ((x).pfn)
#define pagetable_get_mfn(x)    _mfn(((x).pfn))
#define pagetable_is_null(x)    ((x).pfn == 0)
#define pagetable_from_pfn(pfn) ((pagetable_t) { (pfn) })
#define pagetable_from_mfn(mfn) ((pagetable_t) { mfn_x(mfn) })
#define pagetable_from_page(pg) pagetable_from_pfn(page_to_mfn(pg))
#define pagetable_from_paddr(p) pagetable_from_pfn((p)>>PAGE_SHIFT)
#define pagetable_null()        pagetable_from_pfn(0)

void clear_page_sse2(void *);
void copy_page_sse2(void *, const void *);

#define clear_page(_p)      clear_page_sse2(_p)
#define copy_page(_t, _f)   copy_page_sse2(_t, _f)

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define __virt_to_mfn(va)   (virt_to_maddr(va) >> PAGE_SHIFT)
#define __mfn_to_virt(mfn)  (maddr_to_virt((paddr_t)(mfn) << PAGE_SHIFT))

/* Convert between machine frame numbers and page-info structures. */
#define __mfn_to_page(mfn)  (frame_table + pfn_to_pdx(mfn))
#define __page_to_mfn(pg)   pdx_to_pfn((unsigned long)((pg) - frame_table))

/* Convert between machine addresses and page-info structures. */
#define __maddr_to_page(ma) __mfn_to_page((ma) >> PAGE_SHIFT)
#define __page_to_maddr(pg) ((paddr_t)__page_to_mfn(pg) << PAGE_SHIFT)

/* Convert between frame number and address formats.  */
#define __pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define __paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))


/* Convert between machine frame numbers and spage-info structures. */
#define __mfn_to_spage(mfn)  (spage_table + pfn_to_sdx(mfn))
#define __spage_to_mfn(pg)   sdx_to_pfn((unsigned long)((pg) - spage_table))

/* Convert between page-info structures and spage-info structures. */
#define page_to_spage(page)  (spage_table+(((page)-frame_table)>>(SUPERPAGE_SHIFT-PAGE_SHIFT)))
#define spage_to_page(spage)  (frame_table+(((spage)-spage_table)<<(SUPERPAGE_SHIFT-PAGE_SHIFT)))

/*
 * We define non-underscored wrappers for above conversion functions. These are
 * overridden in various source files while underscored versions remain intact.
 */
#define mfn_valid(mfn)      __mfn_valid(mfn)
#define virt_to_mfn(va)     __virt_to_mfn(va)
#define mfn_to_virt(mfn)    __mfn_to_virt(mfn)
#define virt_to_maddr(va)   __virt_to_maddr((unsigned long)(va))
#define maddr_to_virt(ma)   __maddr_to_virt((unsigned long)(ma))
#define mfn_to_page(mfn)    __mfn_to_page(mfn)
#define page_to_mfn(pg)     __page_to_mfn(pg)
#define mfn_to_spage(mfn)    __mfn_to_spage(mfn)
#define spage_to_mfn(pg)     __spage_to_mfn(pg)
#define maddr_to_page(ma)   __maddr_to_page(ma)
#define page_to_maddr(pg)   __page_to_maddr(pg)
#define virt_to_page(va)    __virt_to_page(va)
#define page_to_virt(pg)    __page_to_virt(pg)
#define pfn_to_paddr(pfn)   __pfn_to_paddr(pfn)
#define paddr_to_pfn(pa)    __paddr_to_pfn(pa)
#define paddr_to_pdx(pa)    pfn_to_pdx(paddr_to_pfn(pa))
#define vmap_to_mfn(va)     l1e_get_pfn(*virt_to_xen_l1e((unsigned long)(va)))
#define vmap_to_page(va)    mfn_to_page(vmap_to_mfn(va))

#endif /* !defined(__ASSEMBLY__) */

/* Where to find each level of the linear mapping */
#define __linear_l1_table ((l1_pgentry_t *)(LINEAR_PT_VIRT_START))
#define __linear_l2_table \
 ((l2_pgentry_t *)(__linear_l1_table + l1_linear_offset(LINEAR_PT_VIRT_START)))
#define __linear_l3_table \
 ((l3_pgentry_t *)(__linear_l2_table + l2_linear_offset(LINEAR_PT_VIRT_START)))
#define __linear_l4_table \
 ((l4_pgentry_t *)(__linear_l3_table + l3_linear_offset(LINEAR_PT_VIRT_START)))


#ifndef __ASSEMBLY__
extern root_pgentry_t idle_pg_table[ROOT_PAGETABLE_ENTRIES];
extern l2_pgentry_t  *compat_idle_pg_table_l2;
extern unsigned int   m2p_compat_vstart;
extern l2_pgentry_t l2_xenmap[L2_PAGETABLE_ENTRIES],
    l2_bootmap[L2_PAGETABLE_ENTRIES];
extern l3_pgentry_t l3_bootmap[L3_PAGETABLE_ENTRIES];
extern l2_pgentry_t l2_identmap[4*L2_PAGETABLE_ENTRIES];
extern l1_pgentry_t l1_fixmap[L1_PAGETABLE_ENTRIES];
void paging_init(void);
void efi_update_l4_pgtable(unsigned int l4idx, l4_pgentry_t);
#endif /* !defined(__ASSEMBLY__) */

#define _PAGE_NONE     _AC(0x000,U)
#define _PAGE_PRESENT  _AC(0x001,U)
#define _PAGE_RW       _AC(0x002,U)
#define _PAGE_USER     _AC(0x004,U)
#define _PAGE_PWT      _AC(0x008,U)
#define _PAGE_PCD      _AC(0x010,U)
#define _PAGE_ACCESSED _AC(0x020,U)
#define _PAGE_DIRTY    _AC(0x040,U)
#define _PAGE_PAT      _AC(0x080,U)
#define _PAGE_PSE      _AC(0x080,U)
#define _PAGE_GLOBAL   _AC(0x100,U)
#define _PAGE_AVAIL0   _AC(0x200,U)
#define _PAGE_AVAIL1   _AC(0x400,U)
#define _PAGE_AVAIL2   _AC(0x800,U)
#define _PAGE_AVAIL    _AC(0xE00,U)
#define _PAGE_PSE_PAT  _AC(0x1000,U)
#define _PAGE_AVAIL_HIGH (_AC(0x7ff, U) << 12)
#define _PAGE_NX       (cpu_has_nx ? _PAGE_NX_BIT : 0)
/* non-architectural flags */
#define _PAGE_PAGED   0x2000U
#define _PAGE_SHARED  0x4000U

/*
 * Debug option: Ensure that granted mappings are not implicitly unmapped.
 * WARNING: This will need to be disabled to run OSes that use the spare PTE
 * bits themselves (e.g., *BSD).
 */
#ifdef NDEBUG
#undef _PAGE_GNTTAB
#endif
#ifndef _PAGE_GNTTAB
#define _PAGE_GNTTAB   0
#endif

#define __PAGE_HYPERVISOR_RO      (_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_NX)
#define __PAGE_HYPERVISOR_RW      (__PAGE_HYPERVISOR_RO | \
                                   _PAGE_DIRTY | _PAGE_RW)
#define __PAGE_HYPERVISOR_RX      (_PAGE_PRESENT | _PAGE_ACCESSED)
#define __PAGE_HYPERVISOR         (__PAGE_HYPERVISOR_RX | \
                                   _PAGE_DIRTY | _PAGE_RW)
#define __PAGE_HYPERVISOR_NOCACHE (__PAGE_HYPERVISOR | _PAGE_PCD)

#define MAP_SMALL_PAGES _PAGE_AVAIL0 /* don't use superpages mappings */

#ifndef __ASSEMBLY__

/* Allocator functions for Xen pagetables. */
void *alloc_xen_pagetable(void);
void free_xen_pagetable(void *v);
l1_pgentry_t *virt_to_xen_l1e(unsigned long v);

/* Convert between PAT/PCD/PWT embedded in PTE flags and 3-bit cacheattr. */
static inline unsigned int pte_flags_to_cacheattr(unsigned int flags)
{
    return ((flags >> 5) & 4) | ((flags >> 3) & 3);
}
static inline unsigned int cacheattr_to_pte_flags(unsigned int cacheattr)
{
    return ((cacheattr & 4) << 5) | ((cacheattr & 3) << 3);
}

/* return true if permission increased */
static inline bool_t
perms_strictly_increased(uint32_t old_flags, uint32_t new_flags)
/* Given the flags of two entries, are the new flags a strict
 * increase in rights over the old ones? */
{
    uint32_t of = old_flags & (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_NX_BIT);
    uint32_t nf = new_flags & (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_NX_BIT);
    /* Flip the NX bit, since it's the only one that decreases rights;
     * we calculate as if it were an "X" bit. */
    of ^= _PAGE_NX_BIT;
    nf ^= _PAGE_NX_BIT;
    /* If the changed bits are all set in the new flags, then rights strictly
     * increased between old and new. */
    return ((of | (of ^ nf)) == nf);
}

#endif /* !__ASSEMBLY__ */

#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

#endif /* __X86_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
