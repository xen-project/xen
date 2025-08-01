#ifndef __X86_PAGE_H__
#define __X86_PAGE_H__

#include <xen/const.h>
#include <xen/page-size.h>

#define PAGE_ORDER_4K       0
#define PAGE_ORDER_2M       9
#define PAGE_ORDER_1G       18

#ifndef __ASSEMBLY__
# include <xen/types.h>
# include <xen/lib.h>
#endif

#include <asm/x86_64/page.h>

/* Read a pte atomically from memory. */
#define l1e_read(l1ep) \
    l1e_from_intpte(read_atomic(&l1e_get_intpte(*(l1ep))))
#define l2e_read(l2ep) \
    l2e_from_intpte(read_atomic(&l2e_get_intpte(*(l2ep))))
#define l3e_read(l3ep) \
    l3e_from_intpte(read_atomic(&l3e_get_intpte(*(l3ep))))
#define l4e_read(l4ep) \
    l4e_from_intpte(read_atomic(&l4e_get_intpte(*(l4ep))))

/* Write a pte atomically to memory. */
#define l1e_write(l1ep, l1e) \
    write_atomic(&l1e_get_intpte(*(l1ep)), l1e_get_intpte(l1e))
#define l2e_write(l2ep, l2e) \
    write_atomic(&l2e_get_intpte(*(l2ep)), l2e_get_intpte(l2e))
#define l3e_write(l3ep, l3e) \
    write_atomic(&l3e_get_intpte(*(l3ep)), l3e_get_intpte(l3e))
#define l4e_write(l4ep, l4e) \
    write_atomic(&l4e_get_intpte(*(l4ep)), l4e_get_intpte(l4e))

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

/* Get mfn mapped by pte (mfn_t). */
#define l1e_get_mfn(x) _mfn(l1e_get_pfn(x))
#define l2e_get_mfn(x) _mfn(l2e_get_pfn(x))
#define l3e_get_mfn(x) _mfn(l3e_get_pfn(x))
#define l4e_get_mfn(x) _mfn(l4e_get_pfn(x))

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
#define l1e_get_page(x)           mfn_to_page(l1e_get_mfn(x))
#define l2e_get_page(x)           mfn_to_page(l2e_get_mfn(x))
#define l3e_get_page(x)           mfn_to_page(l3e_get_mfn(x))
#define l4e_get_page(x)           mfn_to_page(l4e_get_mfn(x))

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

/* Construct a pte from an mfn and access flags. */
#define l1e_from_mfn(m, f) l1e_from_pfn(mfn_x(m), f)
#define l2e_from_mfn(m, f) l2e_from_pfn(mfn_x(m), f)
#define l3e_from_mfn(m, f) l3e_from_pfn(mfn_x(m), f)
#define l4e_from_mfn(m, f) l4e_from_pfn(mfn_x(m), f)

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
#define l1e_from_page(page, flags) l1e_from_mfn(page_to_mfn(page), flags)
#define l2e_from_page(page, flags) l2e_from_mfn(page_to_mfn(page), flags)
#define l3e_from_page(page, flags) l3e_from_mfn(page_to_mfn(page), flags)
#define l4e_from_page(page, flags) l4e_from_mfn(page_to_mfn(page), flags)

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

#define map_l1t_from_l2e(x)        (l1_pgentry_t *)map_domain_page(l2e_get_mfn(x))
#define map_l2t_from_l3e(x)        (l2_pgentry_t *)map_domain_page(l3e_get_mfn(x))
#define map_l3t_from_l4e(x)        (l3_pgentry_t *)map_domain_page(l4e_get_mfn(x))

/* Unlike lYe_to_lXe(), lXe_from_lYe() do not rely on the direct map. */
#define l1e_from_l2e(l2e_, offset_) ({                      \
        const l1_pgentry_t *l1t_ = map_l1t_from_l2e(l2e_);  \
        l1_pgentry_t l1e_ = l1t_[offset_];                  \
        unmap_domain_page(l1t_);                            \
        l1e_; })

#define l2e_from_l3e(l3e_, offset_) ({                      \
        const l2_pgentry_t *l2t_ = map_l2t_from_l3e(l3e_);  \
        l2_pgentry_t l2e_ = l2t_[offset_];                  \
        unmap_domain_page(l2t_);                            \
        l2e_; })

#define l3e_from_l4e(l4e_, offset_) ({                      \
        const l3_pgentry_t *l3t_ = map_l3t_from_l4e(l4e_);  \
        l3_pgentry_t l3e_ = l3t_[offset_];                  \
        unmap_domain_page(l3t_);                            \
        l3e_; })

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
#define pagetable_get_page(x)   mfn_to_page(pagetable_get_mfn(x))
#define pagetable_get_pfn(x)    ((x).pfn)
#define pagetable_get_mfn(x)    _mfn(((x).pfn))
#define pagetable_is_null(x)    ((x).pfn == 0)
#define pagetable_from_pfn(pfn) ((pagetable_t) { (pfn) })
#define pagetable_from_mfn(mfn) ((pagetable_t) { mfn_x(mfn) })
#define pagetable_from_page(pg) pagetable_from_mfn(page_to_mfn(pg))
#define pagetable_from_paddr(p) pagetable_from_pfn((p)>>PAGE_SHIFT)
#define pagetable_null()        pagetable_from_pfn(0)

void clear_page_hot(void *pg);
void clear_page_cold(void *pg);
void copy_page_sse2(void *to, const void *from);

#define clear_page(_p)      clear_page_cold(_p)
#define copy_page(_t, _f)   copy_page_sse2(_t, _f)

#ifdef CONFIG_DEBUG
void scrub_page_hot(void *ptr);
void scrub_page_cold(void *ptr);
#endif

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define __virt_to_mfn(va)   (virt_to_maddr(va) >> PAGE_SHIFT)
#define __mfn_to_virt(mfn)  (maddr_to_virt((paddr_t)(mfn) << PAGE_SHIFT))

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)    (frame_table + mfn_to_pdx(mfn))
#define page_to_mfn(pg)     pdx_to_mfn((unsigned long)((pg) - frame_table))

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma)   mfn_to_page(maddr_to_mfn(ma))
#define page_to_maddr(pg)   mfn_to_maddr(page_to_mfn(pg))

/* Convert between frame number and address formats.  */
#define __pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define __paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))
#define gfn_to_gaddr(gfn)   __pfn_to_paddr(gfn_x(gfn))
#define gaddr_to_gfn(ga)    _gfn(__paddr_to_pfn(ga))
#define mfn_to_maddr(mfn)   __pfn_to_paddr(mfn_x(mfn))
#define maddr_to_mfn(ma)    _mfn(__paddr_to_pfn(ma))

/*
 * We define non-underscored wrappers for above conversion functions. These are
 * overridden in various source files while underscored versions remain intact.
 */
#define mfn_valid(mfn)      __mfn_valid(mfn_x(mfn))
#define virt_to_mfn(va)     __virt_to_mfn(va)
#define mfn_to_virt(mfn)    __mfn_to_virt(mfn)
#define pfn_to_paddr(pfn)   __pfn_to_paddr(pfn)
#define paddr_to_pfn(pa)    __paddr_to_pfn(pa)

/* Specialized forms acting on vmap() addresses. */
#define vmap_to_mfn(va)     xen_map_to_mfn((unsigned long)(va))
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
    l2_bootmap[4*L2_PAGETABLE_ENTRIES];
extern l3_pgentry_t l3_bootmap[L3_PAGETABLE_ENTRIES];
extern l2_pgentry_t l2_directmap[4*L2_PAGETABLE_ENTRIES];
extern l1_pgentry_t l1_fixmap[L1_PAGETABLE_ENTRIES];
void paging_init(void);
void efi_update_l4_pgtable(unsigned int l4idx, l4_pgentry_t l4e);
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

#ifndef __ASSEMBLY__
/* Dependency on NX being available can't be expressed. */
#define _PAGE_NX       (cpu_has_nx ? _PAGE_NX_BIT : 0)
#endif

#define PAGE_CACHE_ATTRS (_PAGE_PAT | _PAGE_PCD | _PAGE_PWT)

/* Memory types, encoded under Xen's choice of MSR_PAT. */
#define _PAGE_WB         (                                0)
#define _PAGE_WT         (                        _PAGE_PWT)
#define _PAGE_UCM        (            _PAGE_PCD            )
#define _PAGE_UC         (            _PAGE_PCD | _PAGE_PWT)
#define _PAGE_WC         (_PAGE_PAT                        )
#define _PAGE_WP         (_PAGE_PAT |             _PAGE_PWT)

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
#define __PAGE_HYPERVISOR_WT      (__PAGE_HYPERVISOR | _PAGE_WT)
#define __PAGE_HYPERVISOR_UCMINUS (__PAGE_HYPERVISOR | _PAGE_UCM)
#define __PAGE_HYPERVISOR_UC      (__PAGE_HYPERVISOR | _PAGE_UC)
#define __PAGE_HYPERVISOR_WC      (__PAGE_HYPERVISOR | _PAGE_WC)
#define __PAGE_HYPERVISOR_SHSTK   (__PAGE_HYPERVISOR_RO | _PAGE_DIRTY)

#define MAP_SMALL_PAGES _PAGE_AVAIL0 /* don't use superpages mappings */

#ifndef __ASSEMBLY__

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
static inline bool
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

static inline void invalidate_icache(void)
{
/*
 * There is nothing to be done here as icaches are sufficiently
 * coherent on x86.
 */
}

#endif /* !__ASSEMBLY__ */

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
