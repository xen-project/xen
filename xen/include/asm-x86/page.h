
#ifndef __X86_PAGE_H__
#define __X86_PAGE_H__

/*
 * It is important that the masks are signed quantities. This ensures that
 * the compiler sign-extends a 32-bit mask to 64 bits if that is required.
 */
#ifndef __ASSEMBLY__
#define PAGE_SIZE           (1L << PAGE_SHIFT)
#else
#define PAGE_SIZE           (1 << PAGE_SHIFT)
#endif
#define PAGE_MASK           (~(PAGE_SIZE-1))
#define PAGE_FLAG_MASK      (~0)

#ifndef __ASSEMBLY__
# include <asm/types.h>
# include <xen/lib.h>
#endif

#if defined(__i386__)
# include <asm/x86_32/page.h>
#elif defined(__x86_64__)
# include <asm/x86_64/page.h>
#endif

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
#if CONFIG_PAGING_LEVELS >= 3
static inline l3_pgentry_t l3e_from_paddr(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l3_pgentry_t) { pa | put_pte_flags(flags) };
}
#endif
#if CONFIG_PAGING_LEVELS >= 4
static inline l4_pgentry_t l4e_from_paddr(paddr_t pa, unsigned int flags)
{
    ASSERT((pa & ~(PADDR_MASK & PAGE_MASK)) == 0);
    return (l4_pgentry_t) { pa | put_pte_flags(flags) };
}
#endif
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

/* Page-table type. */
#ifndef __ASSEMBLY__
#if CONFIG_PAGING_LEVELS == 2
/* x86_32 default */
typedef struct { u32 pfn; } pagetable_t;
#elif CONFIG_PAGING_LEVELS == 3
/* x86_32 PAE */
typedef struct { u32 pfn; } pagetable_t;
#elif CONFIG_PAGING_LEVELS == 4
/* x86_64 */
typedef struct { u64 pfn; } pagetable_t;
#endif
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
#endif

#define clear_page(_p)      memset((void *)(_p), 0, PAGE_SIZE)
#define copy_page(_t,_f)    memcpy((void *)(_t), (void *)(_f), PAGE_SIZE)

#define mfn_valid(mfn)      ((mfn) < max_page)

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define PAGE_OFFSET         ((unsigned long)__PAGE_OFFSET)
#define virt_to_maddr(va)   ((unsigned long)(va)-PAGE_OFFSET)
#define maddr_to_virt(ma)   ((void *)((unsigned long)(ma)+PAGE_OFFSET))
/* Shorthand versions of the above functions. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define virt_to_mfn(va)     (virt_to_maddr(va) >> PAGE_SHIFT)
#define mfn_to_virt(mfn)    (maddr_to_virt(mfn << PAGE_SHIFT))

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)    (frame_table + (mfn))
#define page_to_mfn(pg)     ((unsigned long)((pg) - frame_table))

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma)   (frame_table + ((ma) >> PAGE_SHIFT))
#define page_to_maddr(pg)   ((paddr_t)((pg) - frame_table) << PAGE_SHIFT)

/* Convert between Xen-heap virtual addresses and page-info structures. */
#define virt_to_page(va)    (frame_table + (__pa(va) >> PAGE_SHIFT))
#define page_to_virt(pg)    (maddr_to_virt(page_to_maddr(pg)))

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn)   ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)    ((unsigned long)((pa) >> PAGE_SHIFT))

/* High table entries are reserved by the hypervisor. */
#if defined(CONFIG_X86_32) && !defined(CONFIG_X86_PAE)
#define DOMAIN_ENTRIES_PER_L2_PAGETABLE     \
  (HYPERVISOR_VIRT_START >> L2_PAGETABLE_SHIFT)
#define HYPERVISOR_ENTRIES_PER_L2_PAGETABLE \
  (L2_PAGETABLE_ENTRIES - DOMAIN_ENTRIES_PER_L2_PAGETABLE)
#else
#define DOMAIN_ENTRIES_PER_L2_PAGETABLE     0
#define HYPERVISOR_ENTRIES_PER_L2_PAGETABLE 0

#define DOMAIN_ENTRIES_PER_L4_PAGETABLE     \
    (l4_table_offset(HYPERVISOR_VIRT_START))
#define GUEST_ENTRIES_PER_L4_PAGETABLE     \
    (l4_table_offset(HYPERVISOR_VIRT_END))
#define HYPERVISOR_ENTRIES_PER_L4_PAGETABLE \
    (L4_PAGETABLE_ENTRIES - GUEST_ENTRIES_PER_L4_PAGETABLE  \
     + DOMAIN_ENTRIES_PER_L4_PAGETABLE)
#endif

/* Where to find each level of the linear mapping */
#define __linear_l1_table ((l1_pgentry_t *)(LINEAR_PT_VIRT_START))
#define __linear_l2_table \
 ((l2_pgentry_t *)(__linear_l1_table + l1_linear_offset(LINEAR_PT_VIRT_START)))
#define __linear_l3_table \
 ((l3_pgentry_t *)(__linear_l2_table + l2_linear_offset(LINEAR_PT_VIRT_START)))
#define __linear_l4_table \
 ((l4_pgentry_t *)(__linear_l3_table + l3_linear_offset(LINEAR_PT_VIRT_START)))


#ifndef __ASSEMBLY__
#if CONFIG_PAGING_LEVELS == 3
extern root_pgentry_t idle_pg_table[ROOT_PAGETABLE_ENTRIES];
extern l3_pgentry_t   idle_pg_table_l3[ROOT_PAGETABLE_ENTRIES];
extern l2_pgentry_t   idle_pg_table_l2[ROOT_PAGETABLE_ENTRIES*L2_PAGETABLE_ENTRIES];
#else
extern root_pgentry_t idle_pg_table[ROOT_PAGETABLE_ENTRIES];
extern l2_pgentry_t   idle_pg_table_l2[ROOT_PAGETABLE_ENTRIES];
#ifdef CONFIG_COMPAT
extern l2_pgentry_t  *compat_idle_pg_table_l2;
extern unsigned int   m2p_compat_vstart;
#endif
#endif
void paging_init(void);
void setup_idle_pagetable(void);
#endif

#define __pge_off()                                                     \
    do {                                                                \
        __asm__ __volatile__(                                           \
            "mov %0, %%cr4;  # turn off PGE     "                       \
            : : "r" (mmu_cr4_features & ~X86_CR4_PGE) );                \
        } while ( 0 )

#define __pge_on()                                                      \
    do {                                                                \
        __asm__ __volatile__(                                           \
            "mov %0, %%cr4;  # turn off PGE     "                       \
            : : "r" (mmu_cr4_features) );                               \
    } while ( 0 )

#define _PAGE_PRESENT  0x001U
#define _PAGE_RW       0x002U
#define _PAGE_USER     0x004U
#define _PAGE_PWT      0x008U
#define _PAGE_PCD      0x010U
#define _PAGE_ACCESSED 0x020U
#define _PAGE_DIRTY    0x040U
#define _PAGE_PAT      0x080U
#define _PAGE_PSE      0x080U
#define _PAGE_GLOBAL   0x100U
#define _PAGE_AVAIL0   0x200U
#define _PAGE_AVAIL1   0x400U
#define _PAGE_AVAIL2   0x800U
#define _PAGE_AVAIL    0xE00U
#define _PAGE_PSE_PAT 0x1000U

/*
 * Debug option: Ensure that granted mappings are not implicitly unmapped.
 * WARNING: This will need to be disabled to run OSes that use the spare PTE
 * bits themselves (e.g., *BSD).
 */
#ifndef NDEBUG
#define _PAGE_GNTTAB   _PAGE_AVAIL2
#else
#define _PAGE_GNTTAB   0
#endif

#define __PAGE_HYPERVISOR \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED)
#define __PAGE_HYPERVISOR_NOCACHE \
    (_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_PCD | _PAGE_ACCESSED)

#ifndef __ASSEMBLY__

static inline int get_order_from_bytes(paddr_t size)
{
    int order;
    size = (size-1) >> PAGE_SHIFT;
    for ( order = 0; size; order++ )
        size >>= 1;
    return order;
}

static inline int get_order_from_pages(unsigned long nr_pages)
{
    int order;
    nr_pages--;
    for ( order = 0; nr_pages; order++ )
        nr_pages >>= 1;
    return order;
}

/* Allocator functions for Xen pagetables. */
void *alloc_xen_pagetable(void);
void free_xen_pagetable(void *v);
l2_pgentry_t *virt_to_xen_l2e(unsigned long v);

/* Map machine page range in Xen virtual address space. */
#define MAP_SMALL_PAGES (1UL<<16) /* don't use superpages for the mapping */
int
map_pages_to_xen(
    unsigned long virt,
    unsigned long mfn,
    unsigned long nr_mfns,
    unsigned long flags);

#endif /* !__ASSEMBLY__ */

#define PFN_DOWN(x)   ((x) >> PAGE_SHIFT)
#define PFN_UP(x)     (((x) + PAGE_SIZE-1) >> PAGE_SHIFT)

#endif /* __X86_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
