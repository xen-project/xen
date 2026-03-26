#ifndef __ARCH_ARM_MM__
#define __ARCH_ARM_MM__

#include <xen/kernel.h>
#include <asm/page.h>
#include <public/xen.h>
#include <xen/pdx.h>

#if defined(CONFIG_ARM_32)
# include <asm/arm32/mm.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/mm.h>
#else
# error "unknown ARM variant"
#endif

#if defined(CONFIG_MMU)
# include <asm/mmu/mm.h>
#elif !defined(CONFIG_MPU)
# error "Unknown memory management layout"
#endif

/* Align Xen to a 2 MiB boundary. */
#define XEN_PADDR_ALIGN (1 << 21)

/*
 * Per-page-frame information.
 *
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct page_list_entry list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->v.free.order)

/*
 * The size of struct page_info impacts the number of entries that can fit
 * into the frametable area and thus it affects the amount of physical memory
 * we claim to support. Define PAGE_INFO_SIZE to be used for sanity checking.
*/
#ifdef CONFIG_ARM_64
#define PAGE_INFO_SIZE 56
#else
#define PAGE_INFO_SIZE 32
#endif

struct page_info
{
    /* Each frame can be threaded onto a doubly-linked list. */
    struct page_list_entry list;

    /* Reference count and various PGC_xxx flags and fields. */
    unsigned long count_info;

    /* Context-dependent fields follow... */
    union {
        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Type reference count and various PGT_xxx flags and fields. */
            unsigned long type_info;
        } inuse;
        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        union {
            struct {
                /*
                 * Index of the first *possibly* unscrubbed page in the buddy.
                 * One more bit than maximum possible order to accommodate
                 * INVALID_DIRTY_IDX.
                 */
#define INVALID_DIRTY_IDX ((1UL << (MAX_ORDER + 1)) - 1)
                unsigned long first_dirty:MAX_ORDER + 1;

                /* Do TLBs need flushing for safety before next page use? */
                bool need_tlbflush:1;

#define BUDDY_NOT_SCRUBBING    0
#define BUDDY_SCRUBBING        1
#define BUDDY_SCRUB_ABORT      2
                unsigned long scrub_state:2;
            };

            unsigned long val;
            } free;

    } u;

    union {
        /* Page is in use, but not as a shadow. */
        struct {
            /* Owner of this page (zero if page is anonymous). */
            struct domain *domain;
        } inuse;

        /* Page is on a free list. */
        struct {
            /* Order-size of the free chunk this page is the head of. */
            unsigned int order;
        } free;

    } v;

    union {
        /*
         * Timestamp from 'TLB clock', used to avoid extra safety flushes.
         * Only valid for: a) free pages, and b) pages with zero type count
         */
        u32 tlbflush_timestamp;
    };
    u64 pad;
};

#define PG_shift(idx)   (BITS_PER_LONG - (idx))
#define PG_mask(x, idx) (x ## UL << PG_shift(idx))

#define PGT_none          PG_mask(0, 1)  /* no special uses of this page   */
#define PGT_writable_page PG_mask(1, 1)  /* has writable mappings?         */
#define PGT_type_mask     PG_mask(1, 1)  /* Bits 31 or 63.                 */

 /* 2-bit count of uses of this frame as its current type. */
#define PGT_count_mask    PG_mask(3, 3)

/*
 * Stored in bits [28:0] (arm32) or [60:0] (arm64) GFN if page is xenheap page.
 */
#define PGT_gfn_width     PG_shift(3)
#define PGT_gfn_mask      ((1UL<<PGT_gfn_width)-1)

#define PGT_INVALID_XENHEAP_GFN   _gfn(PGT_gfn_mask)

/*
 * An arch-specific initialization pattern is needed for the type_info field
 * as it's GFN portion can contain the valid GFN if page is xenheap page.
 */
#define PGT_TYPE_INFO_INITIALIZER   gfn_x(PGT_INVALID_XENHEAP_GFN)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated    PG_shift(1)
#define PGC_allocated     PG_mask(1, 1)
  /* Page is Xen heap? */
#define _PGC_xen_heap     PG_shift(2)
#define PGC_xen_heap      PG_mask(1, 2)
#ifdef CONFIG_STATIC_MEMORY
/* Page is static memory */
#define _PGC_static    PG_shift(3)
#define PGC_static     PG_mask(1, 3)
#else
#define PGC_static     0
#endif
#ifdef CONFIG_LLC_COLORING
/* Page is cache colored */
#define _PGC_colored      PG_shift(4)
#define PGC_colored       PG_mask(1, 4)
#endif
/* ... */
/* Page is broken? */
#define _PGC_broken       PG_shift(7)
#define PGC_broken        PG_mask(1, 7)
 /* Mutually-exclusive page states: { inuse, offlining, offlined, free }. */
#define PGC_state         PG_mask(3, 9)
#define PGC_state_inuse   PG_mask(0, 9)
#define PGC_state_offlining PG_mask(1, 9)
#define PGC_state_offlined PG_mask(2, 9)
#define PGC_state_free    PG_mask(3, 9)
#define page_state_is(pg, st) (((pg)->count_info&PGC_state) == PGC_state_##st)
/* Page is not reference counted */
#define _PGC_extra        PG_shift(10)
#define PGC_extra         PG_mask(1, 10)

/* Count of references to this frame. */
#define PGC_count_width   PG_shift(10)
#define PGC_count_mask    ((1UL<<PGC_count_width)-1)

/*
 * Page needs to be scrubbed. Since this bit can only be set on a page that is
 * free (i.e. in PGC_state_free) we can reuse PGC_allocated bit.
 */
#define _PGC_need_scrub   _PGC_allocated
#define PGC_need_scrub    PGC_allocated

#ifdef CONFIG_ARM_32
#define is_xen_heap_page(page) is_xen_heap_mfn(page_to_mfn(page))
#define is_xen_heap_mfn(mfn) ({                                 \
    unsigned long mfn_ = mfn_x(mfn);                            \
    (mfn_ >= mfn_x(directmap_mfn_start) &&                      \
     mfn_ < mfn_x(directmap_mfn_end));                          \
})
#else
#define is_xen_heap_page(page) ((page)->count_info & PGC_xen_heap)
#define is_xen_heap_mfn(mfn) \
    (mfn_valid(mfn) && is_xen_heap_page(mfn_to_page(mfn)))
#endif

#define is_xen_fixed_mfn(mfn)                                   \
    ((mfn_to_maddr(mfn) >= virt_to_maddr(&_start)) &&           \
     (mfn_to_maddr(mfn) <= virt_to_maddr((vaddr_t)_end - 1)))

#define page_get_owner(_p)    (_p)->v.inuse.domain
#define page_set_owner(_p,_d) ((_p)->v.inuse.domain = (_d))

#define maddr_get_owner(ma)   (page_get_owner(maddr_to_page((ma))))

/* PDX of the first page in the frame table. */
extern unsigned long frametable_base_pdx;

#define PDX_GROUP_SHIFT SECOND_SHIFT

/* Boot-time pagetable setup */
extern void setup_pagetables(void);
/* Map FDT in boot pagetable */
extern void *early_fdt_map(paddr_t fdt_paddr);
/* Remove early mappings */
extern void remove_early_mappings(void);
/* Prepare the memory subystem to bring-up the given secondary CPU */
extern int prepare_secondary_mm(int cpu);
/* Map a frame table to cover physical addresses ps through pe */
extern void setup_frametable_mappings(paddr_t ps, paddr_t pe);
/* map a physical range in virtual memory */
void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned int attributes);

static inline void __iomem *ioremap_nocache(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR_NOCACHE);
}

static inline void __iomem *ioremap_cache(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR);
}

static inline void __iomem *ioremap_wc(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR_WC);
}

/* XXX -- account for base */
#define mfn_valid(mfn)        ({                                              \
    unsigned long __m_f_n = mfn_x(mfn);                                       \
    likely(pfn_to_pdx(__m_f_n) >= frametable_base_pdx && __mfn_valid(__m_f_n)); \
})

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)                                            \
    (frame_table + (mfn_to_pdx(mfn) - frametable_base_pdx))
#define page_to_mfn(pg)                                             \
    pdx_to_mfn((unsigned long)((pg) - frame_table) + frametable_base_pdx)

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma) mfn_to_page(maddr_to_mfn(ma))
#define page_to_maddr(pg) (mfn_to_maddr(page_to_mfn(pg)))

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))
#define paddr_to_pdx(pa)    mfn_to_pdx(maddr_to_mfn(pa))
#define gfn_to_gaddr(gfn)   pfn_to_paddr(gfn_x(gfn))
#define gaddr_to_gfn(ga)    _gfn(paddr_to_pfn(ga))
#define mfn_to_maddr(mfn)   pfn_to_paddr(mfn_x(mfn))
#define maddr_to_mfn(ma)    _mfn(paddr_to_pfn(ma))
#define vmap_to_mfn(va)     maddr_to_mfn(virt_to_maddr((vaddr_t)(va)))
#define vmap_to_page(va)    mfn_to_page(vmap_to_mfn(va))

/* Page-align address and convert to frame number format */
#define paddr_to_pfn_aligned(paddr)    paddr_to_pfn(PAGE_ALIGN(paddr))

#define virt_to_maddr(va) ({                                        \
    vaddr_t va_ = (vaddr_t)(va);                                    \
    (paddr_t)((va_to_par(va_) & PADDR_MASK & PAGE_MASK) | (va_ & ~PAGE_MASK)); \
})

#ifdef CONFIG_ARM_32
/**
 * Find the virtual address corresponding to a machine address
 *
 * Only memory backing the XENHEAP has a corresponding virtual address to
 * be found. This is so we can save precious virtual space, as it's in
 * short supply on arm32. This mapping is not subject to PDX compression
 * because XENHEAP is known to be physically contiguous and can't hence
 * jump over the PDX hole. This means we can avoid the roundtrips
 * converting to/from pdx.
 *
 * @param ma Machine address
 * @return Virtual address mapped to `ma`
 */
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT(is_xen_heap_mfn(maddr_to_mfn(ma)));
    ma -= mfn_to_maddr(directmap_mfn_start);
    return (void *)(unsigned long) ma + XENHEAP_VIRT_START;
}
#else
/**
 * Find the virtual address corresponding to a machine address
 *
 * The directmap covers all conventional memory accesible by the
 * hypervisor. This means it's subject to PDX compression.
 *
 * Note there's an extra offset applied (directmap_base_pdx) on top of the
 * regular PDX compression logic. Its purpose is to skip over the initial
 * range of non-existing memory, should there be one.
 *
 * @param ma Machine address
 * @return Virtual address mapped to `ma`
 */
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT((mfn_to_pdx(maddr_to_mfn(ma)) - directmap_base_pdx) <
           (DIRECTMAP_SIZE >> PAGE_SHIFT));
    return (void *)(XENHEAP_VIRT_START -
                    (directmap_base_pdx << PAGE_SHIFT) +
                    maddr_to_directmapoff(ma));
}
#endif

/*
 * Translate a guest virtual address to a machine address.
 * Return the fault information if the translation has failed else 0.
 */
static inline uint64_t gvirt_to_maddr(vaddr_t va, paddr_t *pa,
                                      unsigned int flags)
{
    uint64_t par = gva_to_ma_par(va, flags);
    if ( par & PAR_F )
        return par;
    *pa = (par & PADDR_MASK & PAGE_MASK) | ((unsigned long) va & ~PAGE_MASK);
    return 0;
}

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define __virt_to_mfn(va) (virt_to_maddr(va) >> PAGE_SHIFT)
#define __mfn_to_virt(mfn) (maddr_to_virt((paddr_t)(mfn) << PAGE_SHIFT))

/*
 * We define non-underscored wrappers for above conversion functions.
 * These are overriden in various source files while underscored version
 * remain intact.
 */
#define virt_to_mfn(va)     __virt_to_mfn(va)
#define mfn_to_virt(mfn)    __mfn_to_virt(mfn)

/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *virt_to_page(const void *v)
{
    unsigned long va = (unsigned long)v;
    unsigned long pdx;

    ASSERT(va >= XENHEAP_VIRT_START);
    ASSERT(va < directmap_virt_end);

    pdx = (va - XENHEAP_VIRT_START) >> PAGE_SHIFT;
    pdx += mfn_to_pdx(directmap_mfn_start);
    return frame_table + pdx - frametable_base_pdx;
}

static inline void *page_to_virt(const struct page_info *pg)
{
    return mfn_to_virt(mfn_x(page_to_mfn(pg)));
}

struct page_info *get_page_from_gva(struct vcpu *v, vaddr_t va,
                                    unsigned long flags);

/*
 * Arm does not have an M2P, but common code expects a handful of
 * M2P-related defines and functions. Provide dummy versions of these.
 */
#define INVALID_M2P_ENTRY        (~0UL)
#define SHARED_M2P_ENTRY         (~0UL - 1UL)
#define SHARED_M2P(_e)           ((_e) == SHARED_M2P_ENTRY)

/* Xen always owns P2M on ARM */
#define set_gpfn_from_mfn(mfn, pfn) do { (void) (mfn), (void)(pfn); } while (0)
#define mfn_to_gfn(d, mfn) ((void)(d), _gfn(mfn_x(mfn)))

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg);

#define domain_set_alloc_bitsize(d) ((void)0)
#define domain_clamp_alloc_bitsize(d, b) (b)

unsigned long domain_get_maximum_gpfn(struct domain *d);

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void);

int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order);

extern bool get_page_nr(struct page_info *page, const struct domain *domain,
                        unsigned long nr);
extern void put_page_nr(struct page_info *page, unsigned long nr);

extern void put_page_type(struct page_info *page);
static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

void clear_and_clean_page(struct page_info *page);

unsigned int arch_get_dma_bitsize(void);

/*
 * All accesses to the GFN portion of type_info field should always be
 * protected by the P2M lock. In case when it is not feasible to satisfy
 * that requirement (risk of deadlock, lock inversion, etc) it is important
 * to make sure that all non-protected updates to this field are atomic.
 */
static inline gfn_t page_get_xenheap_gfn(const struct page_info *p)
{
    gfn_t gfn_ = _gfn(ACCESS_ONCE(p->u.inuse.type_info) & PGT_gfn_mask);

    ASSERT(is_xen_heap_page(p));

    return gfn_eq(gfn_, PGT_INVALID_XENHEAP_GFN) ? INVALID_GFN : gfn_;
}

static inline void page_set_xenheap_gfn(struct page_info *p, gfn_t gfn)
{
    gfn_t gfn_ = gfn_eq(gfn, INVALID_GFN) ? PGT_INVALID_XENHEAP_GFN : gfn;
    unsigned long x, nx, y = p->u.inuse.type_info;

    ASSERT(is_xen_heap_page(p));

    do {
        x = y;
        nx = (x & ~PGT_gfn_mask) | gfn_x(gfn_);
    } while ( (y = cmpxchg(&p->u.inuse.type_info, x, nx)) != x );
}

#endif /*  __ARCH_ARM_MM__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
