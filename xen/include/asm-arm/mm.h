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

 /* Count of uses of this frame as its current type. */
#define PGT_count_width   PG_shift(2)
#define PGT_count_mask    ((1UL<<PGT_count_width)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated    PG_shift(1)
#define PGC_allocated     PG_mask(1, 1)
  /* Page is Xen heap? */
#define _PGC_xen_heap     PG_shift(2)
#define PGC_xen_heap      PG_mask(1, 2)
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

/* Count of references to this frame. */
#define PGC_count_width   PG_shift(9)
#define PGC_count_mask    ((1UL<<PGC_count_width)-1)

/*
 * Page needs to be scrubbed. Since this bit can only be set on a page that is
 * free (i.e. in PGC_state_free) we can reuse PGC_allocated bit.
 */
#define _PGC_need_scrub   _PGC_allocated
#define PGC_need_scrub    PGC_allocated

extern mfn_t xenheap_mfn_start, xenheap_mfn_end;
extern vaddr_t xenheap_virt_end;
#ifdef CONFIG_ARM_64
extern vaddr_t xenheap_virt_start;
#endif

#ifdef CONFIG_ARM_32
#define is_xen_heap_page(page) is_xen_heap_mfn(page_to_mfn(page))
#define is_xen_heap_mfn(mfn) ({                                 \
    unsigned long _mfn = (mfn);                                 \
    (_mfn >= mfn_x(xenheap_mfn_start) &&                        \
     _mfn < mfn_x(xenheap_mfn_end));                            \
})
#else
#define is_xen_heap_page(page) ((page)->count_info & PGC_xen_heap)
#define is_xen_heap_mfn(mfn) \
    (mfn_valid(_mfn(mfn)) && is_xen_heap_page(__mfn_to_page(mfn)))
#endif

#define is_xen_fixed_mfn(mfn)                                   \
    ((pfn_to_paddr(mfn) >= virt_to_maddr(&_start)) &&       \
     (pfn_to_paddr(mfn) <= virt_to_maddr(&_end)))

#define page_get_owner(_p)    (_p)->v.inuse.domain
#define page_set_owner(_p,_d) ((_p)->v.inuse.domain = (_d))

#define maddr_get_owner(ma)   (page_get_owner(maddr_to_page((ma))))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
extern void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly);
extern void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly);

#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)
/* PDX of the first page in the frame table. */
extern unsigned long frametable_base_pdx;

extern unsigned long max_page;
extern unsigned long total_pages;

#define PDX_GROUP_SHIFT SECOND_SHIFT

/* Boot-time pagetable setup */
extern void setup_pagetables(unsigned long boot_phys_offset, paddr_t xen_paddr);
/* Map FDT in boot pagetable */
extern void *early_fdt_map(paddr_t fdt_paddr);
/* Remove early mappings */
extern void remove_early_mappings(void);
/* Allocate and initialise pagetables for a secondary CPU. Sets init_ttbr to the
 * new page table */
extern int init_secondary_pagetables(int cpu);
/* Switch secondary CPUS to its own pagetables and finalise MMU setup */
extern void mmu_init_secondary_cpu(void);
/* Set up the xenheap: up to 1GB of contiguous, always-mapped memory.
 * Base must be 32MB aligned and size a multiple of 32MB. */
extern void setup_xenheap_mappings(unsigned long base_mfn, unsigned long nr_mfns);
/* Map a frame table to cover physical addresses ps through pe */
extern void setup_frametable_mappings(paddr_t ps, paddr_t pe);
/* Map a 4k page in a fixmap entry */
extern void set_fixmap(unsigned map, mfn_t mfn, unsigned attributes);
/* Remove a mapping from a fixmap entry */
extern void clear_fixmap(unsigned map);
/* map a physical range in virtual memory */
void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned attributes);

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
#define __mfn_to_page(mfn)  (frame_table + (pfn_to_pdx(mfn) - frametable_base_pdx))
#define __page_to_mfn(pg)   pdx_to_pfn((unsigned long)((pg) - frame_table) + frametable_base_pdx)

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma) __mfn_to_page((ma) >> PAGE_SHIFT)
#define page_to_maddr(pg) ((paddr_t)__page_to_mfn(pg) << PAGE_SHIFT)

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))
#define paddr_to_pdx(pa)    pfn_to_pdx(paddr_to_pfn(pa))
#define gfn_to_gaddr(gfn)   pfn_to_paddr(gfn_x(gfn))
#define gaddr_to_gfn(ga)    _gfn(paddr_to_pfn(ga))
#define mfn_to_maddr(mfn)   pfn_to_paddr(mfn_x(mfn))
#define maddr_to_mfn(ma)    _mfn(paddr_to_pfn(ma))
#define vmap_to_mfn(va)     paddr_to_pfn(virt_to_maddr((vaddr_t)va))
#define vmap_to_page(va)    mfn_to_page(vmap_to_mfn(va))

/* Page-align address and convert to frame number format */
#define paddr_to_pfn_aligned(paddr)    paddr_to_pfn(PAGE_ALIGN(paddr))

static inline paddr_t __virt_to_maddr(vaddr_t va)
{
    uint64_t par = va_to_par(va);
    return (par & PADDR_MASK & PAGE_MASK) | (va & ~PAGE_MASK);
}
#define virt_to_maddr(va)   __virt_to_maddr((vaddr_t)(va))

#ifdef CONFIG_ARM_32
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT(is_xen_heap_mfn(ma >> PAGE_SHIFT));
    ma -= mfn_to_maddr(xenheap_mfn_start);
    return (void *)(unsigned long) ma + XENHEAP_VIRT_START;
}
#else
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT(pfn_to_pdx(ma >> PAGE_SHIFT) < (DIRECTMAP_SIZE >> PAGE_SHIFT));
    return (void *)(XENHEAP_VIRT_START -
                    mfn_to_maddr(xenheap_mfn_start) +
                    ((ma & ma_va_bottom_mask) |
                     ((ma & ma_top_mask) >> pfn_pdx_hole_shift)));
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
#define mfn_to_page(mfn)    __mfn_to_page(mfn)
#define page_to_mfn(pg)     __page_to_mfn(pg)
#define virt_to_mfn(va)     __virt_to_mfn(va)
#define mfn_to_virt(mfn)    __mfn_to_virt(mfn)

/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *virt_to_page(const void *v)
{
    unsigned long va = (unsigned long)v;
    unsigned long pdx;

    ASSERT(va >= XENHEAP_VIRT_START);
    ASSERT(va < xenheap_virt_end);

    pdx = (va - XENHEAP_VIRT_START) >> PAGE_SHIFT;
    pdx += pfn_to_pdx(mfn_x(xenheap_mfn_start));
    return frame_table + pdx - frametable_base_pdx;
}

static inline void *page_to_virt(const struct page_info *pg)
{
    return mfn_to_virt(page_to_mfn(pg));
}

struct page_info *get_page_from_gva(struct vcpu *v, vaddr_t va,
                                    unsigned long flags);

/*
 * The MPT (machine->physical mapping table) is an array of word-sized
 * values, indexed on machine frame number. It is expected that guest OSes
 * will use it to store a "physical" frame number to give the appearance of
 * contiguous (or near contiguous) physical memory.
 */
#undef  machine_to_phys_mapping
#define machine_to_phys_mapping  ((unsigned long *)RDWR_MPT_VIRT_START)
#define INVALID_M2P_ENTRY        (~0UL)
#define VALID_M2P(_e)            (!((_e) & (1UL<<(BITS_PER_LONG-1))))
#define SHARED_M2P_ENTRY         (~0UL - 1UL)
#define SHARED_M2P(_e)           ((_e) == SHARED_M2P_ENTRY)

#define _set_gpfn_from_mfn(mfn, pfn) ({                        \
    struct domain *d = page_get_owner(__mfn_to_page(mfn));     \
    if(d && (d == dom_cow))                                    \
        machine_to_phys_mapping[(mfn)] = SHARED_M2P_ENTRY;     \
    else                                                       \
        machine_to_phys_mapping[(mfn)] = (pfn);                \
    })

static inline void put_gfn(struct domain *d, unsigned long gfn) {}
static inline int relinquish_shared_pages(struct domain *d)
{
    return 0;
}

/* Xen always owns P2M on ARM */
#define set_gpfn_from_mfn(mfn, pfn) do { (void) (mfn), (void)(pfn); } while (0)
#define mfn_to_gmfn(_d, mfn)  (mfn)


/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg);

#define domain_set_alloc_bitsize(d) ((void)0)
#define domain_clamp_alloc_bitsize(d, b) (b)

unsigned long domain_get_maximum_gpfn(struct domain *d);

extern struct domain *dom_xen, *dom_io, *dom_cow;

#define memguard_guard_stack(_p)       ((void)0)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void);

int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order);

extern void put_page_type(struct page_info *page);
static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

void clear_and_clean_page(struct page_info *page);

#endif /*  __ARCH_ARM_MM__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
