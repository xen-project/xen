/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_PPC_MM_H
#define _ASM_PPC_MM_H

#include <public/xen.h>
#include <xen/pdx.h>
#include <xen/types.h>
#include <asm/config.h>
#include <asm/page-bits.h>
#include <asm/page.h>

void setup_initial_pagetables(void);

#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))
#define paddr_to_pdx(pa)  mfn_to_pdx(maddr_to_mfn(pa))
#define gfn_to_gaddr(gfn) pfn_to_paddr(gfn_x(gfn))
#define gaddr_to_gfn(ga)  _gfn(paddr_to_pfn(ga))
#define mfn_to_maddr(mfn) pfn_to_paddr(mfn_x(mfn))
#define maddr_to_mfn(ma)  _mfn(paddr_to_pfn(ma))
#define vmap_to_mfn(va)   maddr_to_mfn(virt_to_maddr((vaddr_t)va))
#define vmap_to_page(va)  mfn_to_page(vmap_to_mfn(va))

#define virt_to_maddr(va) ((paddr_t)((vaddr_t)(va) & PADDR_MASK))
#define maddr_to_virt(pa) ((void *)((paddr_t)(pa) | XEN_VIRT_START))

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define __virt_to_mfn(va) (virt_to_maddr(va) >> PAGE_SHIFT)
#define __mfn_to_virt(mfn) (maddr_to_virt((paddr_t)(mfn) << PAGE_SHIFT))

/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *virt_to_page(const void *v)
{
    BUG_ON("unimplemented");
    return NULL;
}

#define virt_to_mfn(va)     __virt_to_mfn(va)
#define mfn_to_virt(mfn)    __mfn_to_virt(mfn)

#define PG_shift(idx)   (BITS_PER_LONG - (idx))
#define PG_mask(x, idx) (x ## UL << PG_shift(idx))

#define PGT_none          PG_mask(0, 1)  /* no special uses of this page   */
#define PGT_writable_page PG_mask(1, 1)  /* has writable mappings?         */
#define PGT_type_mask     PG_mask(1, 1)  /* Bits 31 or 63.                 */

 /* 2-bit count of uses of this frame as its current type. */
#define PGT_count_mask    PG_mask(3, 3)

/* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated    PG_shift(1)
#define PGC_allocated     PG_mask(1, 1)
/* Page is Xen heap? */
#define _PGC_xen_heap     PG_shift(2)
#define PGC_xen_heap      PG_mask(1, 2)
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

#define is_xen_heap_page(page) ((page)->count_info & PGC_xen_heap)
#define is_xen_heap_mfn(mfn) \
    (mfn_valid(mfn) && is_xen_heap_page(mfn_to_page(mfn)))

#define is_xen_fixed_mfn(mfn)                                   \
    ((mfn_to_maddr(mfn) >= virt_to_maddr((vaddr_t)_start)) &&           \
     (mfn_to_maddr(mfn) <= virt_to_maddr((vaddr_t)_end - 1)))

#define page_get_owner(_p)    (_p)->v.inuse.domain
#define page_set_owner(_p,_d) ((_p)->v.inuse.domain = (_d))

/* TODO: implement */
#define mfn_valid(mfn) ({ (void) (mfn); 0; })

#define domain_set_alloc_bitsize(d) ((void)(d))
#define domain_clamp_alloc_bitsize(d, b) (b)

#define PFN_ORDER(pfn_) ((pfn_)->v.free.order)

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
            /* Owner of this page (NULL if page is anonymous). */
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
        uint32_t tlbflush_timestamp;
    };
    uint64_t pad;
};


#define FRAMETABLE_VIRT_START  (XEN_VIRT_START + GB(32))
#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)

/* PDX of the first page in the frame table. */
extern unsigned long frametable_base_pdx;

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)                                            \
    (frame_table + (mfn_to_pdx(mfn) - frametable_base_pdx))
#define page_to_mfn(pg)                                             \
    pdx_to_mfn((unsigned long)((pg) - frame_table) + frametable_base_pdx)

static inline void *page_to_virt(const struct page_info *pg)
{
    return mfn_to_virt(mfn_x(page_to_mfn(pg)));
}

/*
 * Common code requires get_page_type and put_page_type.
 * We don't care about typecounts so we just do the minimum to make it
 * happy.
 */
static inline int get_page_type(struct page_info *page, unsigned long type)
{
    return 1;
}

static inline void put_page_type(struct page_info *page)
{
    return;
}

/* TODO */
static inline bool get_page_nr(struct page_info *page, const struct domain *domain,
                        unsigned long nr)
{
    BUG_ON("unimplemented");
}
static inline void put_page_nr(struct page_info *page, unsigned long nr)
{
    BUG_ON("unimplemented");
}

static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

/*
 * PPC does not have an M2P, but common code expects a handful of
 * M2P-related defines and functions. Provide dummy versions of these.
 */
#define INVALID_M2P_ENTRY        (~0UL)
#define SHARED_M2P_ENTRY         (~0UL - 1UL)
#define SHARED_M2P(_e)           ((_e) == SHARED_M2P_ENTRY)

#define set_gpfn_from_mfn(mfn, pfn) BUG_ON("unimplemented")
#define mfn_to_gfn(d, mfn) ({ BUG_ON("unimplemented"); _gfn(0); })

#define PDX_GROUP_SHIFT XEN_PT_SHIFT_LVL_3

static inline unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    BUG_ON("unimplemented");
    return 0;
}

static inline long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    BUG_ON("unimplemented");
    return 0;
}

static inline unsigned int arch_get_dma_bitsize(void)
{
    return 32; /* TODO */
}

/*
 * On PPC, all the RAM is currently direct mapped in Xen.
 * Hence return always true.
 */
static inline bool arch_mfns_in_directmap(unsigned long mfn, unsigned long nr)
{
    return true;
}

#endif /* _ASM_PPC_MM_H */
