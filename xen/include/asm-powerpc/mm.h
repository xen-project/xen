/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_MM_H_
#define _ASM_MM_H_

#include <public/xen.h>
#include <xen/list.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/misc.h>
#include <asm/system.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>

#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)    ((void)0)

extern unsigned long xenheap_phys_end;

/*
 * Per-page-frame information.
 * 
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct list_head list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->u.free.order)

/* XXX copy-and-paste job; re-examine me */
struct page_info
{
    /* Each frame can be threaded onto a doubly-linked list. */
    struct list_head list;

    /* Timestamp from 'TLB clock', used to reduce need for safety flushes. */
    u32 tlbflush_timestamp;

    /* Reference count and various PGC_xxx flags and fields. */
    unsigned long count_info;

    /* Context-dependent fields follow... */
    union {

        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Owner of this page (NULL if page is anonymous). */
            u32 _domain;
            /* Type reference count and various PGT_xxx flags and fields. */
            unsigned long type_info;
        } inuse;

        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        struct {
            /* Mask of possibly-tainted TLBs. */
            cpumask_t cpumask;
            /* Order-size of the free chunk this page is the head of. */
            u8 order;
        } free;

    } u;

};

struct page_extents {
    /* Each frame can be threaded onto a doubly-linked list. */
    struct list_head pe_list;

    /* page extent */
    struct page_info *pg;
    uint order;
    ulong pfn;
};

 /* The following page types are MUTUALLY EXCLUSIVE. */
#define PGT_none            (0<<29) /* no special uses of this page */
#define PGT_RMA             (1<<29) /* This page is an RMA page? */
#define PGT_writable_page   (7<<29) /* has writable mappings of this page? */
#define PGT_type_mask       (7<<29) /* Bits 29-31. */

 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         28
#define PGT_pinned          (1U<<_PGT_pinned)
 /* Has this page been validated for use as its current type? */
#define _PGT_validated      27
#define PGT_validated       (1U<<_PGT_validated)

 /* The 27 most significant bits of virt address if this is a page table. */
#define PGT_va_shift        32
#define PGT_va_mask         ((unsigned long)((1U<<28)-1)<<PGT_va_shift)
 /* Is the back pointer still mutable (i.e. not fixed yet)? */
#define PGT_va_mutable      ((unsigned long)((1U<<28)-1)<<PGT_va_shift)
 /* Is the back pointer unknown (e.g., p.t. is mapped at multiple VAs)? */
#define PGT_va_unknown      ((unsigned long)((1U<<28)-2)<<PGT_va_shift)

 /* 16-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<16)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* Set on a *guest* page to mark it out-of-sync with its shadow */
#define _PGC_out_of_sync     30
#define PGC_out_of_sync     (1U<<_PGC_out_of_sync)
 /* Set when is using a page as a page table */
#define _PGC_page_table      29
#define PGC_page_table      (1U<<_PGC_page_table)
/* Set when using page for RMA */
#define _PGC_page_RMA      28
#define PGC_page_RMA      (1U<<_PGC_page_RMA)
 /* 29-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<28)-1)

#define IS_XEN_HEAP_FRAME(_pfn) (page_to_maddr(_pfn) < xenheap_phys_end)

static inline struct domain *unpickle_domptr(u32 _domain)
{ return ((_domain == 0) || (_domain & 1)) ? NULL : __va(_domain); }

static inline u32 pickle_domptr(struct domain *domain)
{ return (domain == NULL) ? 0 : (u32)__pa(domain); }

#define PRtype_info "016lx"/* should only be used for printk's */

#define page_get_owner(_p)    (unpickle_domptr((_p)->u.inuse._domain))
#define page_set_owner(_p,_d) ((_p)->u.inuse._domain = pickle_domptr(_d))

extern struct page_info *frame_table;
extern unsigned long max_page;
extern unsigned long total_pages;
void init_frametable(void);
void free_rma_check(struct page_info *page);

static inline void put_page(struct page_info *page)
{
    u32 nx, x, y = page->count_info;

    do {
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) ) {
        /* RMA pages can only be released while the domain is dying */
        free_rma_check(page);
        free_domheap_page(page);
    }
}

static inline int get_page(struct page_info *page,
                           struct domain *domain)
{
    u32 x, nx, y = page->count_info;
    u32 d, nd = page->u.inuse._domain;
    u32 _domain = pickle_domptr(domain);

    do {
        x  = y;
        nx = x + 1;
        d  = nd;
        if ( unlikely((x & PGC_count_mask) == 0) ||  /* Not allocated? */
             unlikely((nx & PGC_count_mask) == 0) || /* Count overflow? */
             unlikely(d != _domain) )                /* Wrong owner? */
        {
            return 0;
        }
        y = cmpxchg(&page->count_info, x, nx);
    }
    while ( unlikely(y != x) );

    return 1;
}

extern void put_page_type(struct page_info *page);
extern int  get_page_type(struct page_info *page, unsigned long type);

static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    unsigned long type)
{
    int rc = get_page(page, domain);

    if ( likely(rc) && unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        rc = 0;
    }

    return rc;
}

static inline int page_is_removable(struct page_info *page)
{
    return ((page->count_info & PGC_count_mask) == 1);
}

extern void synchronise_pagetables(unsigned long cpu_mask);

/* XXX don't know what this is for */
typedef struct {
    void (*enable)(struct domain *);
    void (*disable)(struct domain *);
} vm_assist_info_t;
extern vm_assist_info_t vm_assist_info[];

#define share_xen_page_with_guest(p, d, r) do { } while (0)
#define share_xen_page_with_privileged_guests(p, r) do { } while (0)

/* hope that accesses to this will fail spectacularly */
#define machine_to_phys_mapping ((u32 *)-1UL)

extern int update_grant_va_mapping(unsigned long va,
                                   unsigned long val,
                                   struct domain *,
                                   struct vcpu *);

#define INVALID_MFN (~0UL)
#define PFN_TYPE_NONE 0
#define PFN_TYPE_RMA 1
#define PFN_TYPE_LOGICAL 2
#define PFN_TYPE_IO 3
#define PFN_TYPE_FOREIGN 4

extern ulong pfn2mfn(struct domain *d, ulong pfn, int *type);

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);

/* XXX implement me? */
#define set_gpfn_from_mfn(mfn, pfn) do { } while (0)
/* XXX only used for debug print right now... */
#define get_gpfn_from_mfn(mfn) (mfn)

static inline unsigned long gmfn_to_mfn(struct domain *d, unsigned long gmfn)
{
	return pfn2mfn(d, gmfn, NULL);
}

#define mfn_to_gmfn(_d, mfn) (mfn)

extern int allocate_rma(struct domain *d, unsigned int order_pages);
extern uint allocate_extents(struct domain *d, uint nrpages, uint rma_nrpages);
extern void free_extents(struct domain *d);

extern int steal_page(struct domain *d, struct page_info *page,
                        unsigned int memflags);

#endif
