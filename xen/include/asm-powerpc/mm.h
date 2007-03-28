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
 * Copyright IBM Corp. 2005, 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */

#ifndef _ASM_MM_H_
#define _ASM_MM_H_

#include <public/xen.h>
#include <xen/list.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/system.h>
#include <asm/flushtlb.h>
#include <asm/page.h>
#include <asm/debugger.h>

#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)    ((void)0)

extern unsigned long xenheap_phys_end;
extern int boot_of_mem_avail(int pos, ulong *start, ulong *end);

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

 /* The following page types are MUTUALLY EXCLUSIVE. */
#define PGT_none            (0UL<<29) /* no special uses of this page */
#define PGT_RMA             (1UL<<29) /* This page is an RMA page? */
#define PGT_writable_page   (7UL<<29) /* has writable mappings of this page? */
#define PGT_type_mask       (7UL<<29) /* Bits 29-31. */

 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         28
#define PGT_pinned          (1UL<<_PGT_pinned)
 /* Has this page been validated for use as its current type? */
#define _PGT_validated      27
#define PGT_validated       (1UL<<_PGT_validated)

 /* 16-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1UL<<16)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1UL<<_PGC_allocated)
 /* Set on a *guest* page to mark it out-of-sync with its shadow */
#define _PGC_out_of_sync     30
#define PGC_out_of_sync     (1UL<<_PGC_out_of_sync)
 /* Set when is using a page as a page table */
#define _PGC_page_table      29
#define PGC_page_table      (1UL<<_PGC_page_table)
/* Set when using page for RMA */
#define _PGC_page_RMA      28
#define PGC_page_RMA      (1UL<<_PGC_page_RMA)
 /* 29-bit count of references to this frame. */
#define PGC_count_mask      ((1UL<<28)-1)

#define IS_XEN_HEAP_FRAME(_pfn) (page_to_maddr(_pfn) < xenheap_phys_end)

static inline struct domain *unpickle_domptr(u32 _domain)
{ return ((_domain == 0) || (_domain & 1)) ? NULL : __va(_domain); }

static inline u32 pickle_domptr(struct domain *domain)
{ return (domain == NULL) ? 0 : (u32)__pa(domain); }

#define PRtype_info "016lx"/* should only be used for printk's */

#define page_get_owner(_p)    (unpickle_domptr((_p)->u.inuse._domain))
#define page_set_owner(_p,_d) ((_p)->u.inuse._domain = pickle_domptr(_d))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
extern void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly);
extern void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly);

extern struct page_info *frame_table;
extern unsigned long max_page;
extern unsigned long total_pages;
void init_frametable(void);
void init_machine_to_phys_table(void);
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

extern void synchronise_pagetables(unsigned long cpu_mask);

/* XXX don't know what this is for */
typedef struct {
    void (*enable)(struct domain *);
    void (*disable)(struct domain *);
} vm_assist_info_t;
extern vm_assist_info_t vm_assist_info[];

extern unsigned long *machine_phys_mapping;
#define machine_to_phys_mapping  (machine_phys_mapping)
#define INVALID_M2P_ENTRY        (~0UL)

#define set_gpfn_from_mfn(mfn, pfn) (machine_to_phys_mapping[(mfn)] = (pfn))
#define get_gpfn_from_mfn(mfn)      (machine_to_phys_mapping[(mfn)])

extern unsigned long mfn_to_gmfn(struct domain *d, unsigned long mfn);

extern unsigned long paddr_to_maddr(unsigned long paddr);

/* INVALID_MFN can be any value that fails mfn_valid(). */
#define INVALID_MFN (~0U)

#define PFN_TYPE_NONE 0
#define PFN_TYPE_LOGICAL 2
#define PFN_TYPE_IO 3
#define PFN_TYPE_FOREIGN 4
#define PFN_TYPE_GNTTAB 5

extern ulong pfn2mfn(struct domain *d, ulong pfn, int *type);
static inline unsigned long gmfn_to_mfn(struct domain *d, unsigned long gmfn)
{
    int mtype;
    ulong mfn;
    
    mfn = pfn2mfn(d, gmfn, &mtype);
    if (mfn != INVALID_MFN) {
        switch (mtype) {
        case PFN_TYPE_LOGICAL:
            break;
        default:
            WARN();
            mfn = INVALID_MFN;
            break;
        }
    }
    return mfn;
}

extern int update_grant_va_mapping(unsigned long va,
                                   unsigned long val,
                                   struct domain *,
                                   struct vcpu *);

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);

extern int allocate_rma(struct domain *d, unsigned int order_pages);
extern uint allocate_extents(struct domain *d, uint nrpages, uint rma_nrpages);

extern int steal_page(struct domain *d, struct page_info *page,
                        unsigned int memflags);

/* XXX these just exist until we can stop #including x86 code */
#define access_ok(addr,size) 1
#define array_access_ok(addr,count,size) 1

#define domain_clamp_alloc_bitsize(d, b) (b)

#define domain_get_maximum_gpfn(d) (-ENOSYS)

#endif
