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
#include <asm/misc.h>
#include <asm/system.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>

#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)    ((void)0)

extern unsigned long xenheap_phys_end;
#define IS_XEN_HEAP_FRAME(_pfn) (page_to_mfn(_pfn) < xenheap_phys_end)

/*
 * Per-page-frame information.
 * 
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct list_head list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->u.free.order)
#define PRtype_info "016lx"

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
            struct domain *_domain;
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
#define PGT_none            (0<<29) /* no special uses of this page */
#define PGT_l1_page_table   (1<<29) /* using this page as an L1 page table? */
#define PGT_l2_page_table   (2<<29) /* using this page as an L2 page table? */
#define PGT_l3_page_table   (3<<29) /* using this page as an L3 page table? */
#define PGT_l4_page_table   (4<<29) /* using this page as an L4 page table? */
#define PGT_gdt_page        (5<<29) /* using this page in a GDT? */
#define PGT_ldt_page        (6<<29) /* using this page in an LDT? */
#define PGT_writable_page   (7<<29) /* has writable mappings of this page? */
#define PGT_type_mask       (7<<29) /* Bits 29-31. */
 /* Has this page been validated for use as its current type? */
#define _PGT_validated      28
#define PGT_validated       (1U<<_PGT_validated)
 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned         27
#define PGT_pinned          (1U<<_PGT_pinned)
 /* The 10 most significant bits of virt address if this is a page table. */
#define PGT_va_shift        17
#define PGT_va_mask         (((1U<<10)-1)<<PGT_va_shift)
 /* Is the back pointer still mutable (i.e. not fixed yet)? */
#define PGT_va_mutable      (((1U<<10)-1)<<PGT_va_shift)
 /* Is the back pointer unknown (e.g., p.t. is mapped at multiple VAs)? */
#define PGT_va_unknown      (((1U<<10)-2)<<PGT_va_shift)
 /* 17-bit count of uses of this frame as its current type. */
#define PGT_count_mask      ((1U<<17)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated      31
#define PGC_allocated       (1U<<_PGC_allocated)
 /* 31-bit count of references to this frame. */
#define PGC_count_mask      ((1U<<31)-1)

static inline void put_page(struct page_info *page)
{
#if 0
    int count;

    count = atomic_dec_return(&page->count_info);

    if ( unlikely((count & PGC_count_mask) == 0) )
        free_domheap_page(page);
#else
    trap();
#endif
}

static inline int get_page(struct page_info *page,
                           struct domain *domain)
{
#if 0
    int count;

    count = atomic_inc_return(&page->count_info);

    if (((count & PGC_count_mask) == 0) ||      /* Count overflow? */
            ((count & PGC_count_mask) == 1) ||  /* Wasn't allocated? */
            ((page->domain != domain)))         /* Wrong owner? */
    {
        atomic_dec(&page->count_info);
        return 0;
    }

#else
    trap();
#endif
    return 1;
}

static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    u32 type)
{
    trap();
    return 1;
}

static inline int page_is_removable(struct page_info *page)
{
    return ((page->count_info & PGC_count_mask) == 1);
}

int get_page_type(struct page_info *page, u32 type);

#define set_machinetophys(_mfn, _pfn) (trap(), 0)

extern void synchronise_pagetables(unsigned long cpu_mask);

static inline void put_page_and_type(struct page_info *page)
{
    trap();
}

/* XXX don't know what this is for */
typedef struct {
    void (*enable)(struct domain *);
    void (*disable)(struct domain *);
} vm_assist_info_t;
extern vm_assist_info_t vm_assist_info[];

#define page_get_owner(_p)    ((_p)->u.inuse._domain)
#define page_set_owner(_p,_d) ((_p)->u.inuse._domain = _d)

#define share_xen_page_with_guest(p, d, r) do { } while (0)
#define share_xen_page_with_privileged_guests(p, r) do { } while (0)

extern struct page_info *frame_table;
extern unsigned long frame_table_size;
extern unsigned long max_page;
extern unsigned long total_pages;
void init_frametable(void);

/* hope that accesses to this will fail spectacularly */
#define machine_to_phys_mapping ((u32 *)-1UL)

extern int update_grant_va_mapping(unsigned long va,
                                   unsigned long val,
                                   struct domain *,
                                   struct vcpu *);

extern void put_page_type(struct page_info *page);

#define PFN_TYPE_RMA 0
#define PFN_TYPE_LOGICAL 1
#define PFN_TYPE_IO 2
extern ulong pfn2mfn(struct domain *d, long mfn, int *type);

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

extern int steal_page(struct domain *d, struct page_info *page,
                        unsigned int memflags);

#define sync_pagetable_state(d) ((void)0)

#endif
