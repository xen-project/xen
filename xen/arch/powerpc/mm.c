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
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/shadow.h>
#include <xen/kernel.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <asm/misc.h>
#include <asm/init.h>
#include <asm/page.h>

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                                  \
  printk("DOM%u: (file=mm.c, line=%d) " _f "\n",            \
         current->domain->domain_id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

/* Frame table and its size in pages. */
struct page_info *frame_table;
unsigned long frame_table_size;
unsigned long max_page;
unsigned long total_pages;

int create_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    panic("%s called\n", __func__);
    return 1;
}

int destroy_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    panic("%s called\n", __func__);
    return 1;
}

int steal_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    panic("%s called\n", __func__);
    return 1;
}

void put_page_type(struct page_info *page)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

    do {
        x  = y;
        nx = x - 1;

        ASSERT((x & PGT_count_mask) != 0);

        /*
         * The page should always be validated while a reference is held. The 
         * exception is during domain destruction, when we forcibly invalidate 
         * page-table pages if we detect a referential loop.
         * See domain.c:relinquish_list().
         */
        ASSERT((x & PGT_validated) || 
               test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags));

        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            /* Record TLB information for flush later. */
            page->tlbflush_timestamp = tlbflush_current_time();
        }
        else if ( unlikely((nx & (PGT_pinned|PGT_type_mask|PGT_count_mask)) == 
                           (PGT_pinned | 1)) )
        {
            /* Page is now only pinned. Make the back pointer mutable again. */
            nx |= PGT_va_mutable;
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct page_info *page, unsigned long type)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

 again:
    do {
        x  = y;
        nx = x + 1;
        if ( unlikely((nx & PGT_count_mask) == 0) )
        {
            MEM_LOG("Type count overflow on pfn %lx", page_to_mfn(page));
            return 0;
        }
        else if ( unlikely((x & PGT_count_mask) == 0) )
        {
            if ( (x & (PGT_type_mask|PGT_va_mask)) != type )
            {
                if ( (x & PGT_type_mask) != (type & PGT_type_mask) )
                {
                    /*
                     * On type change we check to flush stale TLB
                     * entries. This may be unnecessary (e.g., page
                     * was GDT/LDT) but those circumstances should be
                     * very rare.
                     */
                    cpumask_t mask =
                        page_get_owner(page)->domain_dirty_cpumask;
                    tlbflush_filter(mask, page->tlbflush_timestamp);

                    if ( unlikely(!cpus_empty(mask)) )
                    {
                        perfc_incrc(need_flush_tlb_flush);
                        flush_tlb_mask(mask);
                    }
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_va_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else
        {
            if ( unlikely((x & (PGT_type_mask|PGT_va_mask)) != type) )
            {
                if ( unlikely((x & PGT_type_mask) != (type & PGT_type_mask) ) )
                {
                    return 0;
                }
                else if ( (x & PGT_va_mask) == PGT_va_mutable )
                {
                    /* The va backpointer is mutable, hence we update it. */
                    nx &= ~PGT_va_mask;
                    nx |= type; /* we know the actual type is correct */
                }
                else if ( (type & PGT_va_mask) != PGT_va_mutable )
                {
                    ASSERT((type & PGT_va_mask) != (x & PGT_va_mask));

                    /* This table is possibly mapped at multiple locations. */
                    nx &= ~PGT_va_mask;
                    nx |= PGT_va_unknown;
                }
            }
            if ( unlikely(!(x & PGT_validated)) )
            {
                /* Someone else is updating validation of this page. Wait... */
                while ( (y = page->u.inuse.type_info) == x )
                    cpu_relax();
                goto again;
            }
        }
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );

    if ( unlikely(!(nx & PGT_validated)) )
    {
        /* Noone else is updating simultaneously. */
        __set_bit(_PGT_validated, &page->u.inuse.type_info);
    }

    return 1;
}

void __init init_frametable(void)
{
    unsigned long p;

    frame_table_size = PFN_UP(max_page * sizeof(struct page_info));

    p = alloc_boot_pages(min(frame_table_size, 4UL << 20), 1);
    if (p == 0)
        panic("Not enough memory for frame table\n");

    frame_table = (struct page_info *)(p << PAGE_SHIFT);
    frame_table_size = (frame_table_size + PAGE_SIZE - 1) & PAGE_MASK;

    memset(frame_table, 0, frame_table_size);
}

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    printk("%s: no PPC specific memory ops\n", __func__);
    return -ENOSYS;
}

void clear_page(void *page)
{
    if (on_mambo()) {
        extern void *mambo_memset(void *,int ,__kernel_size_t);
        mambo_memset(page, 0, PAGE_SIZE);
    } else {
        memset(page, 0, PAGE_SIZE);
    }
}

extern void copy_page(void *dp, void *sp)
{
    if (on_mambo()) {
        extern void *mambo_memcpy(void *,const void *,__kernel_size_t);
        mambo_memcpy(dp, sp, PAGE_SIZE);
    } else {
        memcpy(dp, sp, PAGE_SIZE);
    }
}

static int mfn_in_hole(ulong mfn)
{
    /* totally cheating */
    if (mfn >= (0xf0000000UL >> PAGE_SHIFT) &&
        mfn < (((1UL << 32) - 1) >> PAGE_SHIFT))
        return 1;

    return 0;
}

static uint add_extent(struct domain *d, struct page_info *pg, uint order)
{
    struct page_extents *pe;

    pe = xmalloc(struct page_extents);
    if (pe == NULL)
        return 0;

    pe->pg = pg;
    pe->order = order;
    pe->pfn = page_to_mfn(pg);

    list_add_tail(&pe->pe_list, &d->arch.extent_list);

    return pe->pfn;
}

void free_extents(struct domain *d)
{
    /* we just need to free the memory behind list */
    struct list_head *list;
    struct list_head *ent;
    struct list_head *next;

    list = &d->arch.extent_list;
    ent = list->next;

    while (ent != list) {
        next = ent->next;
        xfree(ent);
        ent = next;
    }
}

uint allocate_extents(struct domain *d, uint nrpages, uint rma_nrpages)
{
    uint ext_order;
    uint ext_nrpages;
    uint total_nrpages;
    struct page_info *pg;

    ext_order = cpu_extent_order();
    ext_nrpages = 1 << ext_order;

    total_nrpages = rma_nrpages;

    /* We only allocate in nr_extsz chunks so if you are not divisible
     * you get more than you asked for */
    while (total_nrpages < nrpages) {
        pg = alloc_domheap_pages(d, ext_order, 0);
        if (pg == NULL)
            return total_nrpages;

        if (add_extent(d, pg, ext_order) == 0) {
            free_domheap_pages(pg, ext_order);
            return total_nrpages;
        }
        total_nrpages += ext_nrpages;
    }

    return total_nrpages;
}
        
int allocate_rma(struct domain *d, unsigned int order_pages)
{
    ulong rma_base;
    ulong rma_sz = rma_size(order_pages);

    d->arch.rma_page = alloc_domheap_pages(d, order_pages, 0);
    if (d->arch.rma_page == NULL) {
        DPRINTK("Could not allocate order_pages=%d RMA for domain %u\n",
                order_pages, d->domain_id);
        return -ENOMEM;
    }
    d->arch.rma_order = order_pages;

    rma_base = page_to_maddr(d->arch.rma_page);
    BUG_ON(rma_base & (rma_sz - 1)); /* check alignment */

    /* XXX */
    printk("clearing RMA: 0x%lx[0x%lx]\n", rma_base, rma_sz);
    memset((void *)rma_base, 0, rma_sz);

    return 0;
}

ulong pfn2mfn(struct domain *d, long pfn, int *type)
{
    ulong rma_base_mfn = page_to_mfn(d->arch.rma_page);
    ulong rma_size_mfn = 1UL << d->arch.rma_order;
    struct page_extents *pe;

    if (pfn < rma_size_mfn) {
        if (type)
            *type = PFN_TYPE_RMA;
        return pfn + rma_base_mfn;
    }

    if (test_bit(_DOMF_privileged, &d->domain_flags) &&
        mfn_in_hole(pfn)) {
        if (type)
            *type = PFN_TYPE_IO;
        return pfn;
    }

    /* quick tests first */
    list_for_each_entry (pe, &d->arch.extent_list, pe_list) {
        uint end_pfn = pe->pfn + (1 << pe->order);

        if (pfn >= pe->pfn && pfn < end_pfn) {
            if (type)
                *type = PFN_TYPE_LOGICAL;
            return page_to_mfn(pe->pg) + (pfn - pe->pfn);
        }
    }

    /* This hack allows dom0 to map all memory, necessary to
     * initialize domU state. */
    if (test_bit(_DOMF_privileged, &d->domain_flags)) {
        if (type)
            *type = PFN_TYPE_REMOTE;
        return pfn;
    }

    BUG();
    return 0;
}

void guest_physmap_add_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn)
{
    printk("%s(%d, 0x%lx, 0x%lx)\n", __func__, d->domain_id, gpfn, mfn);
}
void guest_physmap_remove_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn)
{
    panic("%s\n", __func__);
}
void shadow_drop_references(
    struct domain *d, struct page_info *page)
{
}
