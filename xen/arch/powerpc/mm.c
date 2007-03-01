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
#include <asm/init.h>
#include <asm/page.h>
#include <asm/string.h>
#include <public/arch-powerpc.h>

#ifdef VERBOSE
#define MEM_LOG(_f, _a...)                                  \
  printk("DOM%u: (file=mm.c, line=%d) " _f "\n",            \
         current->domain->domain_id , __LINE__ , ## _a )
#else
#define MEM_LOG(_f, _a...) ((void)0)
#endif

/* Frame table and its size in pages. */
struct page_info *frame_table;
unsigned long max_page;
unsigned long total_pages;

void __init init_frametable(void)
{
    unsigned long p;
    unsigned long nr_pages;
    int i;

    nr_pages = PFN_UP(max_page * sizeof(struct page_info));

    p = alloc_boot_pages(nr_pages, 1);
    if (p == 0)
        panic("Not enough memory for frame table\n");

    frame_table = (struct page_info *)(p << PAGE_SHIFT);
    for (i = 0; i < nr_pages; i += 1)
        clear_page((void *)((p + i) << PAGE_SHIFT));
}

void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly)
{
    if ( page_get_owner(page) == d )
        return;

    /* this causes us to leak pages in the Domain and reuslts in
     * Zombie domains, I think we are missing a piece, until we find
     * it we disable the following code */
    set_gpfn_from_mfn(page_to_mfn(page), INVALID_M2P_ENTRY);

    spin_lock(&d->page_alloc_lock);

    /* The incremented type count pins as writable or read-only. */
    page->u.inuse.type_info  = (readonly ? PGT_none : PGT_writable_page);
    page->u.inuse.type_info |= PGT_validated | 1;

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT(page->count_info == 0);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !test_bit(_DOMF_dying, &d->domain_flags) )
    {
        page->count_info |= PGC_allocated | 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
        list_add_tail(&page->list, &d->xenpage_list);
    }

    spin_unlock(&d->page_alloc_lock);
}

void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly)
{
        unimplemented();
}

static ulong foreign_to_mfn(struct domain *d, ulong pfn)
{

    pfn -= 1UL << cpu_foreign_map_order();

    BUG_ON(pfn >= d->arch.foreign_mfn_count);

    return d->arch.foreign_mfns[pfn];
}

static int set_foreign(struct domain *d, ulong pfn, ulong mfn)
{
    pfn -= 1UL << cpu_foreign_map_order();

    BUG_ON(pfn >= d->arch.foreign_mfn_count);
    d->arch.foreign_mfns[pfn] = mfn;

    return 0;
}

static int create_grant_va_mapping(
    unsigned long va, unsigned long frame, struct vcpu *v)
{
    if (v->domain->domain_id != 0) {
        printk("only Dom0 can map a grant entry\n");
        BUG();
        return GNTST_permission_denied;
    }
    set_foreign(v->domain, va >> PAGE_SHIFT, frame);
    return GNTST_okay;
}

static int destroy_grant_va_mapping(
    unsigned long addr, unsigned long frame, struct domain *d)
{
    if (d->domain_id != 0) {
        printk("only Dom0 can map a grant entry\n");
        BUG();
        return GNTST_permission_denied;
    }
    set_foreign(d, addr >> PAGE_SHIFT, ~0UL);
    return GNTST_okay;
}

int create_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    if (flags & GNTMAP_application_map) {
        printk("%s: GNTMAP_application_map not supported\n", __func__);
        BUG();
        return GNTST_general_error;
    }
    if (flags & GNTMAP_contains_pte) {
        printk("%s: GNTMAP_contains_pte not supported\n", __func__);
        BUG();
        return GNTST_general_error;
    }
    return create_grant_va_mapping(addr, frame, current);
}

int destroy_grant_host_mapping(
    unsigned long addr, unsigned long frame, unsigned int flags)
{
    if (flags & GNTMAP_contains_pte) {
        printk("%s: GNTMAP_contains_pte not supported\n", __func__);
        BUG();
        return GNTST_general_error;
    }

    /* may have force the remove here */
    return destroy_grant_va_mapping(addr, frame, current->domain);
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
    }
    while ( unlikely((y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x) );
}


int get_page_type(struct page_info *page, unsigned long type)
{
    unsigned long nx, x, y = page->u.inuse.type_info;

    ASSERT(!(type & ~PGT_type_mask));

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
            if ( (x & PGT_type_mask) != type )
            {
                /*
                 * On type change we check to flush stale TLB entries. This 
                 * may be unnecessary (e.g., page was GDT/LDT) but those 
                 * circumstances should be very rare.
                 */
                cpumask_t mask =
                    page_get_owner(page)->domain_dirty_cpumask;
                tlbflush_filter(mask, page->tlbflush_timestamp);

                if ( unlikely(!cpus_empty(mask)) )
                {
                    perfc_incrc(need_flush_tlb_flush);
                    flush_tlb_mask(mask);
                }

                /* We lose existing type, back pointer, and validity. */
                nx &= ~(PGT_type_mask | PGT_validated);
                nx |= type;

                /* No special validation needed for writable pages. */
                /* Page tables and GDT/LDT need to be scanned for validity. */
                if ( type == PGT_writable_page )
                    nx |= PGT_validated;
            }
        }
        else if ( unlikely((x & PGT_type_mask) != type) )
        {
            return 0;
        }
        else if ( unlikely(!(x & PGT_validated)) )
        {
            /* Someone else is updating validation of this page. Wait... */
            while ( (y = page->u.inuse.type_info) == x )
                cpu_relax();
            goto again;
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

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    printk("%s: no PPC specific memory ops\n", __func__);
    return -ENOSYS;
}

extern void copy_page(void *dp, void *sp)
{
    if (on_systemsim()) {
        systemsim_memcpy(dp, sp, PAGE_SIZE);
    } else {
        memcpy(dp, sp, PAGE_SIZE);
    }
}

/* XXX should probably replace with faster data structure */
static uint add_extent(struct domain *d, struct page_info *pg, uint order)
{
    struct page_extents *pe;

    pe = xmalloc(struct page_extents);
    if (pe == NULL)
        return -ENOMEM;

    pe->pg = pg;
    pe->order = order;

    list_add_tail(&pe->pe_list, &d->arch.extent_list);

    return 0;
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

        if (add_extent(d, pg, ext_order) < 0) {
            free_domheap_pages(pg, ext_order);
            return total_nrpages;
        }
        total_nrpages += ext_nrpages;
    }

    return total_nrpages;
}

int allocate_rma(struct domain *d, unsigned int order)
{
    struct vcpu *v;
    ulong rma_base;
    ulong rma_sz;
    int i;

    if (d->arch.rma_page)
        return -EINVAL;

    d->arch.rma_page = alloc_domheap_pages(d, order, 0);
    if (d->arch.rma_page == NULL) {
        gdprintk(XENLOG_INFO, "Could not allocate order=%d RMA for domain %u\n",
                order, d->domain_id);
        return -ENOMEM;
    }
    d->arch.rma_order = order;

    rma_base = page_to_maddr(d->arch.rma_page);
    rma_sz = rma_size(d->arch.rma_order);

    BUG_ON(rma_base & (rma_sz - 1)); /* check alignment */

    printk("allocated RMA for Dom[%d]: 0x%lx[0x%lx]\n",
           d->domain_id, rma_base, rma_sz);

    for (i = 0; i < (1 << d->arch.rma_order); i++ ) {
        /* Add in any extra CPUs that need flushing because of this page. */
        d->arch.rma_page[i].count_info |= PGC_page_RMA;
        clear_page((void *)page_to_maddr(&d->arch.rma_page[i]));
    }

    /* shared_info uses last page of RMA */
    d->shared_info = (shared_info_t *) (rma_base + rma_sz - PAGE_SIZE);

    /* if there are already running vcpus, adjust v->vcpu_info */
    /* XXX untested */
    for_each_vcpu(d, v) {
        v->vcpu_info = &d->shared_info->vcpu_info[v->vcpu_id];
    }

    return 0;
}

void free_rma_check(struct page_info *page)
{
    if (test_bit(_PGC_page_RMA, &page->count_info) &&
        !test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags))
        panic("Attempt to free an RMA page: 0x%lx\n", page_to_mfn(page));
}

ulong pfn2mfn(struct domain *d, ulong pfn, int *type)
{
    ulong rma_base_mfn = page_to_mfn(d->arch.rma_page);
    ulong rma_size_mfn = 1UL << d->arch.rma_order;
    struct page_extents *pe;
    ulong mfn = INVALID_MFN;
    int t = PFN_TYPE_NONE;
    ulong foreign_map_pfn = 1UL << cpu_foreign_map_order();

    /* quick tests first */
    if (pfn & foreign_map_pfn) {
        t = PFN_TYPE_FOREIGN;
        mfn = foreign_to_mfn(d, pfn);
    } else if (pfn >= max_page && pfn <
	       (max_page + nr_grant_frames(d->grant_table))) {
        /* XXX access d->grant_table->nr_grant_frames without lock.
         * Currently on powerpc dynamic expanding grant table is
         * inhibited by setting max_nr_grant_frames = INITIAL_NR_GRANT_FRAMES
         * so that this access is safe.
         */
        /* Its a grant table access */
        t = PFN_TYPE_GNTTAB;
        mfn = gnttab_shared_mfn(d, d->grant_table, (pfn - max_page));
    } else if (d->is_privileged && cpu_io_mfn(pfn)) {
        t = PFN_TYPE_IO;
        mfn = pfn;
    } else {
        if (pfn < rma_size_mfn) {
            t = PFN_TYPE_RMA;
            mfn = pfn + rma_base_mfn;
        } else {
            ulong cur_pfn = rma_size_mfn;

            list_for_each_entry (pe, &d->arch.extent_list, pe_list) {
                uint pe_pages = 1UL << pe->order;
                uint end_pfn = cur_pfn + pe_pages;

                if (pfn >= cur_pfn && pfn < end_pfn) {
                    t = PFN_TYPE_LOGICAL;
                    mfn = page_to_mfn(pe->pg) + (pfn - cur_pfn);
                    break;
                }
                cur_pfn += pe_pages;
            }
        }
#ifdef DEBUG
        if (t != PFN_TYPE_NONE &&
            (d->domain_flags & DOMF_dying) &&
            page_get_owner(mfn_to_page(mfn)) != d) {
            printk("%s: page type: %d owner Dom[%d]:%p expected Dom[%d]:%p\n",
                   __func__, t,
                   page_get_owner(mfn_to_page(mfn))->domain_id,
                   page_get_owner(mfn_to_page(mfn)),
                   d->domain_id, d);
            BUG();
        }
#endif
    }

    if (t == PFN_TYPE_NONE) {
        /* This hack allows dom0 to map all memory, necessary to
         * initialize domU state. */
        if (d->is_privileged && mfn_valid(pfn)) {
            struct page_info *pg;

            /* page better be allocated to some domain but not the caller */
            pg = mfn_to_page(pfn);
            if (!(pg->count_info & PGC_allocated))
                panic("Foreign page: 0x%lx is not owned by any domain\n",
                      mfn);
            if (page_get_owner(pg) == d)
                panic("Foreign page: 0x%lx is owned by this domain\n",
                      mfn);
                
            t = PFN_TYPE_FOREIGN;
            mfn = pfn;
        }
    }

    if (mfn == INVALID_MFN) {
        printk("%s: Dom[%d] pfn 0x%lx is not a valid page\n",
               __func__, d->domain_id, pfn);
    }

    if (type)
        *type = t;

    return mfn;
}

unsigned long mfn_to_gmfn(struct domain *d, unsigned long mfn)
{
    struct page_extents *pe;
    ulong cur_pfn;
    ulong gnttab_mfn;
    ulong rma_mfn;

    /* XXX access d->grant_table->nr_grant_frames without lock.
     * Currently on powerpc dynamic expanding grant table is
     * inhibited by setting max_nr_grant_frames = INITIAL_NR_GRANT_FRAMES
     * so that this access is safe.
     */
    /* grant? */
    gnttab_mfn = gnttab_shared_mfn(d, d->grant_table, 0);
    if (mfn >= gnttab_mfn && mfn <
	(gnttab_mfn + nr_grant_frames(d->grant_table)))
        return max_page + (mfn - gnttab_mfn);

    /* IO? */
    if (d->is_privileged && cpu_io_mfn(mfn))
        return mfn;

    rma_mfn = page_to_mfn(d->arch.rma_page);
    if (mfn >= rma_mfn &&
        mfn < (rma_mfn + (1 << d->arch.rma_order)))
        return mfn - rma_mfn;

    /* Extent? */
    cur_pfn = 1UL << d->arch.rma_order;
    list_for_each_entry (pe, &d->arch.extent_list, pe_list) {
        uint pe_pages = 1UL << pe->order;
        uint b_mfn = page_to_mfn(pe->pg);
        uint e_mfn = b_mfn + pe_pages;

        if (mfn >= b_mfn && mfn < e_mfn) {
            return cur_pfn + (mfn - b_mfn);
        }
        cur_pfn += pe_pages;
    }
    return INVALID_M2P_ENTRY;
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

int arch_domain_add_extent(struct domain *d, struct page_info *page, int order)
{
    if (add_extent(d, page, order) < 0)
        return -ENOMEM;
    return 0;
}
