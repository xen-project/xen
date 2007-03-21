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
 *          Ryan Harper <ryanh@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/shadow.h>
#include <xen/kernel.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <asm/init.h>
#include <asm/page.h>
#include <asm/platform.h>
#include <asm/string.h>
#include <asm/platform.h>
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

/* machine to phys mapping to used by all domains */
unsigned long *machine_phys_mapping;

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

/* Array of PFNs, indexed by MFN. */
void __init init_machine_to_phys_table(void)
{
    unsigned long p;
    unsigned long nr_pages;
    int i;

    nr_pages = PFN_UP(max_page * sizeof(unsigned long));

    p = alloc_boot_pages(nr_pages, 1);
    if (p == 0)
        panic("Not enough memory for machine phys mapping table\n");

    machine_phys_mapping = (unsigned long *)(p << PAGE_SHIFT);
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

/* Allocate (rma_nrpages - nrpages) more memory for domain in proper size. */
uint allocate_extents(struct domain *d, uint nrpages, uint rma_nrpages)
{
    struct page_info *pg;
    ulong mfn;
    ulong gpfn = rma_nrpages; /* starting PFN at end of RMA */
    uint ext_order;
    uint ext_nrpages;
    uint total_nrpages;
    int i;

    ext_order = cpu_extent_order();
    ext_nrpages = 1 << ext_order;

    total_nrpages = rma_nrpages;

    /* We only allocate in nr_extsz chunks so if you are not divisible
     * you get more than you asked for. */
    while (total_nrpages < nrpages) {
        pg = alloc_domheap_pages(d, ext_order, 0);
        if (pg == NULL)
            return total_nrpages;

        /* Build p2m mapping for newly allocated extent. */
        mfn = page_to_mfn(pg);
        for (i = 0; i < (1 << ext_order); i++)
            guest_physmap_add_page(d, gpfn + i, mfn + i);

        /* Bump starting PFN by extent size pages. */
        gpfn += ext_nrpages;

        total_nrpages += ext_nrpages;
    }

    return total_nrpages;
}

int allocate_rma(struct domain *d, unsigned int order)
{
    struct vcpu *v;
    ulong rma_base;
    ulong rma_sz;
    ulong mfn;
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

    mfn = page_to_mfn(d->arch.rma_page);

    for (i = 0; i < (1 << d->arch.rma_order); i++ ) {
        d->arch.rma_page[i].count_info |= PGC_page_RMA;
        clear_page((void *)page_to_maddr(&d->arch.rma_page[i]));

        /* Set up p2m mapping for RMA. */
        guest_physmap_add_page(d, i, mfn+i);
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
    if (test_bit(_PGC_page_RMA, &page->count_info)) {
        if (!test_bit(_DOMF_dying, &page_get_owner(page)->domain_flags)) {
            panic("Attempt to free an RMA page: 0x%lx\n", page_to_mfn(page));
        } else {
            clear_bit(_PGC_page_RMA, &page->count_info);
        }
    }
}

ulong pfn2mfn(struct domain *d, ulong pfn, int *type)
{
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
    } else if (d->is_privileged && platform_io_mfn(pfn)) {
        t = PFN_TYPE_IO;
        mfn = pfn;
    } else {
        if (pfn < d->arch.p2m_entries) {
            t = PFN_TYPE_LOGICAL;
            mfn = d->arch.p2m[pfn];
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
    struct page_info *pg = mfn_to_page(mfn);
    ulong gnttab_mfn;

    /* is this our mfn? */
    if (page_get_owner(pg) != d)
        return INVALID_M2P_ENTRY;

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
    if (d->is_privileged && platform_io_mfn(mfn))
        return mfn;

    /* check m2p table */
    return get_gpfn_from_mfn(mfn);
}

/* NB: caller holds d->page_alloc lock, sets d->max_pages = new_max */
int guest_physmap_max_mem_pages(struct domain *d, unsigned long new_max_pages)
{
    u32 *p2m_array = NULL;
    u32 *p2m_old = NULL;
    ulong i;

    /* XXX We probably could, but right now we don't shrink the p2m array.
     * NB: d->max_pages >= d->arch.p2m_entries */
    if (new_max_pages < d->max_pages) {
        printk("Can't shrink DOM%d max memory pages\n", d->domain_id);
        return -EINVAL;
    }

    /* Allocate one u32 per page. */
    p2m_array = xmalloc_array(u32, new_max_pages);
    if (p2m_array == NULL)
        return -ENOMEM;

    /* Copy old mappings into new array. */
    if (d->arch.p2m != NULL) {
        /* XXX This could take a long time; we should use a continuation. */
        memcpy(p2m_array, d->arch.p2m, d->arch.p2m_entries * sizeof(u32));
        p2m_old = d->arch.p2m;
    }

    /* Mark new mfns as invalid. */
    for (i = d->arch.p2m_entries; i < new_max_pages; i++)
        p2m_array[i] = INVALID_MFN;

    /* Set new p2m pointer and size. */
    d->arch.p2m = p2m_array;
    d->arch.p2m_entries = new_max_pages;

    /* Free old p2m array if present. */
    if (p2m_old)
        xfree(p2m_old);

    return 0;
}

void guest_physmap_add_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn)
{
    if (page_get_owner(mfn_to_page(mfn)) != d) {
        printk("Won't map foreign MFN 0x%lx for DOM%d\n", mfn, d->domain_id);
        return;
    }

    /* Check that pfn is within guest table. */
    if (gpfn >= d->arch.p2m_entries) {
        printk("Won't map invalid PFN 0x%lx for DOM%d\n", gpfn, d->domain_id);
        return;
    }

    /* Warn if there is an existing mapping. */
    /* XXX: probably shouldn't let this happen, but
       current interface doesn't throw errors.  =( */
    if (d->arch.p2m[gpfn] != INVALID_MFN)
        printk("Ack! PFN aliased. PFN%lx, old MFN=%x, new MFN=%lx\n",
                gpfn, d->arch.p2m[gpfn], mfn);

    /* PFN and MFN ok, map in p2m table. */
    d->arch.p2m[gpfn] = mfn;

    /* Map in m2p table. */
    set_gpfn_from_mfn(mfn, gpfn);
}

void guest_physmap_remove_page(
    struct domain *d, unsigned long gpfn, unsigned long mfn)
{
    if (page_get_owner(mfn_to_page(mfn)) != d) {
        printk("Won't unmap foreign MFN 0x%lx for DOM%d\n", mfn, d->domain_id);
        return;
    }

    /* check that pfn is within guest table */
    if (gpfn >= d->arch.p2m_entries) {
        printk("Won't unmap invalid PFN 0x%lx for DOM%d\n", gpfn, d->domain_id);
        return;
    }

    /* PFN and MFN ok, unmap from p2m table. */
    d->arch.p2m[gpfn] = INVALID_MFN;

    /* Unmap from m2p table. */
    set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
}

void shadow_drop_references(
    struct domain *d, struct page_info *page)
{
}
