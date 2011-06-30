/******************************************************************************
 * arch/x86/mm/p2m.c
 *
 * physical-to-machine mappings for automatically-translated domains.
 *
 * Parts of this code are Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h> /* ept_p2m_init() */
#include <xen/iommu.h>
#include <asm/mem_event.h>
#include <public/mem_event.h>
#include <asm/mem_sharing.h>
#include <xen/event.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

#include "mm-locks.h"

/* turn on/off 1GB host page table support for hap, default on */
static bool_t __read_mostly opt_hap_1gb = 1;
boolean_param("hap_1gb", opt_hap_1gb);

static bool_t __read_mostly opt_hap_2mb = 1;
boolean_param("hap_2mb", opt_hap_2mb);

/* Printouts */
#define P2M_PRINTK(_f, _a...)                                \
    debugtrace_printk("p2m: %s(): " _f, __func__, ##_a)
#define P2M_ERROR(_f, _a...)                                 \
    printk("pg error: %s(): " _f, __func__, ##_a)
#if P2M_DEBUGGING
#define P2M_DEBUG(_f, _a...)                                 \
    debugtrace_printk("p2mdebug: %s(): " _f, __func__, ##_a)
#else
#define P2M_DEBUG(_f, _a...) do { (void)(_f); } while(0)
#endif


/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))


/* Init the datastructures for later use by the p2m code */
static void p2m_initialise(struct domain *d, struct p2m_domain *p2m)
{
    memset(p2m, 0, sizeof(*p2m));
    mm_lock_init(&p2m->lock);
    INIT_LIST_HEAD(&p2m->np2m_list);
    INIT_PAGE_LIST_HEAD(&p2m->pages);
    INIT_PAGE_LIST_HEAD(&p2m->pod.super);
    INIT_PAGE_LIST_HEAD(&p2m->pod.single);

    p2m->domain = d;
    p2m->default_access = p2m_access_rwx;

    p2m->cr3 = CR3_EADDR;
    cpus_clear(p2m->p2m_dirty_cpumask);

    if ( hap_enabled(d) && (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) )
        ept_p2m_init(p2m);
    else
        p2m_pt_init(p2m);

    return;
}

static int
p2m_init_nestedp2m(struct domain *d)
{
    uint8_t i;
    struct p2m_domain *p2m;

    mm_lock_init(&d->arch.nested_p2m_lock);
    for (i = 0; i < MAX_NESTEDP2M; i++) {
        d->arch.nested_p2m[i] = p2m = xmalloc(struct p2m_domain);
        if (p2m == NULL)
            return -ENOMEM;
        p2m_initialise(d, p2m);
        p2m->write_p2m_entry = nestedp2m_write_p2m_entry;
        list_add(&p2m->np2m_list, &p2m_get_hostp2m(d)->np2m_list);
    }

    return 0;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m;

    p2m_get_hostp2m(d) = p2m = xmalloc(struct p2m_domain);
    if ( p2m == NULL )
        return -ENOMEM;
    p2m_initialise(d, p2m);

    /* Must initialise nestedp2m unconditionally
     * since nestedhvm_enabled(d) returns false here.
     * (p2m_init runs too early for HVM_PARAM_* options)
     */
    return p2m_init_nestedp2m(d);
}

void p2m_change_entry_type_global(struct domain *d,
                                  p2m_type_t ot, p2m_type_t nt)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_lock(p2m);
    p2m->change_entry_type_global(p2m, ot, nt);
    p2m_unlock(p2m);
}

int set_p2m_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
                  unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    struct domain *d = p2m->domain;
    unsigned long todo = 1ul << page_order;
    unsigned int order;
    int rc = 1;

    ASSERT(p2m_locked_by_me(p2m));

    while ( todo )
    {
        if ( hap_enabled(d) )
            order = ( (((gfn | mfn_x(mfn) | todo) & ((1ul << 18) - 1)) == 0) &&
                      hvm_hap_has_1gb(d) && opt_hap_1gb ) ? 18 :
                      ((((gfn | mfn_x(mfn) | todo) & ((1ul << 9) - 1)) == 0) &&
                      hvm_hap_has_2mb(d) && opt_hap_2mb) ? 9 : 0;
        else
            order = 0;

        if ( !p2m->set_entry(p2m, gfn, mfn, order, p2mt, p2ma) )
            rc = 0;
        gfn += 1ul << order;
        if ( mfn_x(mfn) != INVALID_MFN )
            mfn = _mfn(mfn_x(mfn) + (1ul << order));
        todo -= 1ul << order;
    }

    return rc;
}

struct page_info *p2m_alloc_ptp(struct p2m_domain *p2m, unsigned long type)
{
    struct page_info *pg;

    ASSERT(p2m);
    ASSERT(p2m->domain);
    ASSERT(p2m->domain->arch.paging.alloc_page);
    pg = p2m->domain->arch.paging.alloc_page(p2m->domain);
    if (pg == NULL)
        return NULL;

    page_list_add_tail(pg, &p2m->pages);
    pg->u.inuse.type_info = type | 1 | PGT_validated;

    return pg;
}

void p2m_free_ptp(struct p2m_domain *p2m, struct page_info *pg)
{
    ASSERT(pg);
    ASSERT(p2m);
    ASSERT(p2m->domain);
    ASSERT(p2m->domain->arch.paging.free_page);

    page_list_del(pg, &p2m->pages);
    p2m->domain->arch.paging.free_page(p2m->domain, pg);

    return;
}

// Allocate a new p2m table for a domain.
//
// The structure of the p2m table is that of a pagetable for xen (i.e. it is
// controlled by CONFIG_PAGING_LEVELS).
//
// Returns 0 for success or -errno.
//
int p2m_alloc_table(struct p2m_domain *p2m)
{
    mfn_t mfn = _mfn(INVALID_MFN);
    struct page_info *page, *p2m_top;
    unsigned int page_count = 0;
    unsigned long gfn = -1UL;
    struct domain *d = p2m->domain;

    p2m_lock(p2m);

    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) != 0 )
    {
        P2M_ERROR("p2m already allocated for this domain\n");
        p2m_unlock(p2m);
        return -EINVAL;
    }

    P2M_PRINTK("allocating p2m table\n");

    p2m_top = p2m_alloc_ptp(p2m,
#if CONFIG_PAGING_LEVELS == 4
        PGT_l4_page_table
#else
        PGT_l3_page_table
#endif
        );

    if ( p2m_top == NULL )
    {
        p2m_unlock(p2m);
        return -ENOMEM;
    }

    p2m->phys_table = pagetable_from_mfn(page_to_mfn(p2m_top));

    if ( hap_enabled(d) )
        iommu_share_p2m_table(d);

    P2M_PRINTK("populating p2m table\n");

    /* Initialise physmap tables for slot zero. Other code assumes this. */
    if ( !set_p2m_entry(p2m, 0, _mfn(INVALID_MFN), 0,
                        p2m_invalid, p2m->default_access) )
        goto error;

    if ( !p2m_is_nestedp2m(p2m) )
    {
        /* Copy all existing mappings from the page list and m2p */
        spin_lock(&p2m->domain->page_alloc_lock);
        page_list_for_each(page, &p2m->domain->page_list)
        {
            mfn = page_to_mfn(page);
            gfn = get_gpfn_from_mfn(mfn_x(mfn));
            /* Pages should not be shared that early */
            ASSERT(gfn != SHARED_M2P_ENTRY);
            page_count++;
            if (
#ifdef __x86_64__
                (gfn != 0x5555555555555555L)
#else
                (gfn != 0x55555555L)
#endif
                && gfn != INVALID_M2P_ENTRY
                && !set_p2m_entry(p2m, gfn, mfn, 0, p2m_ram_rw, p2m->default_access) )
                goto error_unlock;
        }
        spin_unlock(&p2m->domain->page_alloc_lock);
    }

    P2M_PRINTK("p2m table initialised (%u pages)\n", page_count);
    p2m_unlock(p2m);
    return 0;

error_unlock:
    spin_unlock(&p2m->domain->page_alloc_lock);
 error:
    P2M_PRINTK("failed to initialize p2m table, gfn=%05lx, mfn=%"
               PRI_mfn "\n", gfn, mfn_x(mfn));
    p2m_unlock(p2m);
    return -ENOMEM;
}

void p2m_teardown(struct p2m_domain *p2m)
/* Return all the p2m pages to Xen.
 * We know we don't have any extra mappings to these pages */
{
    struct page_info *pg;
    struct domain *d = p2m->domain;
#ifdef __x86_64__
    unsigned long gfn;
    p2m_type_t t;
    p2m_access_t a;
    mfn_t mfn;
#endif

    if (p2m == NULL)
        return;

#ifdef __x86_64__
    for ( gfn=0; gfn < p2m->max_mapped_pfn; gfn++ )
    {
        mfn = gfn_to_mfn_type_p2m(p2m, gfn, &t, &a, p2m_query);
        if ( mfn_valid(mfn) && (t == p2m_ram_shared) )
        {
            ASSERT(!p2m_is_nestedp2m(p2m));
            BUG_ON(mem_sharing_unshare_page(d, gfn, MEM_SHARING_DESTROY_GFN));
        }

    }
#endif

    p2m_lock(p2m);

    p2m->phys_table = pagetable_null();

    while ( (pg = page_list_remove_head(&p2m->pages)) )
        d->arch.paging.free_page(d, pg);
    p2m_unlock(p2m);
}

static void p2m_teardown_nestedp2m(struct domain *d)
{
    uint8_t i;

    for (i = 0; i < MAX_NESTEDP2M; i++) {
        xfree(d->arch.nested_p2m[i]);
        d->arch.nested_p2m[i] = NULL;
    }
}

void p2m_final_teardown(struct domain *d)
{
    /* Iterate over all p2m tables per domain */
    xfree(d->arch.p2m);
    d->arch.p2m = NULL;

    /* We must teardown unconditionally because
     * we initialise them unconditionally.
     */
    p2m_teardown_nestedp2m(d);
}


static void
p2m_remove_page(struct p2m_domain *p2m, unsigned long gfn, unsigned long mfn,
                unsigned int page_order)
{
    unsigned long i;
    mfn_t mfn_return;
    p2m_type_t t;
    p2m_access_t a;

    if ( !paging_mode_translate(p2m->domain) )
    {
        if ( need_iommu(p2m->domain) )
            for ( i = 0; i < (1 << page_order); i++ )
                iommu_unmap_page(p2m->domain, mfn + i);
        return;
    }

    P2M_DEBUG("removing gfn=%#lx mfn=%#lx\n", gfn, mfn);

    if ( mfn_valid(_mfn(mfn)) )
    {
        for ( i = 0; i < (1UL << page_order); i++ )
        {
            mfn_return = p2m->get_entry(p2m, gfn + i, &t, &a, p2m_query);
            if ( !p2m_is_grant(t) )
                set_gpfn_from_mfn(mfn+i, INVALID_M2P_ENTRY);
            ASSERT( !p2m_is_valid(t) || mfn + i == mfn_x(mfn_return) );
        }
    }
    set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), page_order, p2m_invalid, p2m->default_access);
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                          unsigned long mfn, unsigned int page_order)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_lock(p2m);
    audit_p2m(p2m, 1);
    p2m_remove_page(p2m, gfn, mfn, page_order);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);
}

int
guest_physmap_add_entry(struct domain *d, unsigned long gfn,
                        unsigned long mfn, unsigned int page_order, 
                        p2m_type_t t)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long i, ogfn;
    p2m_type_t ot;
    mfn_t omfn;
    int pod_count = 0;
    int rc = 0;

    if ( !paging_mode_translate(d) )
    {
        if ( need_iommu(d) && t == p2m_ram_rw )
        {
            for ( i = 0; i < (1 << page_order); i++ )
            {
                rc = iommu_map_page(
                    d, mfn + i, mfn + i, IOMMUF_readable|IOMMUF_writable);
                if ( rc != 0 )
                {
                    while ( i-- > 0 )
                        iommu_unmap_page(d, mfn + i);
                    return rc;
                }
            }
        }
        return 0;
    }

    rc = p2m_gfn_check_limit(d, gfn, page_order);
    if ( rc != 0 )
        return rc;

    p2m_lock(p2m);
    audit_p2m(p2m, 0);

    P2M_DEBUG("adding gfn=%#lx mfn=%#lx\n", gfn, mfn);

    /* First, remove m->p mappings for existing p->m mappings */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        omfn = gfn_to_mfn_query(d, gfn + i, &ot);
        if ( p2m_is_grant(ot) )
        {
            /* Really shouldn't be unmapping grant maps this way */
            domain_crash(d);
            p2m_unlock(p2m);
            return -EINVAL;
        }
        else if ( p2m_is_ram(ot) )
        {
            ASSERT(mfn_valid(omfn));
            set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);
        }
        else if ( ot == p2m_populate_on_demand )
        {
            /* Count how man PoD entries we'll be replacing if successful */
            pod_count++;
        }
    }

    /* Then, look for m->p mappings for this range and deal with them */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        if ( page_get_owner(mfn_to_page(_mfn(mfn + i))) != d )
            continue;
        ogfn = mfn_to_gfn(d, _mfn(mfn+i));
        if (
#ifdef __x86_64__
            (ogfn != 0x5555555555555555L)
#else
            (ogfn != 0x55555555L)
#endif
            && (ogfn != INVALID_M2P_ENTRY)
            && (ogfn != gfn + i) )
        {
            /* This machine frame is already mapped at another physical
             * address */
            P2M_DEBUG("aliased! mfn=%#lx, old gfn=%#lx, new gfn=%#lx\n",
                      mfn + i, ogfn, gfn + i);
            omfn = gfn_to_mfn_query(d, ogfn, &ot);
            if ( p2m_is_ram(ot) )
            {
                ASSERT(mfn_valid(omfn));
                P2M_DEBUG("old gfn=%#lx -> mfn %#lx\n",
                          ogfn , mfn_x(omfn));
                if ( mfn_x(omfn) == (mfn + i) )
                    p2m_remove_page(p2m, ogfn, mfn + i, 0);
            }
        }
    }

    /* Now, actually do the two-way mapping */
    if ( mfn_valid(_mfn(mfn)) ) 
    {
        if ( !set_p2m_entry(p2m, gfn, _mfn(mfn), page_order, t, p2m->default_access) )
            rc = -EINVAL;
        if ( !p2m_is_grant(t) )
        {
            for ( i = 0; i < (1UL << page_order); i++ )
                set_gpfn_from_mfn(mfn+i, gfn+i);
        }
    }
    else
    {
        gdprintk(XENLOG_WARNING, "Adding bad mfn to p2m map (%#lx -> %#lx)\n",
                 gfn, mfn);
        if ( !set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), page_order, 
                            p2m_invalid, p2m->default_access) )
            rc = -EINVAL;
        else
        {
            p2m->pod.entry_count -= pod_count; /* Lock: p2m */
            BUG_ON(p2m->pod.entry_count < 0);
        }
    }

    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    return rc;
}


/* Modify the p2m type of a single gfn from ot to nt, returning the 
 * entry's previous type.  Resets the access permissions. */
p2m_type_t p2m_change_type(struct domain *d, unsigned long gfn, 
                           p2m_type_t ot, p2m_type_t nt)
{
    p2m_type_t pt;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));

    p2m_lock(p2m);

    mfn = gfn_to_mfn_query(d, gfn, &pt);
    if ( pt == ot )
        set_p2m_entry(p2m, gfn, mfn, 0, nt, p2m->default_access);

    p2m_unlock(p2m);

    return pt;
}

/* Modify the p2m type of a range of gfns from ot to nt.
 * Resets the access permissions. */
void p2m_change_type_range(struct domain *d, 
                           unsigned long start, unsigned long end,
                           p2m_type_t ot, p2m_type_t nt)
{
    p2m_type_t pt;
    unsigned long gfn;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));

    p2m_lock(p2m);
    p2m->defer_nested_flush = 1;

    for ( gfn = start; gfn < end; gfn++ )
    {
        mfn = gfn_to_mfn_query(d, gfn, &pt);
        if ( pt == ot )
            set_p2m_entry(p2m, gfn, mfn, 0, nt, p2m->default_access);
    }

    p2m->defer_nested_flush = 0;
    if ( nestedhvm_enabled(d) )
        p2m_flush_nestedp2m(d);
    p2m_unlock(p2m);
}



int
set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    int rc = 0;
    p2m_type_t ot;
    mfn_t omfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return 0;

    omfn = gfn_to_mfn_query(d, gfn, &ot);
    if ( p2m_is_grant(ot) )
    {
        domain_crash(d);
        return 0;
    }
    else if ( p2m_is_ram(ot) )
    {
        ASSERT(mfn_valid(omfn));
        set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);
    }

    P2M_DEBUG("set mmio %lx %lx\n", gfn, mfn_x(mfn));
    p2m_lock(p2m);
    rc = set_p2m_entry(p2m, gfn, mfn, 0, p2m_mmio_direct, p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);
    if ( 0 == rc )
        gdprintk(XENLOG_ERR,
            "set_mmio_p2m_entry: set_p2m_entry failed! mfn=%08lx\n",
            mfn_x(gfn_to_mfn_query(d, gfn, &ot)));
    return rc;
}

int
clear_mmio_p2m_entry(struct domain *d, unsigned long gfn)
{
    int rc = 0;
    mfn_t mfn;
    p2m_type_t t;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return 0;

    mfn = gfn_to_mfn(d, gfn, &t);

    /* Do not use mfn_valid() here as it will usually fail for MMIO pages. */
    if ( (INVALID_MFN == mfn_x(mfn)) || (t != p2m_mmio_direct) )
    {
        gdprintk(XENLOG_ERR,
            "clear_mmio_p2m_entry: gfn_to_mfn failed! gfn=%08lx\n", gfn);
        return 0;
    }
    p2m_lock(p2m);
    rc = set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), 0, 0, p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    return rc;
}

int
set_shared_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = 0;
    p2m_type_t ot;
    mfn_t omfn;

    if ( !paging_mode_translate(p2m->domain) )
        return 0;

    omfn = gfn_to_mfn_query(p2m->domain, gfn, &ot);
    /* At the moment we only allow p2m change if gfn has already been made
     * sharable first */
    ASSERT(p2m_is_shared(ot));
    ASSERT(mfn_valid(omfn));
    /* XXX: M2P translations have to be handled properly for shared pages */
    set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);

    P2M_DEBUG("set shared %lx %lx\n", gfn, mfn_x(mfn));
    p2m_lock(p2m);
    rc = set_p2m_entry(p2m, gfn, mfn, 0, p2m_ram_shared, p2m->default_access);
    p2m_unlock(p2m);
    if ( 0 == rc )
        gdprintk(XENLOG_ERR,
            "set_shared_p2m_entry: set_p2m_entry failed! mfn=%08lx\n",
            mfn_x(gfn_to_mfn_query(d, gfn, &ot)));
    return rc;
}

#ifdef __x86_64__
int p2m_mem_paging_nominate(struct domain *d, unsigned long gfn)
{
    struct page_info *page;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t p2mt;
    mfn_t mfn;
    int ret;

    mfn = gfn_to_mfn(p2m->domain, gfn, &p2mt);

    /* Check if mfn is valid */
    ret = -EINVAL;
    if ( !mfn_valid(mfn) )
        goto out;

    /* Check p2m type */
    ret = -EAGAIN;
    if ( !p2m_is_pageable(p2mt) )
        goto out;

    /* Check for io memory page */
    if ( is_iomem_page(mfn_x(mfn)) )
        goto out;

    /* Check page count and type */
    page = mfn_to_page(mfn);
    if ( (page->count_info & (PGC_count_mask | PGC_allocated)) !=
         (1 | PGC_allocated) )
        goto out;

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_none )
        goto out;

    /* Fix p2m entry */
    p2m_lock(p2m);
    set_p2m_entry(p2m, gfn, mfn, 0, p2m_ram_paging_out, p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    ret = 0;

 out:
    return ret;
}

int p2m_mem_paging_evict(struct domain *d, unsigned long gfn)
{
    struct page_info *page;
    p2m_type_t p2mt;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /* Get mfn */
    mfn = gfn_to_mfn(d, gfn, &p2mt);
    if ( unlikely(!mfn_valid(mfn)) )
        return -EINVAL;

    if ( (p2mt == p2m_ram_paged) || (p2mt == p2m_ram_paging_in) ||
         (p2mt == p2m_ram_paging_in_start) )
        return -EINVAL;

    /* Get the page so it doesn't get modified under Xen's feet */
    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, d)) )
        return -EINVAL;

    /* Decrement guest domain's ref count of the page */
    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    /* Remove mapping from p2m table */
    p2m_lock(p2m);
    set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), 0, 
                  p2m_ram_paged, p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    /* Put the page back so it gets freed */
    put_page(page);

    return 0;
}

void p2m_mem_paging_drop_page(struct domain *d, unsigned long gfn)
{
    struct vcpu *v = current;
    mem_event_request_t req;

    /* Check that there's space on the ring for this request */
    if ( mem_event_check_ring(d) == 0)
    {
        /* Send release notification to pager */
        memset(&req, 0, sizeof(req));
        req.flags |= MEM_EVENT_FLAG_DROP_PAGE;
        req.gfn = gfn;
        req.vcpu_id = v->vcpu_id;

        mem_event_put_request(d, &req);
    }
}

void p2m_mem_paging_populate(struct domain *d, unsigned long gfn)
{
    struct vcpu *v = current;
    mem_event_request_t req;
    p2m_type_t p2mt;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /* Check that there's space on the ring for this request */
    if ( mem_event_check_ring(d) )
        return;

    memset(&req, 0, sizeof(req));
    req.type = MEM_EVENT_TYPE_PAGING;

    /* Fix p2m mapping */
    /* XXX: It seems inefficient to have this here, as it's only needed
     *      in one case (ept guest accessing paging out page) */
    gfn_to_mfn(d, gfn, &p2mt);
    if ( p2mt == p2m_ram_paged )
    {
        p2m_lock(p2m);
        set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), 0, 
                      p2m_ram_paging_in_start, p2m->default_access);
        audit_p2m(p2m, 1);
        p2m_unlock(p2m);
    }

    /* Pause domain */
    if ( v->domain->domain_id == d->domain_id )
    {
        vcpu_pause_nosync(v);
        req.flags |= MEM_EVENT_FLAG_VCPU_PAUSED;
    }
    else if ( p2mt != p2m_ram_paging_out && p2mt != p2m_ram_paged )
    {
        /* gfn is already on its way back and vcpu is not paused */
        return;
    }

    /* Send request to pager */
    req.gfn = gfn;
    req.p2mt = p2mt;
    req.vcpu_id = v->vcpu_id;

    mem_event_put_request(d, &req);
}

int p2m_mem_paging_prep(struct domain *d, unsigned long gfn)
{
    struct page_info *page;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /* Get a free page */
    page = alloc_domheap_page(p2m->domain, 0);
    if ( unlikely(page == NULL) )
        return -ENOMEM;

    /* Fix p2m mapping */
    p2m_lock(p2m);
    set_p2m_entry(p2m, gfn, page_to_mfn(page), 0, p2m_ram_paging_in, p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    return 0;
}

void p2m_mem_paging_resume(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    mem_event_response_t rsp;
    p2m_type_t p2mt;
    mfn_t mfn;

    /* Pull the response off the ring */
    mem_event_get_response(d, &rsp);

    /* Fix p2m entry if the page was not dropped */
    if ( !(rsp.flags & MEM_EVENT_FLAG_DROP_PAGE) )
    {
        mfn = gfn_to_mfn(d, rsp.gfn, &p2mt);
        p2m_lock(p2m);
        set_p2m_entry(p2m, rsp.gfn, mfn, 0, p2m_ram_rw, p2m->default_access);
        set_gpfn_from_mfn(mfn_x(mfn), rsp.gfn);
        audit_p2m(p2m, 1);
        p2m_unlock(p2m);
    }

    /* Unpause domain */
    if ( rsp.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
        vcpu_unpause(d->vcpu[rsp.vcpu_id]);

    /* Unpause any domains that were paused because the ring was full */
    mem_event_unpause_vcpus(d);
}

void p2m_mem_access_check(unsigned long gpa, bool_t gla_valid, unsigned long gla, 
                          bool_t access_r, bool_t access_w, bool_t access_x)
{
    struct vcpu *v = current;
    mem_event_request_t req;
    unsigned long gfn = gpa >> PAGE_SHIFT;
    struct domain *d = v->domain;    
    struct p2m_domain* p2m = p2m_get_hostp2m(d);
    int res;
    mfn_t mfn;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    
    /* First, handle rx2rw conversion automatically */
    p2m_lock(p2m);
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, p2m_query);

    if ( access_w && p2ma == p2m_access_rx2rw ) 
    {
        p2m->set_entry(p2m, gfn, mfn, 0, p2mt, p2m_access_rw);
        p2m_unlock(p2m);
        return;
    }
    p2m_unlock(p2m);

    /* Otherwise, check if there is a memory event listener, and send the message along */
    res = mem_event_check_ring(d);
    if ( res < 0 ) 
    {
        /* No listener */
        if ( p2m->access_required ) 
        {
            printk(XENLOG_INFO 
                   "Memory access permissions failure, no mem_event listener: pausing VCPU %d, dom %d\n",
                   v->vcpu_id, d->domain_id);

            mem_event_mark_and_pause(v);
        }
        else
        {
            /* A listener is not required, so clear the access restrictions */
            p2m_lock(p2m);
            p2m->set_entry(p2m, gfn, mfn, 0, p2mt, p2m_access_rwx);
            p2m_unlock(p2m);
        }

        return;
    }
    else if ( res > 0 )
        return;  /* No space in buffer; VCPU paused */

    memset(&req, 0, sizeof(req));
    req.type = MEM_EVENT_TYPE_ACCESS;
    req.reason = MEM_EVENT_REASON_VIOLATION;

    /* Pause the current VCPU unconditionally */
    vcpu_pause_nosync(v);
    req.flags |= MEM_EVENT_FLAG_VCPU_PAUSED;    

    /* Send request to mem event */
    req.gfn = gfn;
    req.offset = gpa & ((1 << PAGE_SHIFT) - 1);
    req.gla_valid = gla_valid;
    req.gla = gla;
    req.access_r = access_r;
    req.access_w = access_w;
    req.access_x = access_x;
    
    req.vcpu_id = v->vcpu_id;

    mem_event_put_request(d, &req);   

    /* VCPU paused, mem event request sent */
}

void p2m_mem_access_resume(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;
    mem_event_response_t rsp;

    mem_event_get_response(d, &rsp);

    /* Unpause domain */
    if ( rsp.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
        vcpu_unpause(d->vcpu[rsp.vcpu_id]);

    /* Unpause any domains that were paused because the ring was full or no listener 
     * was available */
    mem_event_unpause_vcpus(d);
}


/* Set access type for a region of pfns.
 * If start_pfn == -1ul, sets the default access type */
int p2m_set_mem_access(struct domain *d, unsigned long start_pfn, 
                       uint32_t nr, hvmmem_access_t access) 
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long pfn;
    p2m_access_t a;
    p2m_type_t t;
    mfn_t mfn;
    int rc = 0;

    /* N.B. _not_ static: initializer depends on p2m->default_access */
    p2m_access_t memaccess[] = {
        p2m_access_n,
        p2m_access_r,
        p2m_access_w,
        p2m_access_rw,
        p2m_access_x,
        p2m_access_rx,
        p2m_access_wx,
        p2m_access_rwx,
        p2m_access_rx2rw,
        p2m->default_access,
    };

    if ( access >= HVMMEM_access_default || access < 0 )
        return -EINVAL;

    a = memaccess[access];

    /* If request to set default access */
    if ( start_pfn == ~0ull ) 
    {
        p2m->default_access = a;
        return 0;
    }

    p2m_lock(p2m);
    for ( pfn = start_pfn; pfn < start_pfn + nr; pfn++ )
    {
        mfn = gfn_to_mfn_query(d, pfn, &t);
        if ( p2m->set_entry(p2m, pfn, mfn, 0, t, a) == 0 )
        {
            rc = -ENOMEM;
            break;
        }
    }
    p2m_unlock(p2m);
    return rc;
}

/* Get access type for a pfn
 * If pfn == -1ul, gets the default access type */
int p2m_get_mem_access(struct domain *d, unsigned long pfn, 
                       hvmmem_access_t *access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t t;
    p2m_access_t a;
    mfn_t mfn;

    static const hvmmem_access_t memaccess[] = {
        HVMMEM_access_n,
        HVMMEM_access_r,
        HVMMEM_access_w,
        HVMMEM_access_rw,
        HVMMEM_access_x,
        HVMMEM_access_rx,
        HVMMEM_access_wx,
        HVMMEM_access_rwx,
        HVMMEM_access_rx2rw
    };

    /* If request to get default access */
    if ( pfn == ~0ull ) 
    {
        *access = memaccess[p2m->default_access];
        return 0;
    }

    mfn = p2m->get_entry(p2m, pfn, &t, &a, p2m_query);
    if ( mfn_x(mfn) == INVALID_MFN )
        return -ESRCH;
    
    if ( a >= ARRAY_SIZE(memaccess) || a < 0 )
        return -ERANGE;

    *access =  memaccess[a];
    return 0;
}


#endif /* __x86_64__ */

static struct p2m_domain *
p2m_getlru_nestedp2m(struct domain *d, struct p2m_domain *p2m)
{
    struct list_head *lru_list = &p2m_get_hostp2m(d)->np2m_list;
    
    ASSERT(!list_empty(lru_list));

    if ( p2m == NULL )
        p2m = list_entry(lru_list->prev, struct p2m_domain, np2m_list);

    list_move(&p2m->np2m_list, lru_list);

    return p2m;
}

/* Reset this p2m table to be empty */
static void
p2m_flush_table(struct p2m_domain *p2m)
{
    struct page_info *top, *pg;
    struct domain *d = p2m->domain;
    void *p;

    p2m_lock(p2m);

    /* "Host" p2m tables can have shared entries &c that need a bit more 
     * care when discarding them */
    ASSERT(p2m_is_nestedp2m(p2m));
    ASSERT(page_list_empty(&p2m->pod.super));
    ASSERT(page_list_empty(&p2m->pod.single));

    /* This is no longer a valid nested p2m for any address space */
    p2m->cr3 = CR3_EADDR;
    
    /* Zap the top level of the trie */
    top = mfn_to_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    p = __map_domain_page(top);
    clear_page(p);
    unmap_domain_page(p);

    /* Make sure nobody else is using this p2m table */
    nestedhvm_vmcx_flushtlb(p2m);

    /* Free the rest of the trie pages back to the paging pool */
    while ( (pg = page_list_remove_head(&p2m->pages)) )
        if ( pg != top ) 
            d->arch.paging.free_page(d, pg);
    page_list_add(top, &p2m->pages);

    p2m_unlock(p2m);
}

void
p2m_flush(struct vcpu *v, struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;

    ASSERT(v->domain == d);
    vcpu_nestedhvm(v).nv_p2m = NULL;
    p2m_flush_table(p2m);
    hvm_asid_flush_vcpu(v);
}

void
p2m_flush_nestedp2m(struct domain *d)
{
    int i;
    for ( i = 0; i < MAX_NESTEDP2M; i++ )
        p2m_flush_table(d->arch.nested_p2m[i]);
}

struct p2m_domain *
p2m_get_nestedp2m(struct vcpu *v, uint64_t cr3)
{
    /* Use volatile to prevent gcc to cache nv->nv_p2m in a cpu register as
     * this may change within the loop by an other (v)cpu.
     */
    volatile struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct domain *d;
    struct p2m_domain *p2m;

    /* Mask out low bits; this avoids collisions with CR3_EADDR */
    cr3 &= ~(0xfffull);

    if (nv->nv_flushp2m && nv->nv_p2m) {
        nv->nv_p2m = NULL;
    }

    d = v->domain;
    nestedp2m_lock(d);
    p2m = nv->nv_p2m;
    if ( p2m ) 
    {
        p2m_lock(p2m);
        if ( p2m->cr3 == cr3 || p2m->cr3 == CR3_EADDR )
        {
            nv->nv_flushp2m = 0;
            p2m_getlru_nestedp2m(d, p2m);
            nv->nv_p2m = p2m;
            if (p2m->cr3 == CR3_EADDR)
                hvm_asid_flush_vcpu(v);
            p2m->cr3 = cr3;
            cpu_set(v->processor, p2m->p2m_dirty_cpumask);
            p2m_unlock(p2m);
            nestedp2m_unlock(d);
            return p2m;
        }
        p2m_unlock(p2m);
    }

    /* All p2m's are or were in use. Take the least recent used one,
     * flush it and reuse. */
    p2m = p2m_getlru_nestedp2m(d, NULL);
    p2m_flush_table(p2m);
    p2m_lock(p2m);
    nv->nv_p2m = p2m;
    p2m->cr3 = cr3;
    nv->nv_flushp2m = 0;
    hvm_asid_flush_vcpu(v);
    nestedhvm_vmcx_flushtlb(p2m);
    cpu_set(v->processor, p2m->p2m_dirty_cpumask);
    p2m_unlock(p2m);
    nestedp2m_unlock(d);

    return p2m;
}

struct p2m_domain *
p2m_get_p2m(struct vcpu *v)
{
    if (!nestedhvm_is_n2(v))
        return p2m_get_hostp2m(v->domain);

    return p2m_get_nestedp2m(v, nhvm_vcpu_hostcr3(v));
}

unsigned long paging_gva_to_gfn(struct vcpu *v,
                                unsigned long va,
                                uint32_t *pfec)
{
    struct p2m_domain *hostp2m = p2m_get_hostp2m(v->domain);
    const struct paging_mode *hostmode = paging_get_hostmode(v);

    if ( is_hvm_domain(v->domain)
        && paging_mode_hap(v->domain) 
        && nestedhvm_is_n2(v) )
    {
        unsigned long gfn;
        struct p2m_domain *p2m;
        const struct paging_mode *mode;
        uint64_t ncr3 = nhvm_vcpu_hostcr3(v);

        /* translate l2 guest va into l2 guest gfn */
        p2m = p2m_get_nestedp2m(v, ncr3);
        mode = paging_get_nestedmode(v);
        gfn = mode->gva_to_gfn(v, p2m, va, pfec);

        /* translate l2 guest gfn into l1 guest gfn */
        return hostmode->p2m_ga_to_gfn(v, hostp2m, ncr3,
            gfn << PAGE_SHIFT, pfec);
    }

    return hostmode->gva_to_gfn(v, hostp2m, va, pfec);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
