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

#include <xen/iommu.h>
#include <xen/mem_event.h>
#include <xen/event.h>
#include <public/mem_event.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h> /* ept_p2m_init() */
#include <asm/mem_sharing.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <xsm/xsm.h>

#include "mm-locks.h"

/* turn on/off 1GB host page table support for hap, default on */
bool_t __read_mostly opt_hap_1gb = 1;
boolean_param("hap_1gb", opt_hap_1gb);

bool_t __read_mostly opt_hap_2mb = 1;
boolean_param("hap_2mb", opt_hap_2mb);


/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))


/* Init the datastructures for later use by the p2m code */
static int p2m_initialise(struct domain *d, struct p2m_domain *p2m)
{
    int ret = 0;

    mm_rwlock_init(&p2m->lock);
    mm_lock_init(&p2m->pod.lock);
    INIT_LIST_HEAD(&p2m->np2m_list);
    INIT_PAGE_LIST_HEAD(&p2m->pages);
    INIT_PAGE_LIST_HEAD(&p2m->pod.super);
    INIT_PAGE_LIST_HEAD(&p2m->pod.single);

    p2m->domain = d;
    p2m->default_access = p2m_access_rwx;

    p2m->np2m_base = P2M_BASE_EADDR;

    if ( hap_enabled(d) && cpu_has_vmx )
        ret = ept_p2m_init(p2m);
    else
        p2m_pt_init(p2m);

    return ret;
}

static struct p2m_domain *p2m_init_one(struct domain *d)
{
    struct p2m_domain *p2m = xzalloc(struct p2m_domain);

    if ( !p2m )
        return NULL;

    if ( !zalloc_cpumask_var(&p2m->dirty_cpumask) )
        goto free_p2m;

    if ( p2m_initialise(d, p2m) )
        goto free_cpumask;
    return p2m;

free_cpumask:
    free_cpumask_var(p2m->dirty_cpumask);
free_p2m:
    xfree(p2m);
    return NULL;
}

static void p2m_free_one(struct p2m_domain *p2m)
{
    if ( hap_enabled(p2m->domain) && cpu_has_vmx )
        ept_p2m_uninit(p2m);
    free_cpumask_var(p2m->dirty_cpumask);
    xfree(p2m);
}

static int p2m_init_hostp2m(struct domain *d)
{
    struct p2m_domain *p2m = p2m_init_one(d);

    if ( p2m )
    {
        p2m->logdirty_ranges = rangeset_new(d, "log-dirty",
                                            RANGESETF_prettyprint_hex);
        if ( p2m->logdirty_ranges )
        {
            d->arch.p2m = p2m;
            return 0;
        }
        p2m_free_one(p2m);
    }
    return -ENOMEM;
}

static void p2m_teardown_hostp2m(struct domain *d)
{
    /* Iterate over all p2m tables per domain */
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( p2m )
    {
        rangeset_destroy(p2m->logdirty_ranges);
        p2m_free_one(p2m);
        d->arch.p2m = NULL;
    }
}

static void p2m_teardown_nestedp2m(struct domain *d);

static int p2m_init_nestedp2m(struct domain *d)
{
    uint8_t i;
    struct p2m_domain *p2m;

    mm_lock_init(&d->arch.nested_p2m_lock);
    for (i = 0; i < MAX_NESTEDP2M; i++)
    {
        d->arch.nested_p2m[i] = p2m = p2m_init_one(d);
        if ( p2m == NULL )
        {
            p2m_teardown_nestedp2m(d);
            return -ENOMEM;
        }
        p2m->write_p2m_entry = nestedp2m_write_p2m_entry;
        list_add(&p2m->np2m_list, &p2m_get_hostp2m(d)->np2m_list);
    }

    return 0;
}

static void p2m_teardown_nestedp2m(struct domain *d)
{
    uint8_t i;
    struct p2m_domain *p2m;

    for (i = 0; i < MAX_NESTEDP2M; i++)
    {
        if ( !d->arch.nested_p2m[i] )
            continue;
        p2m = d->arch.nested_p2m[i];
        list_del(&p2m->np2m_list);
        p2m_free_one(p2m);
        d->arch.nested_p2m[i] = NULL;
    }
}

int p2m_init(struct domain *d)
{
    int rc;

    rc = p2m_init_hostp2m(d);
    if ( rc )
        return rc;

    /* Must initialise nestedp2m unconditionally
     * since nestedhvm_enabled(d) returns false here.
     * (p2m_init runs too early for HVM_PARAM_* options) */
    rc = p2m_init_nestedp2m(d);
    if ( rc )
        p2m_teardown_hostp2m(d);

    return rc;
}

int p2m_is_logdirty_range(struct p2m_domain *p2m, unsigned long start,
                          unsigned long end)
{
    ASSERT(!p2m_is_nestedp2m(p2m));
    if ( p2m->global_logdirty ||
         rangeset_contains_range(p2m->logdirty_ranges, start, end) )
        return 1;
    if ( rangeset_overlaps_range(p2m->logdirty_ranges, start, end) )
        return -1;
    return 0;
}

void p2m_change_entry_type_global(struct domain *d,
                                  p2m_type_t ot, p2m_type_t nt)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    ASSERT(ot != nt);
    ASSERT(p2m_is_changeable(ot) && p2m_is_changeable(nt));

    p2m_lock(p2m);
    p2m->change_entry_type_global(p2m, ot, nt);
    p2m->global_logdirty = (nt == p2m_ram_logdirty);
    p2m_unlock(p2m);
}

void p2m_memory_type_changed(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( p2m->memory_type_changed )
    {
        p2m_lock(p2m);
        p2m->memory_type_changed(p2m);
        p2m_unlock(p2m);
    }
}

mfn_t __get_gfn_type_access(struct p2m_domain *p2m, unsigned long gfn,
                    p2m_type_t *t, p2m_access_t *a, p2m_query_t q,
                    unsigned int *page_order, bool_t locked)
{
    mfn_t mfn;

    /* Unshare makes no sense withuot populate. */
    if ( q & P2M_UNSHARE )
        q |= P2M_ALLOC;

    if ( !p2m || !paging_mode_translate(p2m->domain) )
    {
        /* Not necessarily true, but for non-translated guests, we claim
         * it's the most generic kind of memory */
        *t = p2m_ram_rw;
        return _mfn(gfn);
    }

    if ( locked )
        /* Grab the lock here, don't release until put_gfn */
        gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, t, a, q, page_order);

    if ( (q & P2M_UNSHARE) && p2m_is_shared(*t) )
    {
        ASSERT(!p2m_is_nestedp2m(p2m));
        /* Try to unshare. If we fail, communicate ENOMEM without
         * sleeping. */
        if ( mem_sharing_unshare_page(p2m->domain, gfn, 0) < 0 )
            (void)mem_sharing_notify_enomem(p2m->domain, gfn, 0);
        mfn = p2m->get_entry(p2m, gfn, t, a, q, page_order);
    }

    if (unlikely((p2m_is_broken(*t))))
    {
        /* Return invalid_mfn to avoid caller's access */
        mfn = _mfn(INVALID_MFN);
        if ( q & P2M_ALLOC )
            domain_crash(p2m->domain);
    }

    return mfn;
}

void __put_gfn(struct p2m_domain *p2m, unsigned long gfn)
{
    if ( !p2m || !paging_mode_translate(p2m->domain) )
        /* Nothing to do in this case */
        return;

    ASSERT(gfn_locked_by_me(p2m, gfn));

    gfn_unlock(p2m, gfn, 0);
}

/* Atomically look up a GFN and take a reference count on the backing page. */
struct page_info *get_page_from_gfn_p2m(
    struct domain *d, struct p2m_domain *p2m, unsigned long gfn,
    p2m_type_t *t, p2m_access_t *a, p2m_query_t q)
{
    struct page_info *page = NULL;
    p2m_access_t _a;
    p2m_type_t _t;
    mfn_t mfn;

    /* Allow t or a to be NULL */
    t = t ?: &_t;
    a = a ?: &_a;

    if ( likely(!p2m_locked_by_me(p2m)) )
    {
        /* Fast path: look up and get out */
        p2m_read_lock(p2m);
        mfn = __get_gfn_type_access(p2m, gfn, t, a, 0, NULL, 0);
        if ( p2m_is_any_ram(*t) && mfn_valid(mfn)
             && !((q & P2M_UNSHARE) && p2m_is_shared(*t)) )
        {
            page = mfn_to_page(mfn);
            if ( unlikely(p2m_is_foreign(*t)) )
            {
                struct domain *fdom = page_get_owner_and_reference(page);
                ASSERT(fdom != d);
                if ( fdom == NULL )
                    page = NULL;
            }
            else if ( !get_page(page, d)
                      /* Page could be shared */
                      && !get_page(page, dom_cow) )
                page = NULL;
        }
        p2m_read_unlock(p2m);

        if ( page )
            return page;

        /* Error path: not a suitable GFN at all */
        if ( !p2m_is_ram(*t) && !p2m_is_paging(*t) && !p2m_is_pod(*t) )
            return NULL;
    }

    /* Slow path: take the write lock and do fixups */
    mfn = get_gfn_type_access(p2m, gfn, t, a, q, NULL);
    if ( p2m_is_ram(*t) && mfn_valid(mfn) )
    {
        page = mfn_to_page(mfn);
        if ( !get_page(page, d) )
            page = NULL;
    }
    put_gfn(d, gfn);

    return page;
}

/* Returns: 0 for success, -errno for failure */
int p2m_set_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn,
                  unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    struct domain *d = p2m->domain;
    unsigned long todo = 1ul << page_order;
    unsigned int order;
    int set_rc, rc = 0;

    ASSERT(gfn_locked_by_me(p2m, gfn));

    while ( todo )
    {
        if ( hap_enabled(d) )
            order = ( (((gfn | mfn_x(mfn) | todo) & ((1ul << PAGE_ORDER_1G) - 1)) == 0) &&
                      hvm_hap_has_1gb(d) && opt_hap_1gb ) ? PAGE_ORDER_1G :
                      ((((gfn | mfn_x(mfn) | todo) & ((1ul << PAGE_ORDER_2M) - 1)) == 0) &&
                      hvm_hap_has_2mb(d) && opt_hap_2mb) ? PAGE_ORDER_2M : PAGE_ORDER_4K;
        else
            order = 0;

        set_rc = p2m->set_entry(p2m, gfn, mfn, order, p2mt, p2ma);
        if ( set_rc )
            rc = set_rc;

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

/*
 * Allocate a new p2m table for a domain.
 *
 * The structure of the p2m table is that of a pagetable for xen (i.e. it is
 * controlled by CONFIG_PAGING_LEVELS).
 *
 * Returns 0 for success, -errno for failure.
 */
int p2m_alloc_table(struct p2m_domain *p2m)
{
    struct page_info *p2m_top;
    struct domain *d = p2m->domain;
    int rc = 0;

    p2m_lock(p2m);

    if ( !p2m_is_nestedp2m(p2m)
         && !page_list_empty(&d->page_list) )
    {
        P2M_ERROR("dom %d already has memory allocated\n", d->domain_id);
        p2m_unlock(p2m);
        return -EINVAL;
    }

    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) != 0 )
    {
        P2M_ERROR("p2m already allocated for this domain\n");
        p2m_unlock(p2m);
        return -EINVAL;
    }

    P2M_PRINTK("allocating p2m table\n");

    p2m_top = p2m_alloc_ptp(p2m, PGT_l4_page_table);
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
    p2m->defer_nested_flush = 1;
    rc = p2m_set_entry(p2m, 0, _mfn(INVALID_MFN), PAGE_ORDER_4K,
                       p2m_invalid, p2m->default_access);
    p2m->defer_nested_flush = 0;
    p2m_unlock(p2m);
    if ( !rc )
        P2M_PRINTK("p2m table initialised for slot zero\n");
    else
        P2M_PRINTK("failed to initialise p2m table for slot zero (%d)\n", rc);
    return rc;
}

/*
 * pvh fixme: when adding support for pvh non-hardware domains, this path must
 * cleanup any foreign p2m types (release refcnts on them).
 */
void p2m_teardown(struct p2m_domain *p2m)
/* Return all the p2m pages to Xen.
 * We know we don't have any extra mappings to these pages */
{
    struct page_info *pg;
    struct domain *d;

    if (p2m == NULL)
        return;

    d = p2m->domain;

    p2m_lock(p2m);
    ASSERT(atomic_read(&d->shr_pages) == 0);
    p2m->phys_table = pagetable_null();

    while ( (pg = page_list_remove_head(&p2m->pages)) )
        d->arch.paging.free_page(d, pg);
    p2m_unlock(p2m);
}

void p2m_final_teardown(struct domain *d)
{
    /* We must teardown unconditionally because
     * we initialise them unconditionally.
     */
    p2m_teardown_nestedp2m(d);

    /* Iterate over all p2m tables per domain */
    p2m_teardown_hostp2m(d);
}


static int
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
        return 0;
    }

    ASSERT(gfn_locked_by_me(p2m, gfn));
    P2M_DEBUG("removing gfn=%#lx mfn=%#lx\n", gfn, mfn);

    if ( mfn_valid(_mfn(mfn)) )
    {
        for ( i = 0; i < (1UL << page_order); i++ )
        {
            mfn_return = p2m->get_entry(p2m, gfn + i, &t, &a, 0, NULL);
            if ( !p2m_is_grant(t) && !p2m_is_shared(t) && !p2m_is_foreign(t) )
                set_gpfn_from_mfn(mfn+i, INVALID_M2P_ENTRY);
            ASSERT( !p2m_is_valid(t) || mfn + i == mfn_x(mfn_return) );
        }
    }
    return p2m_set_entry(p2m, gfn, _mfn(INVALID_MFN), page_order, p2m_invalid,
                         p2m->default_access);
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                          unsigned long mfn, unsigned int page_order)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    gfn_lock(p2m, gfn, page_order);
    p2m_remove_page(p2m, gfn, mfn, page_order);
    gfn_unlock(p2m, gfn, page_order);
}

int
guest_physmap_add_entry(struct domain *d, unsigned long gfn,
                        unsigned long mfn, unsigned int page_order, 
                        p2m_type_t t)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long i, ogfn;
    p2m_type_t ot;
    p2m_access_t a;
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

    /* foreign pages are added thru p2m_add_foreign */
    if ( p2m_is_foreign(t) )
        return -EINVAL;

    p2m_lock(p2m);

    P2M_DEBUG("adding gfn=%#lx mfn=%#lx\n", gfn, mfn);

    /* First, remove m->p mappings for existing p->m mappings */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        omfn = p2m->get_entry(p2m, gfn + i, &ot, &a, 0, NULL);
        if ( p2m_is_shared(ot) )
        {
            /* Do an unshare to cleanly take care of all corner 
             * cases. */
            int rc;
            rc = mem_sharing_unshare_page(p2m->domain, gfn + i, 0);
            if ( rc )
            {
                p2m_unlock(p2m);
                /* NOTE: Should a guest domain bring this upon itself,
                 * there is not a whole lot we can do. We are buried
                 * deep in locks from most code paths by now. So, fail
                 * the call and don't try to sleep on a wait queue
                 * while placing the mem event.
                 *
                 * However, all current (changeset 3432abcf9380) code
                 * paths avoid this unsavoury situation. For now.
                 *
                 * Foreign domains are okay to place an event as they 
                 * won't go to sleep. */
                (void)mem_sharing_notify_enomem(p2m->domain, gfn + i, 0);
                return rc;
            }
            omfn = p2m->get_entry(p2m, gfn + i, &ot, &a, 0, NULL);
            ASSERT(!p2m_is_shared(ot));
        }
        if ( p2m_is_grant(ot) || p2m_is_foreign(ot) )
        {
            /* Really shouldn't be unmapping grant/foreign maps this way */
            domain_crash(d);
            p2m_unlock(p2m);
            
            return -EINVAL;
        }
        else if ( p2m_is_ram(ot) && !p2m_is_paged(ot) )
        {
            ASSERT(mfn_valid(omfn));
            set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);
        }
        else if ( ot == p2m_populate_on_demand )
        {
            /* Count how man PoD entries we'll be replacing if successful */
            pod_count++;
        }
        else if ( p2m_is_paging(ot) && (ot != p2m_ram_paging_out) )
        {
            /* We're plugging a hole in the physmap where a paged out page was */
            atomic_dec(&d->paged_pages);
        }
    }

    /* Then, look for m->p mappings for this range and deal with them */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        if ( page_get_owner(mfn_to_page(_mfn(mfn + i))) == dom_cow )
        {
            /* This is no way to add a shared page to your physmap! */
            gdprintk(XENLOG_ERR, "Adding shared mfn %lx directly to dom %hu "
                        "physmap not allowed.\n", mfn+i, d->domain_id);
            p2m_unlock(p2m);
            return -EINVAL;
        }
        if ( page_get_owner(mfn_to_page(_mfn(mfn + i))) != d )
            continue;
        ogfn = mfn_to_gfn(d, _mfn(mfn+i));
        if ( (ogfn != INVALID_M2P_ENTRY) && (ogfn != gfn + i) )
        {
            /* This machine frame is already mapped at another physical
             * address */
            P2M_DEBUG("aliased! mfn=%#lx, old gfn=%#lx, new gfn=%#lx\n",
                      mfn + i, ogfn, gfn + i);
            omfn = p2m->get_entry(p2m, ogfn, &ot, &a, 0, NULL);
            if ( p2m_is_ram(ot) && !p2m_is_paged(ot) )
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
        rc = p2m_set_entry(p2m, gfn, _mfn(mfn), page_order, t,
                           p2m->default_access);
        if ( rc )
            goto out; /* Failed to update p2m, bail without updating m2p. */

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
        rc = p2m_set_entry(p2m, gfn, _mfn(INVALID_MFN), page_order,
                           p2m_invalid, p2m->default_access);
        if ( rc == 0 )
        {
            pod_lock(p2m);
            p2m->pod.entry_count -= pod_count;
            BUG_ON(p2m->pod.entry_count < 0);
            pod_unlock(p2m);
        }
    }

out:
    p2m_unlock(p2m);

    return rc;
}


/*
 * Modify the p2m type of a single gfn from ot to nt.
 * Returns: 0 for success, -errno for failure.
 * Resets the access permissions.
 */
int p2m_change_type_one(struct domain *d, unsigned long gfn,
                       p2m_type_t ot, p2m_type_t nt)
{
    p2m_access_t a;
    p2m_type_t pt;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc;

    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));
    BUG_ON(p2m_is_foreign(ot) || p2m_is_foreign(nt));

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &pt, &a, 0, NULL);
    rc = likely(pt == ot)
         ? p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, nt,
                         p2m->default_access)
         : -EBUSY;

    gfn_unlock(p2m, gfn, 0);

    return rc;
}

/* Modify the p2m type of a range of gfns from ot to nt. */
void p2m_change_type_range(struct domain *d, 
                           unsigned long start, unsigned long end,
                           p2m_type_t ot, p2m_type_t nt)
{
    unsigned long gfn = start;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = 0;

    ASSERT(ot != nt);
    ASSERT(p2m_is_changeable(ot) && p2m_is_changeable(nt));

    p2m_lock(p2m);
    p2m->defer_nested_flush = 1;

    if ( unlikely(end > p2m->max_mapped_pfn) )
    {
        if ( !gfn )
        {
            p2m->change_entry_type_global(p2m, ot, nt);
            gfn = end;
        }
        end = p2m->max_mapped_pfn + 1;
    }
    if ( gfn < end )
        rc = p2m->change_entry_type_range(p2m, ot, nt, gfn, end - 1);
    if ( rc )
    {
        printk(XENLOG_G_ERR "Error %d changing Dom%d GFNs [%lx,%lx] from %d to %d\n",
               rc, d->domain_id, start, end - 1, ot, nt);
        domain_crash(d);
    }

    switch ( nt )
    {
    case p2m_ram_rw:
        if ( ot == p2m_ram_logdirty )
            rc = rangeset_remove_range(p2m->logdirty_ranges, start, end - 1);
        break;
    case p2m_ram_logdirty:
        if ( ot == p2m_ram_rw )
            rc = rangeset_add_range(p2m->logdirty_ranges, start, end - 1);
        break;
    default:
        break;
    }
    if ( rc )
    {
        printk(XENLOG_G_ERR "Error %d manipulating Dom%d's log-dirty ranges\n",
               rc, d->domain_id);
        domain_crash(d);
    }

    p2m->defer_nested_flush = 0;
    if ( nestedhvm_enabled(d) )
        p2m_flush_nestedp2m(d);
    p2m_unlock(p2m);
}

/* Returns: 0 for success, -errno for failure */
static int set_typed_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn,
                               p2m_type_t gfn_p2mt)
{
    int rc = 0;
    p2m_access_t a;
    p2m_type_t ot;
    mfn_t omfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return -EIO;

    gfn_lock(p2m, gfn, 0);
    omfn = p2m->get_entry(p2m, gfn, &ot, &a, 0, NULL);
    if ( p2m_is_grant(ot) || p2m_is_foreign(ot) )
    {
        p2m_unlock(p2m);
        domain_crash(d);
        return -ENOENT;
    }
    else if ( p2m_is_ram(ot) )
    {
        ASSERT(mfn_valid(omfn));
        set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);
    }

    P2M_DEBUG("set %d %lx %lx\n", gfn_p2mt, gfn, mfn_x(mfn));
    rc = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, gfn_p2mt,
                       p2m->default_access);
    gfn_unlock(p2m, gfn, 0);
    if ( rc )
        gdprintk(XENLOG_ERR,
                 "p2m_set_entry failed! mfn=%08lx rc:%d\n",
                 mfn_x(get_gfn_query_unlocked(p2m->domain, gfn, &ot)), rc);
    return rc;
}

/* Set foreign mfn in the given guest's p2m table. */
static int set_foreign_p2m_entry(struct domain *d, unsigned long gfn,
                                 mfn_t mfn)
{
    return set_typed_p2m_entry(d, gfn, mfn, p2m_map_foreign);
}

int set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    return set_typed_p2m_entry(d, gfn, mfn, p2m_mmio_direct);
}

/* Returns: 0 for success, -errno for failure */
int clear_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    int rc = -EINVAL;
    mfn_t actual_mfn;
    p2m_access_t a;
    p2m_type_t t;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return -EIO;

    gfn_lock(p2m, gfn, 0);
    actual_mfn = p2m->get_entry(p2m, gfn, &t, &a, 0, NULL);

    /* Do not use mfn_valid() here as it will usually fail for MMIO pages. */
    if ( (INVALID_MFN == mfn_x(actual_mfn)) || (t != p2m_mmio_direct) )
    {
        gdprintk(XENLOG_ERR,
                 "gfn_to_mfn failed! gfn=%08lx type:%d\n", gfn, t);
        goto out;
    }
    if ( mfn_x(mfn) != mfn_x(actual_mfn) )
        gdprintk(XENLOG_WARNING,
                 "no mapping between mfn %08lx and gfn %08lx\n",
                 mfn_x(mfn), gfn);
    rc = p2m_set_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K, p2m_invalid,
                       p2m->default_access);

 out:
    gfn_unlock(p2m, gfn, 0);

    return rc;
}

/* Returns: 0 for success, -errno for failure */
int set_shared_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = 0;
    p2m_access_t a;
    p2m_type_t ot;
    mfn_t omfn;
    unsigned long pg_type;

    if ( !paging_mode_translate(p2m->domain) )
        return -EIO;

    gfn_lock(p2m, gfn, 0);
    omfn = p2m->get_entry(p2m, gfn, &ot, &a, 0, NULL);
    /* At the moment we only allow p2m change if gfn has already been made
     * sharable first */
    ASSERT(p2m_is_shared(ot));
    ASSERT(mfn_valid(omfn));
    /* Set the m2p entry to invalid only if there are no further type
     * refs to this page as shared */
    pg_type = read_atomic(&(mfn_to_page(omfn)->u.inuse.type_info));
    if ( (pg_type & PGT_count_mask) == 0
         || (pg_type & PGT_type_mask) != PGT_shared_page )
        set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);

    P2M_DEBUG("set shared %lx %lx\n", gfn, mfn_x(mfn));
    rc = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_ram_shared,
                       p2m->default_access);
    gfn_unlock(p2m, gfn, 0);
    if ( rc )
        gdprintk(XENLOG_ERR,
                 "p2m_set_entry failed! mfn=%08lx rc:%d\n",
                 mfn_x(get_gfn_query_unlocked(p2m->domain, gfn, &ot)), rc);
    return rc;
}

/**
 * p2m_mem_paging_nominate - Mark a guest page as to-be-paged-out
 * @d: guest domain
 * @gfn: guest page to nominate
 *
 * Returns 0 for success or negative errno values if gfn is not pageable.
 *
 * p2m_mem_paging_nominate() is called by the pager and checks if a guest page
 * can be paged out. If the following conditions are met the p2mt will be
 * changed:
 * - the gfn is backed by a mfn
 * - the p2mt of the gfn is pageable
 * - the mfn is not used for IO
 * - the mfn has exactly one user and has no special meaning
 *
 * Once the p2mt is changed the page is readonly for the guest.  On success the
 * pager can write the page contents to disk and later evict the page.
 */
int p2m_mem_paging_nominate(struct domain *d, unsigned long gfn)
{
    struct page_info *page;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    int ret = -EBUSY;

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL);

    /* Check if mfn is valid */
    if ( !mfn_valid(mfn) )
        goto out;

    /* Check p2m type */
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

    if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
        goto out;

    /* Fix p2m entry */
    ret = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_ram_paging_out, a);

 out:
    gfn_unlock(p2m, gfn, 0);
    return ret;
}

/**
 * p2m_mem_paging_evict - Mark a guest page as paged-out
 * @d: guest domain
 * @gfn: guest page to evict
 *
 * Returns 0 for success or negative errno values if eviction is not possible.
 *
 * p2m_mem_paging_evict() is called by the pager and will free a guest page and
 * release it back to Xen. If the following conditions are met the page can be
 * freed:
 * - the gfn is backed by a mfn
 * - the gfn was nominated
 * - the mfn has still exactly one user and has no special meaning
 *
 * After successful nomination some other process could have mapped the page. In
 * this case eviction can not be done. If the gfn was populated before the pager
 * could evict it, eviction can not be done either. In this case the gfn is
 * still backed by a mfn.
 */
int p2m_mem_paging_evict(struct domain *d, unsigned long gfn)
{
    struct page_info *page;
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret = -EBUSY;

    gfn_lock(p2m, gfn, 0);

    /* Get mfn */
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL);
    if ( unlikely(!mfn_valid(mfn)) )
        goto out;

    /* Allow only nominated pages */
    if ( p2mt != p2m_ram_paging_out )
        goto out;

    /* Get the page so it doesn't get modified under Xen's feet */
    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, d)) )
        goto out;

    /* Check page count and type once more */
    if ( (page->count_info & (PGC_count_mask | PGC_allocated)) !=
         (2 | PGC_allocated) )
        goto out_put;

    if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
        goto out_put;

    /* Decrement guest domain's ref count of the page */
    if ( test_and_clear_bit(_PGC_allocated, &page->count_info) )
        put_page(page);

    /* Remove mapping from p2m table */
    ret = p2m_set_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K,
                        p2m_ram_paged, a);

    /* Clear content before returning the page to Xen */
    scrub_one_page(page);

    /* Track number of paged gfns */
    atomic_inc(&d->paged_pages);

 out_put:
    /* Put the page back so it gets freed */
    put_page(page);

 out:
    gfn_unlock(p2m, gfn, 0);
    return ret;
}

/**
 * p2m_mem_paging_drop_page - Tell pager to drop its reference to a paged page
 * @d: guest domain
 * @gfn: guest page to drop
 *
 * p2m_mem_paging_drop_page() will notify the pager that a paged-out gfn was
 * released by the guest. The pager is supposed to drop its reference of the
 * gfn.
 */
void p2m_mem_paging_drop_page(struct domain *d, unsigned long gfn,
                                p2m_type_t p2mt)
{
    mem_event_request_t req = { .gfn = gfn };

    /* We allow no ring in this unique case, because it won't affect
     * correctness of the guest execution at this point.  If this is the only
     * page that happens to be paged-out, we'll be okay..  but it's likely the
     * guest will crash shortly anyways. */
    int rc = mem_event_claim_slot(d, &d->mem_event->paging);
    if ( rc < 0 )
        return;

    /* Send release notification to pager */
    req.flags = MEM_EVENT_FLAG_DROP_PAGE;

    /* Update stats unless the page hasn't yet been evicted */
    if ( p2mt != p2m_ram_paging_out )
        atomic_dec(&d->paged_pages);
    else
        /* Evict will fail now, tag this request for pager */
        req.flags |= MEM_EVENT_FLAG_EVICT_FAIL;

    mem_event_put_request(d, &d->mem_event->paging, &req);
}

/**
 * p2m_mem_paging_populate - Tell pager to populete a paged page
 * @d: guest domain
 * @gfn: guest page in paging state
 *
 * p2m_mem_paging_populate() will notify the pager that a page in any of the
 * paging states needs to be written back into the guest.
 * This function needs to be called whenever gfn_to_mfn() returns any of the p2m
 * paging types because the gfn may not be backed by a mfn.
 *
 * The gfn can be in any of the paging states, but the pager needs only be
 * notified when the gfn is in the paging-out path (paging_out or paged).  This
 * function may be called more than once from several vcpus. If the vcpu belongs
 * to the guest, the vcpu must be stopped and the pager notified that the vcpu
 * was stopped. The pager needs to handle several requests for the same gfn.
 *
 * If the gfn is not in the paging-out path and the vcpu does not belong to the
 * guest, nothing needs to be done and the function assumes that a request was
 * already sent to the pager. In this case the caller has to try again until the
 * gfn is fully paged in again.
 */
void p2m_mem_paging_populate(struct domain *d, unsigned long gfn)
{
    struct vcpu *v = current;
    mem_event_request_t req = { .gfn = gfn };
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /* We're paging. There should be a ring */
    int rc = mem_event_claim_slot(d, &d->mem_event->paging);
    if ( rc == -ENOSYS )
    {
        gdprintk(XENLOG_ERR, "Domain %hu paging gfn %lx yet no ring "
                             "in place\n", d->domain_id, gfn);
        /* Prevent the vcpu from faulting repeatedly on the same gfn */
        if ( v->domain == d )
            vcpu_pause_nosync(v);
        domain_crash(d);
        return;
    }
    else if ( rc < 0 )
        return;

    /* Fix p2m mapping */
    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL);
    /* Allow only nominated or evicted pages to enter page-in path */
    if ( p2mt == p2m_ram_paging_out || p2mt == p2m_ram_paged )
    {
        /* Evict will fail now, tag this request for pager */
        if ( p2mt == p2m_ram_paging_out )
            req.flags |= MEM_EVENT_FLAG_EVICT_FAIL;

        p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_ram_paging_in, a);
    }
    gfn_unlock(p2m, gfn, 0);

    /* Pause domain if request came from guest and gfn has paging type */
    if ( p2m_is_paging(p2mt) && v->domain == d )
    {
        mem_event_vcpu_pause(v);
        req.flags |= MEM_EVENT_FLAG_VCPU_PAUSED;
    }
    /* No need to inform pager if the gfn is not in the page-out path */
    else if ( p2mt != p2m_ram_paging_out && p2mt != p2m_ram_paged )
    {
        /* gfn is already on its way back and vcpu is not paused */
        mem_event_cancel_slot(d, &d->mem_event->paging);
        return;
    }

    /* Send request to pager */
    req.p2mt = p2mt;
    req.vcpu_id = v->vcpu_id;

    mem_event_put_request(d, &d->mem_event->paging, &req);
}

/**
 * p2m_mem_paging_prep - Allocate a new page for the guest
 * @d: guest domain
 * @gfn: guest page in paging state
 *
 * p2m_mem_paging_prep() will allocate a new page for the guest if the gfn is
 * not backed by a mfn. It is called by the pager.
 * It is required that the gfn was already populated. The gfn may already have a
 * mfn if populate was called for  gfn which was nominated but not evicted. In
 * this case only the p2mt needs to be forwarded.
 */
int p2m_mem_paging_prep(struct domain *d, unsigned long gfn, uint64_t buffer)
{
    struct page_info *page;
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret, page_extant = 1;
    const void *user_ptr = (const void *) buffer;

    if ( user_ptr )
        /* Sanity check the buffer and bail out early if trouble */
        if ( (buffer & (PAGE_SIZE - 1)) || 
             (!access_ok(user_ptr, PAGE_SIZE)) )
            return -EINVAL;

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL);

    ret = -ENOENT;
    /* Allow missing pages */
    if ( (p2mt != p2m_ram_paging_in) && (p2mt != p2m_ram_paged) )
        goto out;

    /* Allocate a page if the gfn does not have one yet */
    if ( !mfn_valid(mfn) )
    {
        /* If the user did not provide a buffer, we disallow */
        ret = -EINVAL;
        if ( unlikely(user_ptr == NULL) )
            goto out;
        /* Get a free page */
        ret = -ENOMEM;
        page = alloc_domheap_page(p2m->domain, 0);
        if ( unlikely(page == NULL) )
            goto out;
        mfn = page_to_mfn(page);
        page_extant = 0;
    }

    /* If we were given a buffer, now is the time to use it */
    if ( !page_extant && user_ptr )
    {
        void *guest_map;
        int rc;

        ASSERT( mfn_valid(mfn) );
        guest_map = map_domain_page(mfn_x(mfn));
        rc = copy_from_user(guest_map, user_ptr, PAGE_SIZE);
        unmap_domain_page(guest_map);
        if ( rc )
        {
            gdprintk(XENLOG_ERR, "Failed to load paging-in gfn %lx domain %u "
                                 "bytes left %d\n", gfn, d->domain_id, rc);
            ret = -EFAULT;
            put_page(page); /* Don't leak pages */
            goto out;            
        }
    }

    /* Make the page already guest-accessible. If the pager still has a
     * pending resume operation, it will be idempotent p2m entry-wise,
     * but will unpause the vcpu */
    ret = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                        paging_mode_log_dirty(d) ? p2m_ram_logdirty
                                                 : p2m_ram_rw, a);
    set_gpfn_from_mfn(mfn_x(mfn), gfn);

    if ( !page_extant )
        atomic_dec(&d->paged_pages);

 out:
    gfn_unlock(p2m, gfn, 0);
    return ret;
}

/**
 * p2m_mem_paging_resume - Resume guest gfn and vcpus
 * @d: guest domain
 * @gfn: guest page in paging state
 *
 * p2m_mem_paging_resume() will forward the p2mt of a gfn to ram_rw and all
 * waiting vcpus will be unpaused again. It is called by the pager.
 * 
 * The gfn was previously either evicted and populated, or nominated and
 * populated. If the page was evicted the p2mt will be p2m_ram_paging_in. If
 * the page was just nominated the p2mt will be p2m_ram_paging_in_start because
 * the pager did not call p2m_mem_paging_prep().
 *
 * If the gfn was dropped the vcpu needs to be unpaused.
 */
void p2m_mem_paging_resume(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    mem_event_response_t rsp;
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;

    /* Pull all responses off the ring */
    while( mem_event_get_response(d, &d->mem_event->paging, &rsp) )
    {
        struct vcpu *v;

        if ( rsp.flags & MEM_EVENT_FLAG_DUMMY )
            continue;

        /* Validate the vcpu_id in the response. */
        if ( (rsp.vcpu_id >= d->max_vcpus) || !d->vcpu[rsp.vcpu_id] )
            continue;

        v = d->vcpu[rsp.vcpu_id];

        /* Fix p2m entry if the page was not dropped */
        if ( !(rsp.flags & MEM_EVENT_FLAG_DROP_PAGE) )
        {
            gfn_lock(p2m, rsp.gfn, 0);
            mfn = p2m->get_entry(p2m, rsp.gfn, &p2mt, &a, 0, NULL);
            /* Allow only pages which were prepared properly, or pages which
             * were nominated but not evicted */
            if ( mfn_valid(mfn) && (p2mt == p2m_ram_paging_in) )
            {
                p2m_set_entry(p2m, rsp.gfn, mfn, PAGE_ORDER_4K,
                              paging_mode_log_dirty(d) ? p2m_ram_logdirty :
                              p2m_ram_rw, a);
                set_gpfn_from_mfn(mfn_x(mfn), rsp.gfn);
            }
            gfn_unlock(p2m, rsp.gfn, 0);
        }
        /* Unpause domain */
        if ( rsp.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
            mem_event_vcpu_unpause(v);
    }
}

static void p2m_mem_event_fill_regs(mem_event_request_t *req)
{
    const struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct segment_register seg;
    struct hvm_hw_cpu ctxt;
    struct vcpu *curr = current;

    /* Architecture-specific vmcs/vmcb bits */
    hvm_funcs.save_cpu_ctxt(curr, &ctxt);

    req->x86_regs.rax = regs->eax;
    req->x86_regs.rcx = regs->ecx;
    req->x86_regs.rdx = regs->edx;
    req->x86_regs.rbx = regs->ebx;
    req->x86_regs.rsp = regs->esp;
    req->x86_regs.rbp = regs->ebp;
    req->x86_regs.rsi = regs->esi;
    req->x86_regs.rdi = regs->edi;

    req->x86_regs.r8  = regs->r8;
    req->x86_regs.r9  = regs->r9;
    req->x86_regs.r10 = regs->r10;
    req->x86_regs.r11 = regs->r11;
    req->x86_regs.r12 = regs->r12;
    req->x86_regs.r13 = regs->r13;
    req->x86_regs.r14 = regs->r14;
    req->x86_regs.r15 = regs->r15;

    req->x86_regs.rflags = regs->eflags;
    req->x86_regs.rip    = regs->eip;

    req->x86_regs.dr7 = curr->arch.debugreg[7];
    req->x86_regs.cr0 = ctxt.cr0;
    req->x86_regs.cr2 = ctxt.cr2;
    req->x86_regs.cr3 = ctxt.cr3;
    req->x86_regs.cr4 = ctxt.cr4;

    req->x86_regs.sysenter_cs = ctxt.sysenter_cs;
    req->x86_regs.sysenter_esp = ctxt.sysenter_esp;
    req->x86_regs.sysenter_eip = ctxt.sysenter_eip;

    req->x86_regs.msr_efer = ctxt.msr_efer;
    req->x86_regs.msr_star = ctxt.msr_star;
    req->x86_regs.msr_lstar = ctxt.msr_lstar;

    hvm_get_segment_register(curr, x86_seg_fs, &seg);
    req->x86_regs.fs_base = seg.base;

    hvm_get_segment_register(curr, x86_seg_gs, &seg);
    req->x86_regs.gs_base = seg.base;

    hvm_get_segment_register(curr, x86_seg_cs, &seg);
    req->x86_regs.cs_arbytes = seg.attr.bytes;
}

void p2m_mem_event_emulate_check(struct vcpu *v, const mem_event_response_t *rsp)
{
    /* Mark vcpu for skipping one instruction upon rescheduling. */
    if ( rsp->flags & MEM_EVENT_FLAG_EMULATE )
    {
        xenmem_access_t access;
        bool_t violation = 1;

        if ( p2m_get_mem_access(v->domain, rsp->gfn, &access) == 0 )
        {
            switch ( access )
            {
            case XENMEM_access_n:
            case XENMEM_access_n2rwx:
            default:
                violation = rsp->access_r || rsp->access_w || rsp->access_x;
                break;

            case XENMEM_access_r:
                violation = rsp->access_w || rsp->access_x;
                break;

            case XENMEM_access_w:
                violation = rsp->access_r || rsp->access_x;
                break;

            case XENMEM_access_x:
                violation = rsp->access_r || rsp->access_w;
                break;

            case XENMEM_access_rx:
            case XENMEM_access_rx2rw:
                violation = rsp->access_w;
                break;

            case XENMEM_access_wx:
                violation = rsp->access_r;
                break;

            case XENMEM_access_rw:
                violation = rsp->access_x;
                break;

            case XENMEM_access_rwx:
                violation = 0;
                break;
            }
        }

        v->arch.mem_event.emulate_flags = violation ? rsp->flags : 0;
    }
}

void p2m_setup_introspection(struct domain *d)
{
    if ( hvm_funcs.enable_msr_exit_interception )
    {
        d->arch.hvm_domain.introspection_enabled = 1;
        hvm_funcs.enable_msr_exit_interception(d);
    }
}

bool_t p2m_mem_access_check(paddr_t gpa, unsigned long gla,
                            struct npfec npfec,
                            mem_event_request_t **req_ptr)
{
    struct vcpu *v = current;
    unsigned long gfn = gpa >> PAGE_SHIFT;
    struct domain *d = v->domain;    
    struct p2m_domain* p2m = p2m_get_hostp2m(d);
    mfn_t mfn;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    mem_event_request_t *req;
    int rc;
    unsigned long eip = guest_cpu_user_regs()->eip;

    /* First, handle rx2rw conversion automatically.
     * These calls to p2m->set_entry() must succeed: we have the gfn
     * locked and just did a successful get_entry(). */
    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL);

    if ( npfec.write_access && p2ma == p2m_access_rx2rw ) 
    {
        rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2mt, p2m_access_rw);
        ASSERT(rc == 0);
        gfn_unlock(p2m, gfn, 0);
        return 1;
    }
    else if ( p2ma == p2m_access_n2rwx )
    {
        ASSERT(npfec.write_access || npfec.read_access || npfec.insn_fetch);
        rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                            p2mt, p2m_access_rwx);
        ASSERT(rc == 0);
    }
    gfn_unlock(p2m, gfn, 0);

    /* Otherwise, check if there is a memory event listener, and send the message along */
    if ( !mem_event_check_ring(&d->mem_event->access) || !req_ptr ) 
    {
        /* No listener */
        if ( p2m->access_required ) 
        {
            gdprintk(XENLOG_INFO, "Memory access permissions failure, "
                                  "no mem_event listener VCPU %d, dom %d\n",
                                  v->vcpu_id, d->domain_id);
            domain_crash(v->domain);
            return 0;
        }
        else
        {
            gfn_lock(p2m, gfn, 0);
            mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL);
            if ( p2ma != p2m_access_n2rwx )
            {
                /* A listener is not required, so clear the access
                 * restrictions.  This set must succeed: we have the
                 * gfn locked and just did a successful get_entry(). */
                rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                                    p2mt, p2m_access_rwx);
                ASSERT(rc == 0);
            }
            gfn_unlock(p2m, gfn, 0);
            return 1;
        }
    }

    /* The previous mem_event reply does not match the current state. */
    if ( v->arch.mem_event.gpa != gpa || v->arch.mem_event.eip != eip )
    {
        /* Don't emulate the current instruction, send a new mem_event. */
        v->arch.mem_event.emulate_flags = 0;

        /*
         * Make sure to mark the current state to match it again against
         * the new mem_event about to be sent.
         */
        v->arch.mem_event.gpa = gpa;
        v->arch.mem_event.eip = eip;
    }

    if ( v->arch.mem_event.emulate_flags )
    {
        hvm_mem_event_emulate_one((v->arch.mem_event.emulate_flags &
                                   MEM_EVENT_FLAG_EMULATE_NOWRITE) != 0,
                                  TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);

        v->arch.mem_event.emulate_flags = 0;
        return 1;
    }

    *req_ptr = NULL;
    req = xzalloc(mem_event_request_t);
    if ( req )
    {
        *req_ptr = req;
        req->reason = MEM_EVENT_REASON_VIOLATION;

        /* Pause the current VCPU */
        if ( p2ma != p2m_access_n2rwx )
            req->flags |= MEM_EVENT_FLAG_VCPU_PAUSED;

        /* Send request to mem event */
        req->gfn = gfn;
        req->offset = gpa & ((1 << PAGE_SHIFT) - 1);
        req->gla_valid = npfec.gla_valid;
        req->gla = gla;
        if ( npfec.kind == npfec_kind_with_gla )
            req->fault_with_gla = 1;
        else if ( npfec.kind == npfec_kind_in_gpt )
            req->fault_in_gpt = 1;
        req->access_r = npfec.read_access;
        req->access_w = npfec.write_access;
        req->access_x = npfec.insn_fetch;
        req->vcpu_id = v->vcpu_id;

        p2m_mem_event_fill_regs(req);
    }

    /* Pause the current VCPU */
    if ( p2ma != p2m_access_n2rwx )
        mem_event_vcpu_pause(v);

    /* VCPU may be paused, return whether we promoted automatically */
    return (p2ma == p2m_access_n2rwx);
}

/* Set access type for a region of pfns.
 * If start_pfn == -1ul, sets the default access type */
long p2m_set_mem_access(struct domain *d, unsigned long pfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_access_t a, _a;
    p2m_type_t t;
    mfn_t mfn;
    long rc = 0;

    static const p2m_access_t memaccess[] = {
#define ACCESS(ac) [XENMEM_access_##ac] = p2m_access_##ac
        ACCESS(n),
        ACCESS(r),
        ACCESS(w),
        ACCESS(rw),
        ACCESS(x),
        ACCESS(rx),
        ACCESS(wx),
        ACCESS(rwx),
        ACCESS(rx2rw),
        ACCESS(n2rwx),
#undef ACCESS
    };

    switch ( access )
    {
    case 0 ... ARRAY_SIZE(memaccess) - 1:
        a = memaccess[access];
        break;
    case XENMEM_access_default:
        a = p2m->default_access;
        break;
    default:
        return -EINVAL;
    }

    /* If request to set default access */
    if ( pfn == ~0ul )
    {
        p2m->default_access = a;
        return 0;
    }

    p2m_lock(p2m);
    for ( pfn += start; nr > start; ++pfn )
    {
        mfn = p2m->get_entry(p2m, pfn, &t, &_a, 0, NULL);
        rc = p2m->set_entry(p2m, pfn, mfn, PAGE_ORDER_4K, t, a);
        if ( rc )
            break;

        /* Check for continuation if it's not the last iteration. */
        if ( nr > ++start && !(start & mask) && hypercall_preempt_check() )
        {
            rc = start;
            break;
        }
    }
    p2m_unlock(p2m);
    return rc;
}

/* Get access type for a pfn
 * If pfn == -1ul, gets the default access type */
int p2m_get_mem_access(struct domain *d, unsigned long pfn, 
                       xenmem_access_t *access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t t;
    p2m_access_t a;
    mfn_t mfn;

    static const xenmem_access_t memaccess[] = {
#define ACCESS(ac) [p2m_access_##ac] = XENMEM_access_##ac
            ACCESS(n),
            ACCESS(r),
            ACCESS(w),
            ACCESS(rw),
            ACCESS(x),
            ACCESS(rx),
            ACCESS(wx),
            ACCESS(rwx),
            ACCESS(rx2rw),
            ACCESS(n2rwx),
#undef ACCESS
    };

    /* If request to get default access */
    if ( pfn == ~0ull ) 
    {
        *access = memaccess[p2m->default_access];
        return 0;
    }

    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, pfn, &t, &a, 0, NULL);
    gfn_unlock(p2m, gfn, 0);

    if ( mfn_x(mfn) == INVALID_MFN )
        return -ESRCH;
    
    if ( (unsigned) a >= ARRAY_SIZE(memaccess) )
        return -ERANGE;

    *access =  memaccess[a];
    return 0;
}

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
    /* Nested p2m's do not do pod, hence the asserts (and no pod lock)*/
    ASSERT(page_list_empty(&p2m->pod.super));
    ASSERT(page_list_empty(&p2m->pod.single));

    /* This is no longer a valid nested p2m for any address space */
    p2m->np2m_base = P2M_BASE_EADDR;
    
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
    ASSERT(v->domain == p2m->domain);
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
p2m_get_nestedp2m(struct vcpu *v, uint64_t np2m_base)
{
    /* Use volatile to prevent gcc to cache nv->nv_p2m in a cpu register as
     * this may change within the loop by an other (v)cpu.
     */
    volatile struct nestedvcpu *nv = &vcpu_nestedhvm(v);
    struct domain *d;
    struct p2m_domain *p2m;

    /* Mask out low bits; this avoids collisions with P2M_BASE_EADDR */
    np2m_base &= ~(0xfffull);

    if (nv->nv_flushp2m && nv->nv_p2m) {
        nv->nv_p2m = NULL;
    }

    d = v->domain;
    nestedp2m_lock(d);
    p2m = nv->nv_p2m;
    if ( p2m ) 
    {
        p2m_lock(p2m);
        if ( p2m->np2m_base == np2m_base || p2m->np2m_base == P2M_BASE_EADDR )
        {
            nv->nv_flushp2m = 0;
            p2m_getlru_nestedp2m(d, p2m);
            nv->nv_p2m = p2m;
            if ( p2m->np2m_base == P2M_BASE_EADDR )
                hvm_asid_flush_vcpu(v);
            p2m->np2m_base = np2m_base;
            cpumask_set_cpu(v->processor, p2m->dirty_cpumask);
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
    p2m->np2m_base = np2m_base;
    nv->nv_flushp2m = 0;
    hvm_asid_flush_vcpu(v);
    cpumask_set_cpu(v->processor, p2m->dirty_cpumask);
    p2m_unlock(p2m);
    nestedp2m_unlock(d);

    return p2m;
}

struct p2m_domain *
p2m_get_p2m(struct vcpu *v)
{
    if (!nestedhvm_is_n2(v))
        return p2m_get_hostp2m(v->domain);

    return p2m_get_nestedp2m(v, nhvm_vcpu_p2m_base(v));
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
        uint32_t pfec_21 = *pfec;
        uint64_t np2m_base = nhvm_vcpu_p2m_base(v);

        /* translate l2 guest va into l2 guest gfn */
        p2m = p2m_get_nestedp2m(v, np2m_base);
        mode = paging_get_nestedmode(v);
        gfn = mode->gva_to_gfn(v, p2m, va, pfec);

        /* translate l2 guest gfn into l1 guest gfn */
        return hostmode->p2m_ga_to_gfn(v, hostp2m, np2m_base,
                                       gfn << PAGE_SHIFT, &pfec_21, NULL);
    }

    return hostmode->gva_to_gfn(v, hostp2m, va, pfec);
}

int map_mmio_regions(struct domain *d,
                     unsigned long start_gfn,
                     unsigned long nr,
                     unsigned long mfn)
{
    int ret = 0;
    unsigned long i;

    if ( !paging_mode_translate(d) )
        return 0;

    for ( i = 0; !ret && i < nr; i++ )
    {
        ret = set_mmio_p2m_entry(d, start_gfn + i, _mfn(mfn + i));
        if ( ret )
        {
            unmap_mmio_regions(d, start_gfn, i, mfn);
            break;
        }
    }

    return ret;
}

int unmap_mmio_regions(struct domain *d,
                       unsigned long start_gfn,
                       unsigned long nr,
                       unsigned long mfn)
{
    int err = 0;
    unsigned long i;

    if ( !paging_mode_translate(d) )
        return 0;

    for ( i = 0; i < nr; i++ )
    {
        int ret = clear_mmio_p2m_entry(d, start_gfn + i, _mfn(mfn + i));
        if ( ret )
            err = ret;
    }

    return err;
}

/*** Audit ***/

#if P2M_AUDIT
void audit_p2m(struct domain *d,
               uint64_t *orphans,
                uint64_t *m2p_bad,
                uint64_t *p2m_bad)
{
    struct page_info *page;
    struct domain *od;
    unsigned long mfn, gfn;
    mfn_t p2mfn;
    unsigned long orphans_count = 0, mpbad = 0, pmbad = 0;
    p2m_access_t p2ma;
    p2m_type_t type;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        goto out_p2m_audit;

    P2M_PRINTK("p2m audit starts\n");

    p2m_lock(p2m);
    pod_lock(p2m);

    if (p2m->audit_p2m)
        pmbad = p2m->audit_p2m(p2m);

    /* Audit part two: walk the domain's page allocation list, checking
     * the m2p entries. */
    spin_lock(&d->page_alloc_lock);
    page_list_for_each ( page, &d->page_list )
    {
        mfn = mfn_x(page_to_mfn(page));

        P2M_PRINTK("auditing guest page, mfn=%#lx\n", mfn);

        od = page_get_owner(page);

        if ( od != d )
        {
            P2M_PRINTK("wrong owner %#lx -> %p(%u) != %p(%u)\n",
                       mfn, od, (od?od->domain_id:-1), d, d->domain_id);
            continue;
        }

        gfn = get_gpfn_from_mfn(mfn);
        if ( gfn == INVALID_M2P_ENTRY )
        {
            orphans_count++;
            P2M_PRINTK("orphaned guest page: mfn=%#lx has invalid gfn\n",
                           mfn);
            continue;
        }

        if ( gfn == SHARED_M2P_ENTRY )
        {
            P2M_PRINTK("shared mfn (%lx) on domain page list!\n",
                    mfn);
            continue;
        }

        p2mfn = get_gfn_type_access(p2m, gfn, &type, &p2ma, 0, NULL);
        if ( mfn_x(p2mfn) != mfn )
        {
            mpbad++;
            P2M_PRINTK("map mismatch mfn %#lx -> gfn %#lx -> mfn %#lx"
                       " (-> gfn %#lx)\n",
                       mfn, gfn, mfn_x(p2mfn),
                       (mfn_valid(p2mfn)
                        ? get_gpfn_from_mfn(mfn_x(p2mfn))
                        : -1u));
            /* This m2p entry is stale: the domain has another frame in
             * this physical slot.  No great disaster, but for neatness,
             * blow away the m2p entry. */
            set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
        }
        __put_gfn(p2m, gfn);

        P2M_PRINTK("OK: mfn=%#lx, gfn=%#lx, p2mfn=%#lx\n",
                       mfn, gfn, mfn_x(p2mfn));
    }
    spin_unlock(&d->page_alloc_lock);

    pod_unlock(p2m);
    p2m_unlock(p2m);
 
    P2M_PRINTK("p2m audit complete\n");
    if ( orphans_count | mpbad | pmbad )
        P2M_PRINTK("p2m audit found %lu orphans\n", orphans_count);
    if ( mpbad | pmbad )
    {
        P2M_PRINTK("p2m audit found %lu odd p2m, %lu bad m2p entries\n",
                   pmbad, mpbad);
        WARN();
    }

out_p2m_audit:
    *orphans = (uint64_t) orphans_count;
    *m2p_bad = (uint64_t) mpbad;
    *p2m_bad = (uint64_t) pmbad;
}
#endif /* P2M_AUDIT */

/*
 * Add frame from foreign domain to target domain's physmap. Similar to
 * XENMAPSPACE_gmfn but the frame is foreign being mapped into current,
 * and is not removed from foreign domain.
 *
 * Usage: - libxl on pvh dom0 creating a guest and doing privcmd_ioctl_mmap.
 *        - xentrace running on dom0 mapping xenheap pages. foreigndom would
 *          be DOMID_XEN in such a case.
 *        etc..
 *
 * Side Effect: the mfn for fgfn will be refcounted in lower level routines
 *              so it is not lost while mapped here. The refcnt is released
 *              via the XENMEM_remove_from_physmap path.
 *
 * Returns: 0 ==> success
 */
int p2m_add_foreign(struct domain *tdom, unsigned long fgfn,
                    unsigned long gpfn, domid_t foreigndom)
{
    p2m_type_t p2mt, p2mt_prev;
    unsigned long prev_mfn, mfn;
    struct page_info *page;
    int rc;
    struct domain *fdom;

    ASSERT(tdom);
    if ( foreigndom == DOMID_SELF || !is_pvh_domain(tdom) )
        return -EINVAL;
    /*
     * pvh fixme: until support is added to p2m teardown code to cleanup any
     * foreign entries, limit this to hardware domain only.
     */
    if ( !is_hardware_domain(tdom) )
        return -EPERM;

    if ( foreigndom == DOMID_XEN )
        fdom = rcu_lock_domain(dom_xen);
    else
        fdom = rcu_lock_domain_by_id(foreigndom);
    if ( fdom == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( tdom == fdom )
        goto out;

    rc = xsm_map_gmfn_foreign(XSM_TARGET, tdom, fdom);
    if ( rc )
        goto out;

    /*
     * Take a refcnt on the mfn. NB: following supported for foreign mapping:
     *     ram_rw | ram_logdirty | ram_ro | paging_out.
     */
    page = get_page_from_gfn(fdom, fgfn, &p2mt, P2M_ALLOC);
    if ( !page ||
         !p2m_is_ram(p2mt) || p2m_is_shared(p2mt) || p2m_is_hole(p2mt) )
    {
        if ( page )
            put_page(page);
        rc = -EINVAL;
        goto out;
    }
    mfn = mfn_x(page_to_mfn(page));

    /* Remove previously mapped page if it is present. */
    prev_mfn = mfn_x(get_gfn(tdom, gpfn, &p2mt_prev));
    if ( mfn_valid(_mfn(prev_mfn)) )
    {
        if ( is_xen_heap_mfn(prev_mfn) )
            /* Xen heap frames are simply unhooked from this phys slot */
            guest_physmap_remove_page(tdom, gpfn, prev_mfn, 0);
        else
            /* Normal domain memory is freed, to avoid leaking memory. */
            guest_remove_page(tdom, gpfn);
    }
    /*
     * Create the new mapping. Can't use guest_physmap_add_page() because it
     * will update the m2p table which will result in  mfn -> gpfn of dom0
     * and not fgfn of domU.
     */
    rc = set_foreign_p2m_entry(tdom, gpfn, _mfn(mfn));
    if ( rc )
        gdprintk(XENLOG_WARNING, "set_foreign_p2m_entry failed. "
                 "gpfn:%lx mfn:%lx fgfn:%lx td:%d fd:%d\n",
                 gpfn, mfn, fgfn, tdom->domain_id, fdom->domain_id);

    put_page(page);

    /*
     * This put_gfn for the above get_gfn for prev_mfn.  We must do this
     * after set_foreign_p2m_entry so another cpu doesn't populate the gpfn
     * before us.
     */
    put_gfn(tdom, gpfn);

out:
    if ( fdom )
        rcu_unlock_domain(fdom);
    return rc;
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
