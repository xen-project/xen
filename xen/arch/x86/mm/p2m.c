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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/iommu.h>
#include <xen/vm_event.h>
#include <xen/event.h>
#include <public/vm_event.h>
#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h> /* ept_p2m_init() */
#include <asm/mem_sharing.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/altp2m.h>
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
    p2m->p2m_class = p2m_host;

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
        p2m->p2m_class = p2m_nested;
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

static void p2m_teardown_altp2m(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( !d->arch.altp2m_p2m[i] )
            continue;
        p2m = d->arch.altp2m_p2m[i];
        d->arch.altp2m_p2m[i] = NULL;
        p2m_free_one(p2m);
    }
}

static int p2m_init_altp2m(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    mm_lock_init(&d->arch.altp2m_list_lock);
    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        d->arch.altp2m_p2m[i] = p2m = p2m_init_one(d);
        if ( p2m == NULL )
        {
            p2m_teardown_altp2m(d);
            return -ENOMEM;
        }
        p2m->p2m_class = p2m_alternate;
        p2m->access_required = 1;
        _atomic_set(&p2m->active_vcpus, 0);
    }

    return 0;
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
    {
        p2m_teardown_hostp2m(d);
        return rc;
    }

    rc = p2m_init_altp2m(d);
    if ( rc )
    {
        p2m_teardown_hostp2m(d);
        p2m_teardown_nestedp2m(d);
    }

    return rc;
}

int p2m_is_logdirty_range(struct p2m_domain *p2m, unsigned long start,
                          unsigned long end)
{
    ASSERT(p2m_is_hostp2m(p2m));
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

void p2m_enable_hardware_log_dirty(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( p2m->enable_hardware_log_dirty )
    {
        p2m_lock(p2m);
        p2m->enable_hardware_log_dirty(p2m);
        p2m_unlock(p2m);
    }
}

void p2m_disable_hardware_log_dirty(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( p2m->disable_hardware_log_dirty )
    {
        p2m_lock(p2m);
        p2m->disable_hardware_log_dirty(p2m);
        p2m_unlock(p2m);
    }
}

void p2m_flush_hardware_cached_dirty(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( p2m->flush_hardware_cached_dirty )
    {
        p2m_lock(p2m);
        p2m->flush_hardware_cached_dirty(p2m);
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

    mfn = p2m->get_entry(p2m, gfn, t, a, q, page_order, NULL);

    if ( (q & P2M_UNSHARE) && p2m_is_shared(*t) )
    {
        ASSERT(p2m_is_hostp2m(p2m));
        /* Try to unshare. If we fail, communicate ENOMEM without
         * sleeping. */
        if ( mem_sharing_unshare_page(p2m->domain, gfn, 0) < 0 )
            (void)mem_sharing_notify_enomem(p2m->domain, gfn, 0);
        mfn = p2m->get_entry(p2m, gfn, t, a, q, page_order, NULL);
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

        set_rc = p2m->set_entry(p2m, gfn, mfn, order, p2mt, p2ma, -1);
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

    if ( p2m_is_hostp2m(p2m)
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
            mfn_return = p2m->get_entry(p2m, gfn + i, &t, &a, 0, NULL, NULL);
            if ( !p2m_is_grant(t) && !p2m_is_shared(t) && !p2m_is_foreign(t) )
                set_gpfn_from_mfn(mfn+i, INVALID_M2P_ENTRY);
            ASSERT( !p2m_is_valid(t) || mfn + i == mfn_x(mfn_return) );
        }
    }
    return p2m_set_entry(p2m, gfn, _mfn(INVALID_MFN), page_order, p2m_invalid,
                         p2m->default_access);
}

int
guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                          unsigned long mfn, unsigned int page_order)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc;
    gfn_lock(p2m, gfn, page_order);
    rc = p2m_remove_page(p2m, gfn, mfn, page_order);
    gfn_unlock(p2m, gfn, page_order);
    return rc;
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
        omfn = p2m->get_entry(p2m, gfn + i, &ot, &a, 0, NULL, NULL);
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
            omfn = p2m->get_entry(p2m, gfn + i, &ot, &a, 0, NULL, NULL);
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
            omfn = p2m->get_entry(p2m, ogfn, &ot, &a, 0, NULL, NULL);
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

    mfn = p2m->get_entry(p2m, gfn, &pt, &a, 0, NULL, NULL);
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
                               p2m_type_t gfn_p2mt, p2m_access_t access)
{
    int rc = 0;
    p2m_access_t a;
    p2m_type_t ot;
    mfn_t omfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return -EIO;

    gfn_lock(p2m, gfn, 0);
    omfn = p2m->get_entry(p2m, gfn, &ot, &a, 0, NULL, NULL);
    if ( p2m_is_grant(ot) || p2m_is_foreign(ot) )
    {
        gfn_unlock(p2m, gfn, 0);
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
                       access);
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
    return set_typed_p2m_entry(d, gfn, mfn, p2m_map_foreign,
                               p2m_get_hostp2m(d)->default_access);
}

int set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn,
                       p2m_access_t access)
{
    return set_typed_p2m_entry(d, gfn, mfn, p2m_mmio_direct, access);
}

int set_identity_p2m_entry(struct domain *d, unsigned long gfn,
                           p2m_access_t p2ma, unsigned int flag)
{
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret;

    if ( !paging_mode_translate(p2m->domain) )
    {
        if ( !need_iommu(d) )
            return 0;
        return iommu_map_page(d, gfn, gfn, IOMMUF_readable|IOMMUF_writable);
    }

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);

    if ( p2mt == p2m_invalid || p2mt == p2m_mmio_dm )
        ret = p2m_set_entry(p2m, gfn, _mfn(gfn), PAGE_ORDER_4K,
                            p2m_mmio_direct, p2ma);
    else if ( mfn_x(mfn) == gfn && p2mt == p2m_mmio_direct && a == p2ma )
    {
        ret = 0;
        /*
         * PVH fixme: during Dom0 PVH construction, p2m entries are being set
         * but iomem regions are not mapped with IOMMU. This makes sure that
         * RMRRs are correctly mapped with IOMMU.
         */
        if ( is_hardware_domain(d) && !iommu_use_hap_pt(d) )
            ret = iommu_map_page(d, gfn, gfn, IOMMUF_readable|IOMMUF_writable);
    }
    else
    {
        if ( flag & XEN_DOMCTL_DEV_RDM_RELAXED )
            ret = 0;
        else
            ret = -EBUSY;
        printk(XENLOG_G_WARNING
               "Cannot setup identity map d%d:%lx,"
               " gfn already mapped to %lx.\n",
               d->domain_id, gfn, mfn_x(mfn));
    }

    gfn_unlock(p2m, gfn, 0);
    return ret;
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
    actual_mfn = p2m->get_entry(p2m, gfn, &t, &a, 0, NULL, NULL);

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

int clear_identity_p2m_entry(struct domain *d, unsigned long gfn)
{
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret;

    if ( !paging_mode_translate(d) )
    {
        if ( !need_iommu(d) )
            return 0;
        return iommu_unmap_page(d, gfn);
    }

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
    if ( p2mt == p2m_mmio_direct && mfn_x(mfn) == gfn )
    {
        ret = p2m_set_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K,
                            p2m_invalid, p2m->default_access);
        gfn_unlock(p2m, gfn, 0);
    }
    else
    {
        gfn_unlock(p2m, gfn, 0);
        printk(XENLOG_G_WARNING
               "non-identity map d%d:%lx not cleared (mapped to %lx)\n",
               d->domain_id, gfn, mfn_x(mfn));
        ret = 0;
    }

    return ret;
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
    omfn = p2m->get_entry(p2m, gfn, &ot, &a, 0, NULL, NULL);
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

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);

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
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
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
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_MEM_PAGING,
        .u.mem_paging.gfn = gfn
    };

    /* We allow no ring in this unique case, because it won't affect
     * correctness of the guest execution at this point.  If this is the only
     * page that happens to be paged-out, we'll be okay..  but it's likely the
     * guest will crash shortly anyways. */
    int rc = vm_event_claim_slot(d, &d->vm_event->paging);
    if ( rc < 0 )
        return;

    /* Send release notification to pager */
    req.u.mem_paging.flags = MEM_PAGING_DROP_PAGE;

    /* Update stats unless the page hasn't yet been evicted */
    if ( p2mt != p2m_ram_paging_out )
        atomic_dec(&d->paged_pages);
    else
        /* Evict will fail now, tag this request for pager */
        req.u.mem_paging.flags |= MEM_PAGING_EVICT_FAIL;

    vm_event_put_request(d, &d->vm_event->paging, &req);
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
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_MEM_PAGING,
        .u.mem_paging.gfn = gfn
    };
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    /* We're paging. There should be a ring */
    int rc = vm_event_claim_slot(d, &d->vm_event->paging);
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
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
    /* Allow only nominated or evicted pages to enter page-in path */
    if ( p2mt == p2m_ram_paging_out || p2mt == p2m_ram_paged )
    {
        /* Evict will fail now, tag this request for pager */
        if ( p2mt == p2m_ram_paging_out )
            req.u.mem_paging.flags |= MEM_PAGING_EVICT_FAIL;

        p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_ram_paging_in, a);
    }
    gfn_unlock(p2m, gfn, 0);

    /* Pause domain if request came from guest and gfn has paging type */
    if ( p2m_is_paging(p2mt) && v->domain == d )
    {
        vm_event_vcpu_pause(v);
        req.flags |= VM_EVENT_FLAG_VCPU_PAUSED;
    }
    /* No need to inform pager if the gfn is not in the page-out path */
    else if ( p2mt != p2m_ram_paging_out && p2mt != p2m_ram_paged )
    {
        /* gfn is already on its way back and vcpu is not paused */
        vm_event_cancel_slot(d, &d->vm_event->paging);
        return;
    }

    /* Send request to pager */
    req.u.mem_paging.p2mt = p2mt;
    req.vcpu_id = v->vcpu_id;

    vm_event_put_request(d, &d->vm_event->paging, &req);
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

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);

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
        guest_map = map_domain_page(mfn);
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
 * p2m_mem_paging_resume - Resume guest gfn
 * @d: guest domain
 * @rsp: vm_event response received
 *
 * p2m_mem_paging_resume() will forward the p2mt of a gfn to ram_rw. It is
 * called by the pager.
 *
 * The gfn was previously either evicted and populated, or nominated and
 * populated. If the page was evicted the p2mt will be p2m_ram_paging_in. If
 * the page was just nominated the p2mt will be p2m_ram_paging_in_start because
 * the pager did not call p2m_mem_paging_prep().
 *
 * If the gfn was dropped the vcpu needs to be unpaused.
 */

void p2m_mem_paging_resume(struct domain *d, vm_event_response_t *rsp)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;

    /* Fix p2m entry if the page was not dropped */
    if ( !(rsp->u.mem_paging.flags & MEM_PAGING_DROP_PAGE) )
    {
        unsigned long gfn = rsp->u.mem_access.gfn;

        gfn_lock(p2m, gfn, 0);
        mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
        /*
         * Allow only pages which were prepared properly, or pages which
         * were nominated but not evicted.
         */
        if ( mfn_valid(mfn) && (p2mt == p2m_ram_paging_in) )
        {
            p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                          paging_mode_log_dirty(d) ? p2m_ram_logdirty :
                          p2m_ram_rw, a);
            set_gpfn_from_mfn(mfn_x(mfn), gfn);
        }
        gfn_unlock(p2m, gfn, 0);
    }
}

static void p2m_vm_event_fill_regs(vm_event_request_t *req)
{
    const struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct segment_register seg;
    struct hvm_hw_cpu ctxt;
    struct vcpu *curr = current;

    /* Architecture-specific vmcs/vmcb bits */
    hvm_funcs.save_cpu_ctxt(curr, &ctxt);

    req->data.regs.x86.rax = regs->eax;
    req->data.regs.x86.rcx = regs->ecx;
    req->data.regs.x86.rdx = regs->edx;
    req->data.regs.x86.rbx = regs->ebx;
    req->data.regs.x86.rsp = regs->esp;
    req->data.regs.x86.rbp = regs->ebp;
    req->data.regs.x86.rsi = regs->esi;
    req->data.regs.x86.rdi = regs->edi;

    req->data.regs.x86.r8  = regs->r8;
    req->data.regs.x86.r9  = regs->r9;
    req->data.regs.x86.r10 = regs->r10;
    req->data.regs.x86.r11 = regs->r11;
    req->data.regs.x86.r12 = regs->r12;
    req->data.regs.x86.r13 = regs->r13;
    req->data.regs.x86.r14 = regs->r14;
    req->data.regs.x86.r15 = regs->r15;

    req->data.regs.x86.rflags = regs->eflags;
    req->data.regs.x86.rip    = regs->eip;

    req->data.regs.x86.dr7 = curr->arch.debugreg[7];
    req->data.regs.x86.cr0 = ctxt.cr0;
    req->data.regs.x86.cr2 = ctxt.cr2;
    req->data.regs.x86.cr3 = ctxt.cr3;
    req->data.regs.x86.cr4 = ctxt.cr4;

    req->data.regs.x86.sysenter_cs = ctxt.sysenter_cs;
    req->data.regs.x86.sysenter_esp = ctxt.sysenter_esp;
    req->data.regs.x86.sysenter_eip = ctxt.sysenter_eip;

    req->data.regs.x86.msr_efer = ctxt.msr_efer;
    req->data.regs.x86.msr_star = ctxt.msr_star;
    req->data.regs.x86.msr_lstar = ctxt.msr_lstar;

    hvm_get_segment_register(curr, x86_seg_fs, &seg);
    req->data.regs.x86.fs_base = seg.base;

    hvm_get_segment_register(curr, x86_seg_gs, &seg);
    req->data.regs.x86.gs_base = seg.base;

    hvm_get_segment_register(curr, x86_seg_cs, &seg);
    req->data.regs.x86.cs_arbytes = seg.attr.bytes;
}

void p2m_mem_access_emulate_check(struct vcpu *v,
                                  const vm_event_response_t *rsp)
{
    /* Mark vcpu for skipping one instruction upon rescheduling. */
    if ( rsp->flags & VM_EVENT_FLAG_EMULATE )
    {
        xenmem_access_t access;
        bool_t violation = 1;
        const struct vm_event_mem_access *data = &rsp->u.mem_access;

        if ( p2m_get_mem_access(v->domain, _gfn(data->gfn), &access) == 0 )
        {
            switch ( access )
            {
            case XENMEM_access_n:
            case XENMEM_access_n2rwx:
            default:
                violation = data->flags & MEM_ACCESS_RWX;
                break;

            case XENMEM_access_r:
                violation = data->flags & MEM_ACCESS_WX;
                break;

            case XENMEM_access_w:
                violation = data->flags & MEM_ACCESS_RX;
                break;

            case XENMEM_access_x:
                violation = data->flags & MEM_ACCESS_RW;
                break;

            case XENMEM_access_rx:
            case XENMEM_access_rx2rw:
                violation = data->flags & MEM_ACCESS_W;
                break;

            case XENMEM_access_wx:
                violation = data->flags & MEM_ACCESS_R;
                break;

            case XENMEM_access_rw:
                violation = data->flags & MEM_ACCESS_X;
                break;

            case XENMEM_access_rwx:
                violation = 0;
                break;
            }
        }

        v->arch.vm_event.emulate_flags = violation ? rsp->flags : 0;

        if ( (rsp->flags & VM_EVENT_FLAG_SET_EMUL_READ_DATA) &&
             v->arch.vm_event.emul_read_data )
            *v->arch.vm_event.emul_read_data = rsp->data.emul_read_data;
    }
}

void p2m_altp2m_check(struct vcpu *v, uint16_t idx)
{
    if ( altp2m_active(v->domain) )
        p2m_switch_vcpu_altp2m_by_id(v, idx);
}

bool_t p2m_mem_access_check(paddr_t gpa, unsigned long gla,
                            struct npfec npfec,
                            vm_event_request_t **req_ptr)
{
    struct vcpu *v = current;
    unsigned long gfn = gpa >> PAGE_SHIFT;
    struct domain *d = v->domain;    
    struct p2m_domain *p2m = NULL;
    mfn_t mfn;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    vm_event_request_t *req;
    int rc;
    unsigned long eip = guest_cpu_user_regs()->eip;

    if ( altp2m_active(d) )
        p2m = p2m_get_altp2m(v);
    if ( !p2m )
        p2m = p2m_get_hostp2m(d);

    /* First, handle rx2rw conversion automatically.
     * These calls to p2m->set_entry() must succeed: we have the gfn
     * locked and just did a successful get_entry(). */
    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL, NULL);

    if ( npfec.write_access && p2ma == p2m_access_rx2rw ) 
    {
        rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2mt, p2m_access_rw, -1);
        ASSERT(rc == 0);
        gfn_unlock(p2m, gfn, 0);
        return 1;
    }
    else if ( p2ma == p2m_access_n2rwx )
    {
        ASSERT(npfec.write_access || npfec.read_access || npfec.insn_fetch);
        rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                            p2mt, p2m_access_rwx, -1);
        ASSERT(rc == 0);
    }
    gfn_unlock(p2m, gfn, 0);

    /* Otherwise, check if there is a memory event listener, and send the message along */
    if ( !vm_event_check_ring(&d->vm_event->monitor) || !req_ptr ) 
    {
        /* No listener */
        if ( p2m->access_required ) 
        {
            gdprintk(XENLOG_INFO, "Memory access permissions failure, "
                                  "no vm_event listener VCPU %d, dom %d\n",
                                  v->vcpu_id, d->domain_id);
            domain_crash(v->domain);
            return 0;
        }
        else
        {
            gfn_lock(p2m, gfn, 0);
            mfn = p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL, NULL);
            if ( p2ma != p2m_access_n2rwx )
            {
                /* A listener is not required, so clear the access
                 * restrictions.  This set must succeed: we have the
                 * gfn locked and just did a successful get_entry(). */
                rc = p2m->set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                                    p2mt, p2m_access_rwx, -1);
                ASSERT(rc == 0);
            }
            gfn_unlock(p2m, gfn, 0);
            return 1;
        }
    }

    /* The previous vm_event reply does not match the current state. */
    if ( v->arch.vm_event.gpa != gpa || v->arch.vm_event.eip != eip )
    {
        /* Don't emulate the current instruction, send a new vm_event. */
        v->arch.vm_event.emulate_flags = 0;

        /*
         * Make sure to mark the current state to match it again against
         * the new vm_event about to be sent.
         */
        v->arch.vm_event.gpa = gpa;
        v->arch.vm_event.eip = eip;
    }

    if ( v->arch.vm_event.emulate_flags )
    {
        enum emul_kind kind = EMUL_KIND_NORMAL;

        if ( v->arch.vm_event.emulate_flags &
             VM_EVENT_FLAG_SET_EMUL_READ_DATA )
            kind = EMUL_KIND_SET_CONTEXT;
        else if ( v->arch.vm_event.emulate_flags &
                  VM_EVENT_FLAG_EMULATE_NOWRITE )
            kind = EMUL_KIND_NOWRITE;

        hvm_mem_access_emulate_one(kind, TRAP_invalid_op,
                                   HVM_DELIVER_NO_ERROR_CODE);

        v->arch.vm_event.emulate_flags = 0;
        return 1;
    }

    *req_ptr = NULL;
    req = xzalloc(vm_event_request_t);
    if ( req )
    {
        *req_ptr = req;
        req->reason = VM_EVENT_REASON_MEM_ACCESS;

        /* Pause the current VCPU */
        if ( p2ma != p2m_access_n2rwx )
            req->flags |= VM_EVENT_FLAG_VCPU_PAUSED;

        /* Send request to mem event */
        req->u.mem_access.gfn = gfn;
        req->u.mem_access.offset = gpa & ((1 << PAGE_SHIFT) - 1);
        if ( npfec.gla_valid )
        {
            req->u.mem_access.flags |= MEM_ACCESS_GLA_VALID;
            req->u.mem_access.gla = gla;

            if ( npfec.kind == npfec_kind_with_gla )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_WITH_GLA;
            else if ( npfec.kind == npfec_kind_in_gpt )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_IN_GPT;
        }
        req->u.mem_access.flags |= npfec.read_access    ? MEM_ACCESS_R : 0;
        req->u.mem_access.flags |= npfec.write_access   ? MEM_ACCESS_W : 0;
        req->u.mem_access.flags |= npfec.insn_fetch     ? MEM_ACCESS_X : 0;
        req->vcpu_id = v->vcpu_id;

        p2m_vm_event_fill_regs(req);

        if ( altp2m_active(v->domain) )
        {
            req->flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
            req->altp2m_idx = vcpu_altp2m(v).p2midx;
        }
    }

    /* Pause the current VCPU */
    if ( p2ma != p2m_access_n2rwx )
        vm_event_vcpu_pause(v);

    /* VCPU may be paused, return whether we promoted automatically */
    return (p2ma == p2m_access_n2rwx);
}

/*
 * Set access type for a region of gfns.
 * If gfn == INVALID_GFN, sets the default access type.
 */
long p2m_set_mem_access(struct domain *d, gfn_t gfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_access_t a, _a;
    p2m_type_t t;
    mfn_t mfn;
    unsigned long gfn_l;
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

    /* If request to set default access. */
    if ( gfn_x(gfn) == INVALID_GFN )
    {
        p2m->default_access = a;
        return 0;
    }

    p2m_lock(p2m);
    for ( gfn_l = gfn_x(gfn) + start; nr > start; ++gfn_l )
    {
        mfn = p2m->get_entry(p2m, gfn_l, &t, &_a, 0, NULL, NULL);
        rc = p2m->set_entry(p2m, gfn_l, mfn, PAGE_ORDER_4K, t, a, -1);
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

/*
 * Get access type for a gfn.
 * If gfn == INVALID_GFN, gets the default access type.
 */
int p2m_get_mem_access(struct domain *d, gfn_t gfn, xenmem_access_t *access)
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

    /* If request to get default access. */
    if ( gfn_x(gfn) == INVALID_GFN )
    {
        *access = memaccess[p2m->default_access];
        return 0;
    }

    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn_x(gfn), &t, &a, 0, NULL, NULL);
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
    ASSERT(!p2m_is_hostp2m(p2m));
    /* Nested p2m's do not do pod, hence the asserts (and no pod lock)*/
    ASSERT(page_list_empty(&p2m->pod.super));
    ASSERT(page_list_empty(&p2m->pod.single));

    if ( p2m->np2m_base == P2M_BASE_EADDR )
    {
        p2m_unlock(p2m);
        return;
    }

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

    if ( is_hvm_vcpu(v) && paging_mode_hap(v->domain) && nestedhvm_is_n2(v) )
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
        ret = set_mmio_p2m_entry(d, start_gfn + i, _mfn(mfn + i),
                                 p2m_get_hostp2m(d)->default_access);
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

unsigned int p2m_find_altp2m_by_eptp(struct domain *d, uint64_t eptp)
{
    struct p2m_domain *p2m;
    struct ept_data *ept;
    unsigned int i;

    altp2m_list_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_eptp[i] == INVALID_MFN )
            continue;

        p2m = d->arch.altp2m_p2m[i];
        ept = &p2m->ept;

        if ( eptp == ept_get_eptp(ept) )
            goto out;
    }

    i = INVALID_ALTP2M;

 out:
    altp2m_list_unlock(d);
    return i;
}

bool_t p2m_switch_vcpu_altp2m_by_id(struct vcpu *v, unsigned int idx)
{
    struct domain *d = v->domain;
    bool_t rc = 0;

    if ( idx >= MAX_ALTP2M )
        return rc;

    altp2m_list_lock(d);

    if ( d->arch.altp2m_eptp[idx] != INVALID_MFN )
    {
        if ( idx != vcpu_altp2m(v).p2midx )
        {
            atomic_dec(&p2m_get_altp2m(v)->active_vcpus);
            vcpu_altp2m(v).p2midx = idx;
            atomic_inc(&p2m_get_altp2m(v)->active_vcpus);
            altp2m_vcpu_update_p2m(v);
        }
        rc = 1;
    }

    altp2m_list_unlock(d);
    return rc;
}

/*
 * If the fault is for a not present entry:
 *     if the entry in the host p2m has a valid mfn, copy it and retry
 *     else indicate that outer handler should handle fault
 *
 * If the fault is for a present entry:
 *     indicate that outer handler should handle fault
 */

bool_t p2m_altp2m_lazy_copy(struct vcpu *v, paddr_t gpa,
                            unsigned long gla, struct npfec npfec,
                            struct p2m_domain **ap2m)
{
    struct p2m_domain *hp2m = p2m_get_hostp2m(v->domain);
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    unsigned int page_order;
    gfn_t gfn = _gfn(paddr_to_pfn(gpa));
    unsigned long mask;
    mfn_t mfn;
    int rv;

    *ap2m = p2m_get_altp2m(v);

    mfn = get_gfn_type_access(*ap2m, gfn_x(gfn), &p2mt, &p2ma,
                              0, &page_order);
    __put_gfn(*ap2m, gfn_x(gfn));

    if ( mfn_x(mfn) != INVALID_MFN )
        return 0;

    mfn = get_gfn_type_access(hp2m, gfn_x(gfn), &p2mt, &p2ma,
                              P2M_ALLOC | P2M_UNSHARE, &page_order);
    __put_gfn(hp2m, gfn_x(gfn));

    if ( mfn_x(mfn) == INVALID_MFN )
        return 0;

    p2m_lock(*ap2m);

    /*
     * If this is a superpage mapping, round down both frame numbers
     * to the start of the superpage.
     */
    mask = ~((1UL << page_order) - 1);
    mfn = _mfn(mfn_x(mfn) & mask);

    rv = p2m_set_entry(*ap2m, gfn_x(gfn) & mask, mfn, page_order, p2mt, p2ma);
    p2m_unlock(*ap2m);

    if ( rv )
    {
        gdprintk(XENLOG_ERR,
	    "failed to set entry for %#"PRIx64" -> %#"PRIx64" p2m %#"PRIx64"\n",
	    gfn_x(gfn), mfn_x(mfn), (unsigned long)*ap2m);
        domain_crash(hp2m->domain);
    }

    return 1;
}

void p2m_flush_altp2m(struct domain *d)
{
    unsigned int i;

    altp2m_list_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        p2m_flush_table(d->arch.altp2m_p2m[i]);
        /* Uninit and reinit ept to force TLB shootdown */
        ept_p2m_uninit(d->arch.altp2m_p2m[i]);
        ept_p2m_init(d->arch.altp2m_p2m[i]);
        d->arch.altp2m_eptp[i] = INVALID_MFN;
    }

    altp2m_list_unlock(d);
}

static void p2m_init_altp2m_helper(struct domain *d, unsigned int i)
{
    struct p2m_domain *p2m = d->arch.altp2m_p2m[i];
    struct ept_data *ept;

    p2m->min_remapped_gfn = INVALID_GFN;
    p2m->max_remapped_gfn = 0;
    ept = &p2m->ept;
    ept->asr = pagetable_get_pfn(p2m_get_pagetable(p2m));
    d->arch.altp2m_eptp[i] = ept_get_eptp(ept);
}

int p2m_init_altp2m_by_id(struct domain *d, unsigned int idx)
{
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M )
        return rc;

    altp2m_list_lock(d);

    if ( d->arch.altp2m_eptp[idx] == INVALID_MFN )
    {
        p2m_init_altp2m_helper(d, idx);
        rc = 0;
    }

    altp2m_list_unlock(d);
    return rc;
}

int p2m_init_next_altp2m(struct domain *d, uint16_t *idx)
{
    int rc = -EINVAL;
    unsigned int i;

    altp2m_list_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_eptp[i] != INVALID_MFN )
            continue;

        p2m_init_altp2m_helper(d, i);
        *idx = i;
        rc = 0;

        break;
    }

    altp2m_list_unlock(d);
    return rc;
}

int p2m_destroy_altp2m_by_id(struct domain *d, unsigned int idx)
{
    struct p2m_domain *p2m;
    int rc = -EBUSY;

    if ( !idx || idx >= MAX_ALTP2M )
        return rc;

    domain_pause_except_self(d);

    altp2m_list_lock(d);

    if ( d->arch.altp2m_eptp[idx] != INVALID_MFN )
    {
        p2m = d->arch.altp2m_p2m[idx];

        if ( !_atomic_read(p2m->active_vcpus) )
        {
            p2m_flush_table(d->arch.altp2m_p2m[idx]);
            /* Uninit and reinit ept to force TLB shootdown */
            ept_p2m_uninit(d->arch.altp2m_p2m[idx]);
            ept_p2m_init(d->arch.altp2m_p2m[idx]);
            d->arch.altp2m_eptp[idx] = INVALID_MFN;
            rc = 0;
        }
    }

    altp2m_list_unlock(d);

    domain_unpause_except_self(d);

    return rc;
}

int p2m_switch_domain_altp2m_by_id(struct domain *d, unsigned int idx)
{
    struct vcpu *v;
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M )
        return rc;

    domain_pause_except_self(d);

    altp2m_list_lock(d);

    if ( d->arch.altp2m_eptp[idx] != INVALID_MFN )
    {
        for_each_vcpu( d, v )
            if ( idx != vcpu_altp2m(v).p2midx )
            {
                atomic_dec(&p2m_get_altp2m(v)->active_vcpus);
                vcpu_altp2m(v).p2midx = idx;
                atomic_inc(&p2m_get_altp2m(v)->active_vcpus);
                altp2m_vcpu_update_p2m(v);
            }

        rc = 0;
    }

    altp2m_list_unlock(d);

    domain_unpause_except_self(d);

    return rc;
}

int p2m_set_altp2m_mem_access(struct domain *d, unsigned int idx,
                              gfn_t gfn, xenmem_access_t access)
{
    struct p2m_domain *hp2m, *ap2m;
    p2m_access_t req_a, old_a;
    p2m_type_t t;
    mfn_t mfn;
    unsigned int page_order;
    int rc = -EINVAL;

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
#undef ACCESS
    };

    if ( idx >= MAX_ALTP2M || d->arch.altp2m_eptp[idx] == INVALID_MFN )
        return rc;

    ap2m = d->arch.altp2m_p2m[idx];

    switch ( access )
    {
    case 0 ... ARRAY_SIZE(memaccess) - 1:
        req_a = memaccess[access];
        break;
    case XENMEM_access_default:
        req_a = ap2m->default_access;
        break;
    default:
        return rc;
    }

    /* If request to set default access */
    if ( gfn_x(gfn) == INVALID_GFN )
    {
        ap2m->default_access = req_a;
        return 0;
    }

    hp2m = p2m_get_hostp2m(d);

    p2m_lock(ap2m);

    mfn = ap2m->get_entry(ap2m, gfn_x(gfn), &t, &old_a, 0, NULL, NULL);

    /* Check host p2m if no valid entry in alternate */
    if ( !mfn_valid(mfn) )
    {
        mfn = hp2m->get_entry(hp2m, gfn_x(gfn), &t, &old_a,
                              P2M_ALLOC | P2M_UNSHARE, &page_order, NULL);

        if ( !mfn_valid(mfn) || t != p2m_ram_rw )
            goto out;

        /* If this is a superpage, copy that first */
        if ( page_order != PAGE_ORDER_4K )
        {
            gfn_t gfn2;
            unsigned long mask;
            mfn_t mfn2;

            mask = ~((1UL << page_order) - 1);
            gfn2 = _gfn(gfn_x(gfn) & mask);
            mfn2 = _mfn(mfn_x(mfn) & mask);

            if ( ap2m->set_entry(ap2m, gfn_x(gfn2), mfn2, page_order, t, old_a, 1) )
                goto out;
        }
    }

    if ( !ap2m->set_entry(ap2m, gfn_x(gfn), mfn, PAGE_ORDER_4K, t, req_a,
                          (current->domain != d)) )
        rc = 0;

 out:
    p2m_unlock(ap2m);
    return rc;
}

int p2m_change_altp2m_gfn(struct domain *d, unsigned int idx,
                          gfn_t old_gfn, gfn_t new_gfn)
{
    struct p2m_domain *hp2m, *ap2m;
    p2m_access_t a;
    p2m_type_t t;
    mfn_t mfn;
    unsigned int page_order;
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M || d->arch.altp2m_eptp[idx] == INVALID_MFN )
        return rc;

    hp2m = p2m_get_hostp2m(d);
    ap2m = d->arch.altp2m_p2m[idx];

    p2m_lock(ap2m);

    mfn = ap2m->get_entry(ap2m, gfn_x(old_gfn), &t, &a, 0, NULL, NULL);

    if ( gfn_x(new_gfn) == INVALID_GFN )
    {
        if ( mfn_valid(mfn) )
            p2m_remove_page(ap2m, gfn_x(old_gfn), mfn_x(mfn), PAGE_ORDER_4K);
        rc = 0;
        goto out;
    }

    /* Check host p2m if no valid entry in alternate */
    if ( !mfn_valid(mfn) )
    {
        mfn = hp2m->get_entry(hp2m, gfn_x(old_gfn), &t, &a,
                              P2M_ALLOC | P2M_UNSHARE, &page_order, NULL);

        if ( !mfn_valid(mfn) || t != p2m_ram_rw )
            goto out;

        /* If this is a superpage, copy that first */
        if ( page_order != PAGE_ORDER_4K )
        {
            gfn_t gfn;
            unsigned long mask;

            mask = ~((1UL << page_order) - 1);
            gfn = _gfn(gfn_x(old_gfn) & mask);
            mfn = _mfn(mfn_x(mfn) & mask);

            if ( ap2m->set_entry(ap2m, gfn_x(gfn), mfn, page_order, t, a, 1) )
                goto out;
        }
    }

    mfn = ap2m->get_entry(ap2m, gfn_x(new_gfn), &t, &a, 0, NULL, NULL);

    if ( !mfn_valid(mfn) )
        mfn = hp2m->get_entry(hp2m, gfn_x(new_gfn), &t, &a, 0, NULL, NULL);

    if ( !mfn_valid(mfn) || (t != p2m_ram_rw) )
        goto out;

    if ( !ap2m->set_entry(ap2m, gfn_x(old_gfn), mfn, PAGE_ORDER_4K, t, a,
                          (current->domain != d)) )
    {
        rc = 0;

        if ( gfn_x(new_gfn) < ap2m->min_remapped_gfn )
            ap2m->min_remapped_gfn = gfn_x(new_gfn);
        if ( gfn_x(new_gfn) > ap2m->max_remapped_gfn )
            ap2m->max_remapped_gfn = gfn_x(new_gfn);
    }

 out:
    p2m_unlock(ap2m);
    return rc;
}

static void p2m_reset_altp2m(struct p2m_domain *p2m)
{
    p2m_flush_table(p2m);
    /* Uninit and reinit ept to force TLB shootdown */
    ept_p2m_uninit(p2m);
    ept_p2m_init(p2m);
    p2m->min_remapped_gfn = INVALID_GFN;
    p2m->max_remapped_gfn = 0;
}

void p2m_altp2m_propagate_change(struct domain *d, gfn_t gfn,
                                 mfn_t mfn, unsigned int page_order,
                                 p2m_type_t p2mt, p2m_access_t p2ma)
{
    struct p2m_domain *p2m;
    p2m_access_t a;
    p2m_type_t t;
    mfn_t m;
    unsigned int i;
    unsigned int reset_count = 0;
    unsigned int last_reset_idx = ~0;

    if ( !altp2m_active(d) )
        return;

    altp2m_list_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_eptp[i] == INVALID_MFN )
            continue;

        p2m = d->arch.altp2m_p2m[i];
        m = get_gfn_type_access(p2m, gfn_x(gfn), &t, &a, 0, NULL);

        /* Check for a dropped page that may impact this altp2m */
        if ( mfn_x(mfn) == INVALID_MFN &&
             gfn_x(gfn) >= p2m->min_remapped_gfn &&
             gfn_x(gfn) <= p2m->max_remapped_gfn )
        {
            if ( !reset_count++ )
            {
                p2m_reset_altp2m(p2m);
                last_reset_idx = i;
            }
            else
            {
                /* At least 2 altp2m's impacted, so reset everything */
                __put_gfn(p2m, gfn_x(gfn));

                for ( i = 0; i < MAX_ALTP2M; i++ )
                {
                    if ( i == last_reset_idx ||
                         d->arch.altp2m_eptp[i] == INVALID_MFN )
                        continue;

                    p2m = d->arch.altp2m_p2m[i];
                    p2m_lock(p2m);
                    p2m_reset_altp2m(p2m);
                    p2m_unlock(p2m);
                }

                goto out;
            }
        }
        else if ( mfn_x(m) != INVALID_MFN )
            p2m_set_entry(p2m, gfn_x(gfn), mfn, page_order, p2mt, p2ma);

        __put_gfn(p2m, gfn_x(gfn));
    }

 out:
    altp2m_list_unlock(d);
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
