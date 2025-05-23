/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/mm/p2m-pod.c
 *
 * Populate-on-demand p2m entries.
 *
 * Copyright (c) 2009-2011 Citrix Systems, Inc.
 */

#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/ioreq.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/trace.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>

#include "mm-locks.h"
#include "p2m.h"

#define superpage_aligned(_x)  (((_x)&(SUPERPAGE_PAGES-1))==0)

/* Enforce lock ordering when grabbing the "external" page_alloc lock */
static always_inline void lock_page_alloc(struct p2m_domain *p2m)
{
    page_alloc_mm_pre_lock(p2m->domain);
    nrspin_lock(&(p2m->domain->page_alloc_lock));
    page_alloc_mm_post_lock(p2m->domain,
                            p2m->domain->arch.page_alloc_unlock_level);
}

static inline void unlock_page_alloc(struct p2m_domain *p2m)
{
    page_alloc_mm_unlock(p2m->domain->arch.page_alloc_unlock_level);
    nrspin_unlock(&(p2m->domain->page_alloc_lock));
}

/*
 * Populate-on-demand functionality
 */

static int
p2m_pod_cache_add(struct p2m_domain *p2m,
                  struct page_info *page,
                  unsigned int order)
{
    unsigned long i;
    struct domain *d = p2m->domain;
    mfn_t mfn = page_to_mfn(page);

#ifndef NDEBUG
    /* Check to make sure this is a contiguous region */
    if ( mfn_x(mfn) & ((1UL << order) - 1) )
    {
        printk("%s: mfn %lx not aligned order %u! (mask %lx)\n",
               __func__, mfn_x(mfn), order, ((1UL << order) - 1));
        return -EINVAL;
    }

    for ( i = 0; i < (1UL << order); i++)
    {
        const struct domain *od = page_get_owner(page + i);

        if ( od != d )
        {
            printk("%s: mfn %lx owner: expected %pd, got %pd\n",
                   __func__, mfn_x(mfn) + i, d, od);
            return -EACCES;
        }
    }
#endif

    ASSERT(pod_locked_by_me(p2m));

    /*
     * Pages from domain_alloc and returned by the balloon driver aren't
     * guaranteed to be zero; but by reclaiming zero pages, we implicitly
     * promise to provide zero pages. So we scrub pages before using.
     */
    for ( i = 0; i < (1UL << order); i++ )
        clear_domain_page(mfn_add(mfn, i));

    /* First, take all pages off the domain list */
    lock_page_alloc(p2m);
    for ( i = 0; i < (1UL << order); i++ )
        page_list_del(page + i, &d->page_list);
    unlock_page_alloc(p2m);

    /* Then add to the appropriate populate-on-demand list. */
    switch ( order )
    {
    case PAGE_ORDER_2M ... PAGE_ORDER_1G:
        for ( i = 0; i < (1UL << order); i += 1UL << PAGE_ORDER_2M )
            page_list_add_tail(page + i, &p2m->pod.super);
        break;
    case PAGE_ORDER_4K ... PAGE_ORDER_2M - 1:
        for ( i = 0; i < (1UL << order); i += 1UL << PAGE_ORDER_4K )
            page_list_add_tail(page + i, &p2m->pod.single);
        break;
    default:
        BUG();
    }
    p2m->pod.count += 1UL << order;

    return 0;
}

/* Get a page of size order from the populate-on-demand cache.  Will break
 * down 2-meg pages into singleton pages automatically.  Returns null if
 * a superpage is requested and no superpages are available. */
static struct page_info * p2m_pod_cache_get(struct p2m_domain *p2m,
                                            unsigned int order)
{
    struct page_info *p = NULL;
    unsigned long i;

    ASSERT(pod_locked_by_me(p2m));

    if ( order == PAGE_ORDER_2M && page_list_empty(&p2m->pod.super) )
    {
        return NULL;
    }
    else if ( order == PAGE_ORDER_4K && page_list_empty(&p2m->pod.single) )
    {
        unsigned long mfn;
        struct page_info *q;

        BUG_ON( page_list_empty(&p2m->pod.super) );

        /*
         * Break up a superpage to make single pages. NB count doesn't
         * need to be adjusted.
         */
        p = page_list_remove_head(&p2m->pod.super);
        mfn = mfn_x(page_to_mfn(p));

        for ( i = 0; i < SUPERPAGE_PAGES; i++ )
        {
            q = mfn_to_page(_mfn(mfn+i));
            page_list_add_tail(q, &p2m->pod.single);
        }
    }

    switch ( order )
    {
    case PAGE_ORDER_2M:
        BUG_ON( page_list_empty(&p2m->pod.super) );
        p = page_list_remove_head(&p2m->pod.super);
        p2m->pod.count -= 1UL << order;
        break;
    case PAGE_ORDER_4K:
        BUG_ON( page_list_empty(&p2m->pod.single) );
        p = page_list_remove_head(&p2m->pod.single);
        p2m->pod.count -= 1UL;
        break;
    default:
        BUG();
    }

    /* Put the pages back on the domain page_list */
    lock_page_alloc(p2m);
    for ( i = 0 ; i < (1UL << order); i++ )
    {
        BUG_ON(page_get_owner(p + i) != p2m->domain);
        page_list_add_tail(p + i, &p2m->domain->page_list);
    }
    unlock_page_alloc(p2m);

    return p;
}

/* Set the size of the cache, allocating or freeing as necessary. */
static int
p2m_pod_set_cache_target(struct p2m_domain *p2m, unsigned long pod_target, int preemptible)
{
    struct domain *d = p2m->domain;
    int ret = 0;

    ASSERT(pod_locked_by_me(p2m));

    /* Increasing the target */
    while ( pod_target > p2m->pod.count )
    {
        struct page_info * page;
        int order;

        if ( (pod_target - p2m->pod.count) >= SUPERPAGE_PAGES )
            order = PAGE_ORDER_2M;
        else
            order = PAGE_ORDER_4K;
    retry:
        page = alloc_domheap_pages(d, order, 0);
        if ( unlikely(page == NULL) )
        {
            if ( order == PAGE_ORDER_2M )
            {
                /* If we can't allocate a superpage, try singleton pages */
                order = PAGE_ORDER_4K;
                goto retry;
            }

            printk("%s: Unable to allocate page for PoD cache (target=%lu cache=%ld)\n",
                   __func__, pod_target, p2m->pod.count);
            ret = -ENOMEM;
            goto out;
        }

        p2m_pod_cache_add(p2m, page, order);

        if ( preemptible && pod_target != p2m->pod.count &&
             hypercall_preempt_check() )
        {
            ret = -ERESTART;
            goto out;
        }
    }

    /* Decreasing the target */
    /*
     * We hold the pod lock here, so we don't need to worry about
     * cache disappearing under our feet.
     */
    while ( pod_target < p2m->pod.count )
    {
        struct page_info * page;
        unsigned int order;
        unsigned long i;

        if ( (p2m->pod.count - pod_target) > SUPERPAGE_PAGES
             && !page_list_empty(&p2m->pod.super) )
            order = PAGE_ORDER_2M;
        else
            order = PAGE_ORDER_4K;

        page = p2m_pod_cache_get(p2m, order);

        ASSERT(page != NULL);

        /* Then free them */
        for ( i = 0 ; i < (1UL << order) ; i++ )
        {
            /* Copied from common/memory.c:guest_remove_page() */
            if ( unlikely(!get_page(page + i, d)) )
            {
                gdprintk(XENLOG_INFO, "Bad page free for domain %u\n", d->domain_id);
                ret = -EINVAL;
                goto out;
            }

            put_page_alloc_ref(page + i);
            put_page(page + i);

            if ( preemptible && pod_target != p2m->pod.count &&
                 hypercall_preempt_check() )
            {
                ret = -ERESTART;
                goto out;
            }
        }
    }

out:
    return ret;
}

/*
 * The "right behavior" here requires some careful thought.  First, some
 * definitions:
 * + M: static_max
 * + B: number of pages the balloon driver has ballooned down to.
 * + P: Number of populated pages.
 * + T: Old target
 * + T': New target
 *
 * The following equations should hold:
 *  0 <= P <= T <= B <= M
 *  d->arch.p2m->pod.entry_count == B - P
 *  domain_tot_pages(d) == P + d->arch.p2m->pod.count
 *
 * Now we have the following potential cases to cover:
 *     B <T': Set the PoD cache size equal to the number of outstanding PoD
 *   entries.  The balloon driver will deflate the balloon to give back
 *   the remainder of the ram to the guest OS.
 *  T <T'<B : Increase PoD cache size.
 *  T'<T<=B : Here we have a choice.  We can decrease the size of the cache,
 *   get the memory right away.  However, that means every time we
 *   reduce the memory target we risk the guest attempting to populate the
 *   memory before the balloon driver has reached its new target.  Safer to
 *   never reduce the cache size here, but only when the balloon driver frees
 *   PoD ranges.
 *
 * If there are many zero pages, we could reach the target also by doing
 * zero sweeps and marking the ranges PoD; but the balloon driver will have
 * to free this memory eventually anyway, so we don't actually gain that much
 * by doing so.
 *
 * NB that the equation (B<T') may require adjustment to the cache
 * size as PoD pages are freed as well; i.e., freeing a PoD-backed
 * entry when pod.entry_count == pod.count requires us to reduce both
 * pod.entry_count and pod.count.
 */
int
p2m_pod_set_mem_target(struct domain *d, unsigned long target)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret = 0;
    unsigned long populated, pod_target;

    pod_lock(p2m);

    /* P == B: Nothing to do (unless the guest is being created). */
    populated = domain_tot_pages(d) - p2m->pod.count;
    if ( populated > 0 && p2m->pod.entry_count == 0 )
        goto out;

    /* Don't do anything if the domain is being torn down */
    if ( d->is_dying )
        goto out;

    /*
     * T' < B: Don't reduce the cache size; let the balloon driver
     * take care of it.
     */
    if ( target < domain_tot_pages(d) )
        goto out;

    pod_target = target - populated;

    /*
     * B < T': Set the cache size equal to # of outstanding entries,
     * let the balloon driver fill in the rest.
     */
    if ( populated > 0 && pod_target > p2m->pod.entry_count )
        pod_target = p2m->pod.entry_count;

    ASSERT( pod_target >= p2m->pod.count );

    if ( has_arch_pdevs(d) || has_arch_io_resources(d) )
        ret = -ENOTEMPTY;
    else
        ret = p2m_pod_set_cache_target(p2m, pod_target, 1/*preemptible*/);

out:
    pod_unlock(p2m);

    return ret;
}

void p2m_pod_get_mem_target(const struct domain *d, xen_pod_target_t *target)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    ASSERT(is_hvm_domain(d));

    pod_lock(p2m);
    lock_page_alloc(p2m);

    target->tot_pages       = domain_tot_pages(d);
    target->pod_cache_pages = p2m->pod.count;
    target->pod_entries     = p2m->pod.entry_count;

    unlock_page_alloc(p2m);
    pod_unlock(p2m);
}

int p2m_pod_empty_cache(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *page;
    unsigned int i;

    /* After this barrier no new PoD activities can happen. */
    BUG_ON(!d->is_dying);
    rspin_barrier(&p2m->pod.lock.lock);

    lock_page_alloc(p2m);

    while ( (page = page_list_remove_head(&p2m->pod.super)) )
    {
        for ( i = 0 ; i < SUPERPAGE_PAGES ; i++ )
        {
            BUG_ON(page_get_owner(page + i) != d);
            page_list_add_tail(page + i, &d->page_list);
        }

        p2m->pod.count -= SUPERPAGE_PAGES;

        if ( hypercall_preempt_check() )
            goto out;
    }

    for ( i = 0; (page = page_list_remove_head(&p2m->pod.single)); ++i )
    {
        BUG_ON(page_get_owner(page) != d);
        page_list_add_tail(page, &d->page_list);

        p2m->pod.count -= 1;

        if ( i && !(i & 511) && hypercall_preempt_check() )
            goto out;
    }

    BUG_ON(p2m->pod.count != 0);

 out:
    unlock_page_alloc(p2m);
    return p2m->pod.count ? -ERESTART : 0;
}

int
p2m_pod_offline_or_broken_hit(struct page_info *p)
{
    struct domain *d;
    struct p2m_domain *p2m;
    struct page_info *q, *tmp;
    unsigned long mfn, bmfn;

    if ( !(d = page_get_owner(p)) || !(p2m = p2m_get_hostp2m(d)) )
        return 0;

    pod_lock(p2m);
    bmfn = mfn_x(page_to_mfn(p));
    page_list_for_each_safe(q, tmp, &p2m->pod.super)
    {
        mfn = mfn_x(page_to_mfn(q));
        if ( (bmfn >= mfn) && ((bmfn - mfn) < SUPERPAGE_PAGES) )
        {
            unsigned long i;
            page_list_del(q, &p2m->pod.super);
            for ( i = 0; i < SUPERPAGE_PAGES; i++)
            {
                q = mfn_to_page(_mfn(mfn + i));
                page_list_add_tail(q, &p2m->pod.single);
            }
            page_list_del(p, &p2m->pod.single);
            p2m->pod.count--;
            goto pod_hit;
        }
    }

    page_list_for_each_safe(q, tmp, &p2m->pod.single)
    {
        mfn = mfn_x(page_to_mfn(q));
        if ( mfn == bmfn )
        {
            page_list_del(p, &p2m->pod.single);
            p2m->pod.count--;
            goto pod_hit;
        }
    }

    pod_unlock(p2m);
    return 0;

pod_hit:
    lock_page_alloc(p2m);
    /* Insertion must be at list head (see iommu_populate_page_table()). */
    page_list_add(p, &d->arch.relmem_list);
    unlock_page_alloc(p2m);
    pod_unlock(p2m);
    return 1;
}

void
p2m_pod_offline_or_broken_replace(struct page_info *p)
{
    struct domain *d;
    struct p2m_domain *p2m;
    nodeid_t node = page_to_nid(p);

    if ( !(d = page_get_owner(p)) || !(p2m = p2m_get_hostp2m(d)) )
        return;

    free_domheap_page(p);

    p = alloc_domheap_page(d, MEMF_node(node));
    if ( unlikely(!p) )
        return;

    pod_lock(p2m);
    p2m_pod_cache_add(p2m, p, PAGE_ORDER_4K);
    pod_unlock(p2m);
    return;
}

static int
p2m_pod_zero_check_superpage(struct p2m_domain *p2m, gfn_t gfn);

static void pod_unlock_and_flush(struct p2m_domain *p2m)
{
    pod_unlock(p2m);
    p2m->defer_nested_flush = false;
    if ( nestedhvm_enabled(p2m->domain) )
        p2m_flush_nestedp2m(p2m->domain);
}

/*
 * This pair of functions is needed for two reasons:
 * + To properly handle clearing of PoD entries
 * + To "steal back" memory being freed for the PoD cache, rather than
 *   releasing it.
 *
 * Once both of these functions have been completed, we can return and
 * allow decrease_reservation() to handle everything else.
 */
static unsigned long
decrease_reservation(struct domain *d, gfn_t gfn, unsigned int order)
{
    unsigned long ret = 0, i, n;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    bool steal_for_cache;
    long pod = 0, ram = 0;

    gfn_lock(p2m, gfn, order);
    pod_lock(p2m);
    p2m->defer_nested_flush = true;

    /*
     * If we don't have any outstanding PoD entries, let things take their
     * course.
     */
    if ( p2m->pod.entry_count == 0 )
        goto out_unlock;

    if ( unlikely(d->is_dying) )
        goto out_unlock;

    /* Figure out if we need to steal some freed memory for our cache */
    steal_for_cache =  ( p2m->pod.entry_count > p2m->pod.count );

    for ( i = 0; i < (1UL << order); i += n )
    {
        p2m_access_t a;
        p2m_type_t t;
        unsigned int cur_order;

        p2m->get_entry(p2m, gfn_add(gfn, i), &t, &a, 0, &cur_order, NULL);
        n = 1UL << min(order, cur_order);
        if ( p2m_is_pod(t) )
            pod += n;
        else if ( p2m_is_ram(t) )
            ram += n;
    }

    /* No populate-on-demand?  Don't need to steal anything?  Then we're done!*/
    if ( !pod && !steal_for_cache )
        goto out_unlock;

    if ( i == pod )
    {
        /*
         * All PoD: Mark the whole region invalid and tell caller
         * we're done.
         */
        int rc = p2m_set_entry(p2m, gfn, INVALID_MFN, order, p2m_invalid,
                               p2m->default_access);

        if ( rc )
        {
            /*
             * If this fails, we can't tell how much of the range was changed.
             * Best to crash the domain unless we're sure a partial change is
             * impossible.
             */
            if ( order != 0 )
            {
                printk(XENLOG_G_ERR
                       "%pd: marking GFN %#lx (order %u) as non-PoD failed: %d\n",
                       d, gfn_x(gfn), order, rc);
                domain_crash(d);
            }
            goto out_unlock;
        }
        ret = 1UL << order;
        p2m->pod.entry_count -= ret;
        BUG_ON(p2m->pod.entry_count < 0);
        goto out_entry_check;
    }

    /*
     * Try to grab entire superpages if possible.  Since the common case is for
     * drivers to pass back singleton pages, see if we can take the whole page
     * back and mark the rest PoD.
     * No need to do this though if
     * - order >= SUPERPAGE_ORDER (the loop below will take care of this)
     * - not all of the pages were RAM (now knowing order < SUPERPAGE_ORDER)
     */
    if ( steal_for_cache && order < SUPERPAGE_ORDER && ram == (1UL << order) &&
         p2m_pod_zero_check_superpage(p2m, _gfn(gfn_x(gfn) & ~(SUPERPAGE_PAGES - 1))) )
    {
        pod = 1UL << order;
        ram = 0;
        ASSERT(steal_for_cache == (p2m->pod.entry_count > p2m->pod.count));
    }

    /*
     * Process as long as:
     * + There are PoD entries to handle, or
     * + There is ram left, and we want to steal it
     */
    for ( i = 0;
          i < (1UL << order) && (pod > 0 || (steal_for_cache && ram > 0));
          i += n )
    {
        mfn_t mfn;
        p2m_type_t t;
        p2m_access_t a;
        unsigned int cur_order;

        mfn = p2m->get_entry(p2m, gfn_add(gfn, i), &t, &a, 0, &cur_order, NULL);
        if ( order < cur_order )
            cur_order = order;
        n = 1UL << cur_order;
        if ( p2m_is_pod(t) )
        {
            /* This shouldn't be able to fail */
            if ( p2m_set_entry(p2m, gfn_add(gfn, i), INVALID_MFN, cur_order,
                               p2m_invalid, p2m->default_access) )
            {
                ASSERT_UNREACHABLE();
                domain_crash(d);
                goto out_unlock;
            }
            p2m->pod.entry_count -= n;
            BUG_ON(p2m->pod.entry_count < 0);
            pod -= n;
            ret += n;
        }
        else if ( steal_for_cache && p2m_is_ram(t) )
        {
            /*
             * If we need less than 1 << cur_order, we may end up stealing
             * more memory here than we actually need. This will be rectified
             * below, however; and stealing too much and then freeing what we
             * need may allow us to free smaller pages from the cache, and
             * avoid breaking up superpages.
             */
            struct page_info *page;
            unsigned long j;

            ASSERT(mfn_valid(mfn));

            page = mfn_to_page(mfn);

            /* This shouldn't be able to fail */
            if ( p2m_set_entry(p2m, gfn_add(gfn, i), INVALID_MFN, cur_order,
                               p2m_invalid, p2m->default_access) )
            {
                ASSERT_UNREACHABLE();
                domain_crash(d);
                goto out_unlock;
            }
            p2m_tlb_flush_sync(p2m);
            for ( j = 0; j < n; ++j )
                set_gpfn_from_mfn(mfn_x(mfn), INVALID_M2P_ENTRY);
            p2m_pod_cache_add(p2m, page, cur_order);

            ioreq_request_mapcache_invalidate(d);

            steal_for_cache =  ( p2m->pod.entry_count > p2m->pod.count );

            ram -= n;
            ret += n;
        }
    }

out_entry_check:
    /* If we've reduced our "liabilities" beyond our "assets", free some */
    if ( p2m->pod.entry_count < p2m->pod.count )
    {
        p2m_pod_set_cache_target(p2m, p2m->pod.entry_count, 0/*can't preempt*/);
    }

out_unlock:
    pod_unlock_and_flush(p2m);
    gfn_unlock(p2m, gfn, order);
    return ret;
}

unsigned long
p2m_pod_decrease_reservation(struct domain *d, gfn_t gfn, unsigned int order)
{
    unsigned long left = 1UL << order, ret = 0;
    unsigned int chunk_order = ffsl(gfn_x(gfn) | left) - 1;

    do {
        ret += decrease_reservation(d, gfn, chunk_order);

        left -= 1UL << chunk_order;
        gfn = gfn_add(gfn, 1UL << chunk_order);
    } while ( left );

    return ret;
}

void p2m_pod_dump_data(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    printk("    PoD entries=%ld cachesize=%ld\n",
           p2m->pod.entry_count, p2m->pod.count);
}


/*
 * Search for all-zero superpages to be reclaimed as superpages for the
 * PoD cache. Must be called w/ pod lock held, must lock the superpage
 * in the p2m.
 */
static int
p2m_pod_zero_check_superpage(struct p2m_domain *p2m, gfn_t gfn)
{
    mfn_t mfn, mfn0 = INVALID_MFN;
    p2m_type_t type, type0 = 0;
    unsigned long * map = NULL;
    int ret=0, reset = 0;
    unsigned long i, n;
    unsigned int j;
    int max_ref = 1;
    struct domain *d = p2m->domain;

    ASSERT(pod_locked_by_me(p2m));

    if ( !superpage_aligned(gfn_x(gfn)) )
        goto out;

    /* Allow an extra refcount for one shadow pt mapping in shadowed domains */
    if ( paging_mode_shadow(d) )
        max_ref++;

    /*
     * NOTE: this is why we don't enforce deadlock constraints between p2m
     * and pod locks.
     */
    gfn_lock(p2m, gfn, SUPERPAGE_ORDER);

    /*
     * Look up the mfns, checking to make sure they're the same mfn
     * and aligned, and mapping them.
     */
    for ( i = 0; i < SUPERPAGE_PAGES; i += n )
    {
        p2m_access_t a;
        unsigned int cur_order;
        unsigned long k;
        const struct page_info *page;

        mfn = p2m->get_entry(p2m, gfn_add(gfn, i), &type, &a, 0,
                             &cur_order, NULL);

        /*
         * Conditions that must be met for superpage-superpage:
         * + All gfns are ram types
         * + All gfns have the same type
         * + All of the mfns are allocated to a domain
         * + None of the mfns are used as pagetables, or allocated via xenheap
         * + The first mfn is 2-meg aligned
         * + All the other mfns are in sequence
         * Adding for good measure:
         * + None of the mfns are likely to be mapped elsewhere (refcount
         *   2 or less for shadow, 1 for hap)
         */
        if ( !p2m_is_ram(type) )
            goto out;

        if ( i == 0 )
        {
            if ( !superpage_aligned(mfn_x(mfn)) )
                goto out;
            mfn0 = mfn;
            type0 = type;
        }
        else if ( type != type0 || !mfn_eq(mfn, mfn_add(mfn0, i)) )
            goto out;

        n = 1UL << min(cur_order, SUPERPAGE_ORDER + 0U);
        for ( k = 0, page = mfn_to_page(mfn); k < n; ++k, ++page )
            if ( is_special_page(page) ||
                 !(page->count_info & PGC_allocated) ||
                 (page->count_info & PGC_shadowed_pt) ||
                 (page->count_info & PGC_count_mask) > max_ref )
                goto out;
    }

    /* Now, do a quick check to see if it may be zero before unmapping. */
    for ( i = 0; i < SUPERPAGE_PAGES; i++ )
    {
        /* Quick zero-check */
        map = map_domain_page(mfn_add(mfn0, i));

        for ( j = 0; j < 16; j++ )
            if ( *(map + j) != 0 )
                break;

        unmap_domain_page(map);

        if ( j < 16 )
            goto out;

    }

    /* Try to remove the page, restoring old mapping if it fails. */
    if ( p2m_set_entry(p2m, gfn, INVALID_MFN, PAGE_ORDER_2M,
                       p2m_populate_on_demand, p2m->default_access) )
        goto out;

    p2m_tlb_flush_sync(p2m);

    /*
     * Make none of the MFNs are used elsewhere... for example, mapped
     * via the grant table interface, or by qemu.  Allow one refcount for
     * being allocated to the domain.
     */
    for ( i = 0; i < SUPERPAGE_PAGES; i++ )
    {
        mfn = mfn_add(mfn0, i);
        if ( (mfn_to_page(mfn)->count_info & PGC_count_mask) > 1 )
        {
            reset = 1;
            goto out_reset;
        }
    }

    /* Finally, do a full zero-check */
    for ( i = 0; i < SUPERPAGE_PAGES; i++ )
    {
        map = map_domain_page(mfn_add(mfn0, i));

        for ( j = 0; j < (PAGE_SIZE / sizeof(*map)); j++ )
            if ( *(map+j) != 0 )
            {
                reset = 1;
                break;
            }

        unmap_domain_page(map);

        if ( reset )
            goto out_reset;
    }

    if ( tb_init_done )
    {
        struct {
            uint64_t gfn, mfn;
            uint32_t d, order;
        } t;

        t.gfn = gfn_x(gfn);
        t.mfn = mfn_x(mfn);
        t.d = d->domain_id;
        t.order = 9;

        trace(TRC_MEM_POD_ZERO_RECLAIM, sizeof(t), &t);
    }

    /*
     * Finally!  We've passed all the checks, and can add the mfn superpage
     * back on the PoD cache, and account for the new p2m PoD entries.
     */
    p2m_pod_cache_add(p2m, mfn_to_page(mfn0), PAGE_ORDER_2M);
    p2m->pod.entry_count += SUPERPAGE_PAGES;

    ioreq_request_mapcache_invalidate(d);

    ret = SUPERPAGE_PAGES;

out_reset:
    /*
     * This p2m_set_entry() call shouldn't be able to fail, since the same order
     * on the same gfn succeeded above.  If that turns out to be false, crashing
     * the domain should be the safest way of making sure we don't leak memory.
     */
    if ( reset && p2m_set_entry(p2m, gfn, mfn0, PAGE_ORDER_2M,
                                type0, p2m->default_access) )
    {
        ASSERT_UNREACHABLE();
        domain_crash(d);
    }

out:
    gfn_unlock(p2m, gfn, SUPERPAGE_ORDER);
    return ret;
}

#define POD_SWEEP_LIMIT 1024
#define POD_SWEEP_STRIDE  16

static void
p2m_pod_zero_check(struct p2m_domain *p2m, const gfn_t *gfns, unsigned int count)
{
    mfn_t mfns[POD_SWEEP_STRIDE];
    p2m_type_t types[POD_SWEEP_STRIDE];
    unsigned long *map[POD_SWEEP_STRIDE];
    struct domain *d = p2m->domain;
    unsigned int i, j, max_ref = 1;

    BUG_ON(count > POD_SWEEP_STRIDE);

    /* Allow an extra refcount for one shadow pt mapping in shadowed domains */
    if ( paging_mode_shadow(d) )
        max_ref++;

    /* First, get the gfn list, translate to mfns, and map the pages. */
    for ( i = 0; i < count; i++ )
    {
        p2m_access_t a;

        mfns[i] = p2m->get_entry(p2m, gfns[i], types + i, &a,
                                 0, NULL, NULL);

        /*
         * If this is ram, and not a pagetable or a special page, and
         * probably not mapped elsewhere, map it; otherwise, skip.
         */
        map[i] = NULL;
        if ( p2m_is_ram(types[i]) )
        {
            const struct page_info *pg = mfn_to_page(mfns[i]);

            if ( !is_special_page(pg) &&
                 (pg->count_info & PGC_allocated) &&
                 !(pg->count_info & PGC_shadowed_pt) &&
                 ((pg->count_info & PGC_count_mask) <= max_ref) )
                map[i] = map_domain_page(mfns[i]);
        }
    }

    /*
     * Then, go through and check for zeroed pages, removing write permission
     * for those with zeroes.
     */
    for ( i = 0; i < count; i++ )
    {
        if ( !map[i] )
            continue;

        /* Quick zero-check */
        for ( j = 0; j < 16; j++ )
            if ( *(map[i] + j) != 0 )
                goto skip;

        /* Try to remove the page, restoring old mapping if it fails. */
        if ( p2m_set_entry(p2m, gfns[i], INVALID_MFN, PAGE_ORDER_4K,
                           p2m_populate_on_demand, p2m->default_access) )
            goto skip;

        /*
         * See if the page was successfully unmapped.  (Allow one refcount
         * for being allocated to a domain.)
         */
        if ( (mfn_to_page(mfns[i])->count_info & PGC_count_mask) > 1 )
        {
            /*
             * If the previous p2m_set_entry call succeeded, this one shouldn't
             * be able to fail.  If it does, crashing the domain should be safe.
             */
            if ( p2m_set_entry(p2m, gfns[i], mfns[i], PAGE_ORDER_4K,
                               types[i], p2m->default_access) )
            {
                ASSERT_UNREACHABLE();
                domain_crash(d);
                goto out_unmap;
            }

        skip:
            unmap_domain_page(map[i]);
            map[i] = NULL;

            continue;
        }
    }

    p2m_tlb_flush_sync(p2m);

    /* Now check each page for real */
    for ( i = 0; i < count; i++ )
    {
        if ( !map[i] )
            continue;

        for ( j = 0; j < (PAGE_SIZE / sizeof(*map[i])); j++ )
            if ( *(map[i] + j) != 0 )
                break;

        unmap_domain_page(map[i]);

        map[i] = NULL;

        /*
         * See comment in p2m_pod_zero_check_superpage() re gnttab
         * check timing.
         */
        if ( j < (PAGE_SIZE / sizeof(*map[i])) )
        {
            /*
             * If the previous p2m_set_entry call succeeded, this one shouldn't
             * be able to fail.  If it does, crashing the domain should be safe.
             */
            if ( p2m_set_entry(p2m, gfns[i], mfns[i], PAGE_ORDER_4K,
                               types[i], p2m->default_access) )
            {
                ASSERT_UNREACHABLE();
                domain_crash(d);
 out_unmap:
                /*
                 * Something went wrong, probably crashing the domain.  Unmap
                 * everything and return.
                 */
                for ( i = 0; i < count; i++ )
                    if ( map[i] )
                        unmap_domain_page(map[i]);
            }
        }
        else
        {
            if ( tb_init_done )
            {
                struct {
                    uint64_t gfn, mfn;
                    uint32_t d, order;
                } t;

                t.gfn = gfn_x(gfns[i]);
                t.mfn = mfn_x(mfns[i]);
                t.d = d->domain_id;
                t.order = 0;

                trace(TRC_MEM_POD_ZERO_RECLAIM, sizeof(t), &t);
            }

            /* Add to cache, and account for the new p2m PoD entry */
            p2m_pod_cache_add(p2m, mfn_to_page(mfns[i]), PAGE_ORDER_4K);
            p2m->pod.entry_count++;

            ioreq_request_mapcache_invalidate(d);
        }
    }
}

static void
p2m_pod_emergency_sweep(struct p2m_domain *p2m)
{
    gfn_t gfns[POD_SWEEP_STRIDE];
    unsigned long i, j = 0, start, limit;
    p2m_type_t t;


    if ( gfn_eq(p2m->pod.reclaim_single, _gfn(0)) )
        p2m->pod.reclaim_single = p2m->pod.max_guest;

    start = gfn_x(p2m->pod.reclaim_single);
    limit = (start > POD_SWEEP_LIMIT) ? (start - POD_SWEEP_LIMIT) : 0;

    /* FIXME: Figure out how to avoid superpages */
    /*
     * NOTE: Promote to globally locking the p2m. This will get complicated
     * in a fine-grained scenario. If we lock each gfn individually we must be
     * careful about spinlock recursion limits and POD_SWEEP_STRIDE.
     */
    p2m_lock(p2m);
    for ( i = gfn_x(p2m->pod.reclaim_single); i > 0 ; i-- )
    {
        p2m_access_t a;
        (void)p2m->get_entry(p2m, _gfn(i), &t, &a, 0, NULL, NULL);
        if ( p2m_is_ram(t) )
        {
            gfns[j] = _gfn(i);
            j++;
            BUG_ON(j > POD_SWEEP_STRIDE);
            if ( j == POD_SWEEP_STRIDE )
            {
                p2m_pod_zero_check(p2m, gfns, j);
                j = 0;
            }
        }
        /*
         * Stop if we're past our limit and we have found *something*.
         *
         * NB that this is a zero-sum game; we're increasing our cache size
         * by re-increasing our 'debt'.  Since we hold the pod lock,
         * (entry_count - count) must remain the same.
         */
        if ( i < limit && (p2m->pod.count > 0 || hypercall_preempt_check()) )
            break;
    }

    if ( j )
        p2m_pod_zero_check(p2m, gfns, j);

    p2m_unlock(p2m);
    p2m->pod.reclaim_single = _gfn(i ? i - 1 : i);

}

static void pod_eager_reclaim(struct p2m_domain *p2m)
{
    struct pod_mrp_list *mrp = &p2m->pod.mrp;
    unsigned int i = 0;

    /*
     * Always check one page for reclaimation.
     *
     * If the PoD pool is empty, keep checking some space is found, or all
     * entries have been exhaused.
     */
    do
    {
        unsigned int idx = (mrp->idx + i++) % ARRAY_SIZE(mrp->list);
        gfn_t gfn = _gfn(mrp->list[idx]);

        if ( !gfn_eq(gfn, INVALID_GFN) )
        {
            if ( gfn_x(gfn) & POD_LAST_SUPERPAGE )
            {
                gfn = _gfn(gfn_x(gfn) & ~POD_LAST_SUPERPAGE);

                if ( p2m_pod_zero_check_superpage(p2m, gfn) == 0 )
                {
                    unsigned int x;

                    for ( x = 0; x < SUPERPAGE_PAGES; ++x, gfn = gfn_add(gfn, 1) )
                        p2m_pod_zero_check(p2m, &gfn, 1);
                }
            }
            else
                p2m_pod_zero_check(p2m, &gfn, 1);

            mrp->list[idx] = gfn_x(INVALID_GFN);
        }

    } while ( (p2m->pod.count == 0) && (i < ARRAY_SIZE(mrp->list)) );
}

static void pod_eager_record(struct p2m_domain *p2m, gfn_t gfn,
                             unsigned int order)
{
    struct pod_mrp_list *mrp = &p2m->pod.mrp;

    ASSERT(!gfn_eq(gfn, INVALID_GFN));

    mrp->list[mrp->idx++] =
        gfn_x(gfn) | (order == PAGE_ORDER_2M ? POD_LAST_SUPERPAGE : 0);
    mrp->idx %= ARRAY_SIZE(mrp->list);
}

bool
p2m_pod_demand_populate(struct p2m_domain *p2m, gfn_t gfn,
                        unsigned int order)
{
    struct domain *d = p2m->domain;
    struct page_info *p = NULL; /* Compiler warnings */
    gfn_t gfn_aligned = _gfn((gfn_x(gfn) >> order) << order);
    mfn_t mfn;
    unsigned long i;

    if ( !p2m_is_hostp2m(p2m) )
    {
        ASSERT_UNREACHABLE();
        return false;
    }

    ASSERT(gfn_locked_by_me(p2m, gfn));
    pod_lock(p2m);

    /*
     * This check is done with the pod lock held.  This will make sure that
     * even if d->is_dying changes under our feet, p2m_pod_empty_cache()
     * won't start until we're done.
     */
    if ( unlikely(d->is_dying) )
    {
        pod_unlock(p2m);
        return false;
    }

    /*
     * Because PoD does not have cache list for 1GB pages, it has to remap
     * 1GB region to 2MB chunks for a retry.
     */
    if ( order == PAGE_ORDER_1G )
    {
        pod_unlock(p2m);
        /*
         * Note that we are supposed to call p2m_set_entry() 512 times to
         * split 1GB into 512 2MB pages here. But We only do once here because
         * p2m_set_entry() should automatically shatter the 1GB page into
         * 512 2MB pages. The rest of 511 calls are unnecessary.
         *
         * NOTE: In a fine-grained p2m locking scenario this operation
         * may need to promote its locking from gfn->1g superpage
         */
        return !p2m_set_entry(p2m, gfn_aligned, INVALID_MFN, PAGE_ORDER_2M,
                              p2m_populate_on_demand, p2m->default_access);
    }

    p2m->defer_nested_flush = true;

    /* Only reclaim if we're in actual need of more cache. */
    if ( p2m->pod.entry_count > p2m->pod.count )
        pod_eager_reclaim(p2m);

    /*
     * Only sweep if we're actually out of memory.  Doing anything else
     * causes unnecessary time and fragmentation of superpages in the p2m.
     */
    if ( p2m->pod.count == 0 )
        p2m_pod_emergency_sweep(p2m);

    /* If the sweep failed, give up. */
    if ( p2m->pod.count == 0 )
        goto out_of_memory;

    /* Keep track of the highest gfn demand-populated by a guest fault */
    p2m->pod.max_guest = gfn_max(gfn, p2m->pod.max_guest);

    /*
     * Get a page f/ the cache.  A NULL return value indicates that the
     * 2-meg range should be marked singleton PoD, and retried.
     */
    if ( (p = p2m_pod_cache_get(p2m, order)) == NULL )
        goto remap_and_retry;

    mfn = page_to_mfn(p);

    BUG_ON((mfn_x(mfn) & ((1UL << order) - 1)) != 0);

    if ( p2m_set_entry(p2m, gfn_aligned, mfn, order, p2m_ram_rw,
                       p2m->default_access) )
    {
        p2m_pod_cache_add(p2m, p, order);
        goto out_fail;
    }

    for( i = 0; i < (1UL << order); i++ )
    {
        set_gpfn_from_mfn(mfn_x(mfn) + i, gfn_x(gfn_aligned) + i);
        paging_mark_pfn_dirty(d, _pfn(gfn_x(gfn_aligned) + i));
    }

    p2m->pod.entry_count -= (1UL << order);
    BUG_ON(p2m->pod.entry_count < 0);

    pod_eager_record(p2m, gfn_aligned, order);

    if ( tb_init_done )
    {
        struct {
            uint64_t gfn, mfn;
            uint32_t d, order;
        } t;

        t.gfn = gfn_x(gfn);
        t.mfn = mfn_x(mfn);
        t.d = d->domain_id;
        t.order = order;

        trace(TRC_MEM_POD_POPULATE, sizeof(t), &t);
    }

    pod_unlock_and_flush(p2m);
    return true;

out_of_memory:
    pod_unlock_and_flush(p2m);

    printk("%s: Dom%d out of PoD memory! (tot=%"PRIu32" ents=%ld dom%d)\n",
           __func__, d->domain_id, domain_tot_pages(d),
           p2m->pod.entry_count, current->domain->domain_id);
    domain_crash(d);
    return false;

out_fail:
    pod_unlock_and_flush(p2m);
    return false;

remap_and_retry:
    BUG_ON(order != PAGE_ORDER_2M);
    pod_unlock_and_flush(p2m);

    /*
     * Remap this 2-meg region in singleton chunks. See the comment on the
     * 1G page splitting path above for why a single call suffices.
     *
     * NOTE: In a p2m fine-grained lock scenario this might
     * need promoting the gfn lock from gfn->2M superpage.
     */
    if ( p2m_set_entry(p2m, gfn_aligned, INVALID_MFN, PAGE_ORDER_4K,
                       p2m_populate_on_demand, p2m->default_access) )
        return false;

    if ( tb_init_done )
    {
        struct {
            uint64_t gfn;
            uint32_t d, order;
        } t;

        t.gfn = gfn_x(gfn);
        t.d = d->domain_id;
        t.order = order;

        trace(TRC_MEM_POD_SUPERPAGE_SPLINTER, sizeof(t), &t);
    }

    return true;
}

static int
mark_populate_on_demand(struct domain *d, unsigned long gfn_l,
                        unsigned int order)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    gfn_t gfn = _gfn(gfn_l);
    unsigned long i, n, pod_count = 0;
    int rc = 0;

    gfn_lock(p2m, gfn, order);

    P2M_DEBUG("mark pod gfn=%#lx\n", gfn_l);

    /* Make sure all gpfns are unused */
    for ( i = 0; i < (1UL << order); i += n )
    {
        p2m_type_t ot;
        p2m_access_t a;
        unsigned int cur_order;

        p2m->get_entry(p2m, gfn_add(gfn, i), &ot, &a, 0, &cur_order, NULL);
        n = 1UL << min(order, cur_order);
        if ( p2m_is_pod(ot) )
        {
            /* Count how many PoD entries we'll be replacing if successful */
            pod_count += n;
        }
        else if ( ot != p2m_invalid && ot != p2m_mmio_dm )
        {
            P2M_DEBUG("gfn_to_mfn returned type %d!\n", ot);
            rc = -EBUSY;
            goto out;
        }
    }

    /*
     * P2M update and stats increment need to collectively be under PoD lock,
     * to prevent code elsewhere observing PoD entry count being zero despite
     * there actually still being PoD entries (created by the p2m_set_entry()
     * invocation below).
     */
    pod_lock(p2m);

    /* Now, actually do the two-way mapping */
    rc = p2m_set_entry(p2m, gfn, INVALID_MFN, order,
                       p2m_populate_on_demand, p2m->default_access);
    if ( rc == 0 )
    {
        p2m->pod.entry_count += 1UL << order;
        p2m->pod.entry_count -= pod_count;
        BUG_ON(p2m->pod.entry_count < 0);
    }

    pod_unlock(p2m);

    if ( rc == 0 )
        ioreq_request_mapcache_invalidate(d);
    else if ( order )
    {
        /*
         * If this failed, we can't tell how much of the range was changed.
         * Best to crash the domain.
         */
        printk(XENLOG_G_ERR
               "%pd: marking GFN %#lx (order %u) as PoD failed: %d\n",
               d, gfn_l, order, rc);
        domain_crash(d);
    }

out:
    gfn_unlock(p2m, gfn, order);

    return rc;
}

int
guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                      unsigned int order)
{
    unsigned long left = 1UL << order;
    unsigned int chunk_order = ffsl(gfn | left) - 1;
    int rc;

    if ( !paging_mode_translate(d) )
        return -EINVAL;

    if ( has_arch_pdevs(d) || has_arch_io_resources(d) )
        return -ENOTEMPTY;

    do {
        rc = mark_populate_on_demand(d, gfn, chunk_order);

        left -= 1UL << chunk_order;
        gfn += 1UL << chunk_order;
    } while ( !rc && left );

    return rc;
}

void p2m_pod_init(struct p2m_domain *p2m)
{
    unsigned int i;

    mm_lock_init(&p2m->pod.lock);
    INIT_PAGE_LIST_HEAD(&p2m->pod.super);
    INIT_PAGE_LIST_HEAD(&p2m->pod.single);

    for ( i = 0; i < ARRAY_SIZE(p2m->pod.mrp.list); ++i )
        p2m->pod.mrp.list[i] = gfn_x(INVALID_GFN);
}

bool p2m_pod_active(const struct domain *d)
{
    struct p2m_domain *p2m;
    bool res;

    if ( !is_hvm_domain(d) )
        return false;

    p2m = p2m_get_hostp2m(d);

    pod_lock(p2m);
    res = p2m->pod.entry_count | p2m->pod.count;
    pod_unlock(p2m);

    return res;
}
