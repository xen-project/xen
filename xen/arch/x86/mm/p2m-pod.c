/******************************************************************************
 * arch/x86/mm/p2m-pod.c
 *
 * Populate-on-demand p2m entries. 
 *
 * Copyright (c) 2009-2011 Citrix Systems, Inc.
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
#include <asm/hvm/svm/amd-iommu-proto.h>

#include "mm-locks.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

#define superpage_aligned(_x)  (((_x)&(SUPERPAGE_PAGES-1))==0)

/* Enforce lock ordering when grabbing the "external" page_alloc lock */
static inline void lock_page_alloc(struct p2m_domain *p2m)
{
    page_alloc_mm_pre_lock();
    spin_lock(&(p2m->domain->page_alloc_lock));
    page_alloc_mm_post_lock(p2m->domain->arch.page_alloc_unlock_level);
}

static inline void unlock_page_alloc(struct p2m_domain *p2m)
{
    page_alloc_mm_unlock(p2m->domain->arch.page_alloc_unlock_level);
    spin_unlock(&(p2m->domain->page_alloc_lock));
}

/*
 * Populate-on-demand functionality
 */

static int
p2m_pod_cache_add(struct p2m_domain *p2m,
                  struct page_info *page,
                  unsigned int order)
{
    int i;
    struct page_info *p;
    struct domain *d = p2m->domain;

#ifndef NDEBUG
    mfn_t mfn;

    mfn = page_to_mfn(page);

    /* Check to make sure this is a contiguous region */
    if( mfn_x(mfn) & ((1 << order) - 1) )
    {
        printk("%s: mfn %lx not aligned order %u! (mask %lx)\n",
               __func__, mfn_x(mfn), order, ((1UL << order) - 1));
        return -1;
    }
    
    for(i=0; i < 1 << order ; i++) {
        struct domain * od;

        p = mfn_to_page(_mfn(mfn_x(mfn) + i));
        od = page_get_owner(p);
        if(od != d)
        {
            printk("%s: mfn %lx expected owner d%d, got owner d%d!\n",
                   __func__, mfn_x(mfn), d->domain_id,
                   od?od->domain_id:-1);
            return -1;
        }
    }
#endif

    ASSERT(pod_locked_by_me(p2m));

    /*
     * Pages from domain_alloc and returned by the balloon driver aren't
     * guaranteed to be zero; but by reclaiming zero pages, we implicitly
     * promise to provide zero pages. So we scrub pages before using.
     */
    for ( i = 0; i < (1 << order); i++ )
    {
        char *b = map_domain_page(_mfn(mfn_x(page_to_mfn(page)) + i));
        clear_page(b);
        unmap_domain_page(b);
    }

    /* First, take all pages off the domain list */
    lock_page_alloc(p2m);
    for(i=0; i < 1 << order ; i++)
    {
        p = page + i;
        page_list_del(p, &d->page_list);
    }

    unlock_page_alloc(p2m);

    /* Then add the first one to the appropriate populate-on-demand list */
    switch(order)
    {
    case PAGE_ORDER_2M:
        page_list_add_tail(page, &p2m->pod.super); /* lock: page_alloc */
        p2m->pod.count += 1 << order;
        break;
    case PAGE_ORDER_4K:
        page_list_add_tail(page, &p2m->pod.single); /* lock: page_alloc */
        p2m->pod.count += 1;
        break;
    default:
        BUG();
    }

    return 0;
}

/* Get a page of size order from the populate-on-demand cache.  Will break
 * down 2-meg pages into singleton pages automatically.  Returns null if
 * a superpage is requested and no superpages are available. */
static struct page_info * p2m_pod_cache_get(struct p2m_domain *p2m,
                                            unsigned int order)
{
    struct page_info *p = NULL;
    int i;

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

        /* Break up a superpage to make single pages. NB count doesn't
         * need to be adjusted. */
        p = page_list_remove_head(&p2m->pod.super);
        mfn = mfn_x(page_to_mfn(p));

        for ( i=0; i<SUPERPAGE_PAGES; i++ )
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
        p2m->pod.count -= 1 << order;
        break;
    case PAGE_ORDER_4K:
        BUG_ON( page_list_empty(&p2m->pod.single) );
        p = page_list_remove_head(&p2m->pod.single);
        p2m->pod.count -= 1;
        break;
    default:
        BUG();
    }

    /* Put the pages back on the domain page_list */
    lock_page_alloc(p2m);
    for ( i = 0 ; i < (1 << order); i++ )
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
        page = alloc_domheap_pages(d, order, PAGE_ORDER_4K);
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
    /* We hold the pod lock here, so we don't need to worry about
     * cache disappearing under our feet. */
    while ( pod_target < p2m->pod.count )
    {
        struct page_info * page;
        int order, i;

        if ( (p2m->pod.count - pod_target) > SUPERPAGE_PAGES
             && !page_list_empty(&p2m->pod.super) )
            order = PAGE_ORDER_2M;
        else
            order = PAGE_ORDER_4K;

        page = p2m_pod_cache_get(p2m, order);

        ASSERT(page != NULL);

        /* Then free them */
        for ( i = 0 ; i < (1 << order) ; i++ )
        {
            /* Copied from common/memory.c:guest_remove_page() */
            if ( unlikely(!get_page(page+i, d)) )
            {
                gdprintk(XENLOG_INFO, "Bad page free for domain %u\n", d->domain_id);
                ret = -EINVAL;
                goto out;
            }

            if ( test_and_clear_bit(_PGT_pinned, &(page+i)->u.inuse.type_info) )
                put_page_and_type(page+i);
            
            if ( test_and_clear_bit(_PGC_allocated, &(page+i)->count_info) )
                put_page(page+i);

            put_page(page+i);

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
 *  d->tot_pages == P + d->arch.p2m->pod.count
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
    populated = d->tot_pages - p2m->pod.count;
    if ( populated > 0 && p2m->pod.entry_count == 0 )
        goto out;

    /* Don't do anything if the domain is being torn down */
    if ( d->is_dying )
        goto out;

    /* T' < B: Don't reduce the cache size; let the balloon driver
     * take care of it. */
    if ( target < d->tot_pages )
        goto out;

    pod_target = target - populated;

    /* B < T': Set the cache size equal to # of outstanding entries,
     * let the balloon driver fill in the rest. */
    if ( populated > 0 && pod_target > p2m->pod.entry_count )
        pod_target = p2m->pod.entry_count;

    ASSERT( pod_target >= p2m->pod.count );

    ret = p2m_pod_set_cache_target(p2m, pod_target, 1/*preemptible*/);

out:
    pod_unlock(p2m);

    return ret;
}

void
p2m_pod_empty_cache(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *page;

    /* After this barrier no new PoD activities can happen. */
    BUG_ON(!d->is_dying);
    spin_barrier(&p2m->pod.lock.lock);

    lock_page_alloc(p2m);

    while ( (page = page_list_remove_head(&p2m->pod.super)) )
    {
        int i;
            
        for ( i = 0 ; i < SUPERPAGE_PAGES ; i++ )
        {
            BUG_ON(page_get_owner(page + i) != d);
            page_list_add_tail(page + i, &d->page_list);
        }

        p2m->pod.count -= SUPERPAGE_PAGES;
    }

    while ( (page = page_list_remove_head(&p2m->pod.single)) )
    {
        BUG_ON(page_get_owner(page) != d);
        page_list_add_tail(page, &d->page_list);

        p2m->pod.count -= 1;
    }

    BUG_ON(p2m->pod.count != 0);

    unlock_page_alloc(p2m);
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

    if ( !(d = page_get_owner(p)) || !(p2m = p2m_get_hostp2m(d)) )
        return;

    free_domheap_page(p);

    p = alloc_domheap_page(d, PAGE_ORDER_4K);
    if ( unlikely(!p) )
        return;

    pod_lock(p2m);
    p2m_pod_cache_add(p2m, p, PAGE_ORDER_4K);
    pod_unlock(p2m);
    return;
}

static int
p2m_pod_zero_check_superpage(struct p2m_domain *p2m, unsigned long gfn);


/* This function is needed for two reasons:
 * + To properly handle clearing of PoD entries
 * + To "steal back" memory being freed for the PoD cache, rather than
 *   releasing it.
 *
 * Once both of these functions have been completed, we can return and
 * allow decrease_reservation() to handle everything else.
 */
int
p2m_pod_decrease_reservation(struct domain *d,
                             xen_pfn_t gpfn,
                             unsigned int order)
{
    int ret=0;
    int i;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    int steal_for_cache;
    int pod, nonpod, ram;

    gfn_lock(p2m, gpfn, order);
    pod_lock(p2m);    

    /* If we don't have any outstanding PoD entries, let things take their
     * course */
    if ( p2m->pod.entry_count == 0 )
        goto out_unlock;

    if ( unlikely(d->is_dying) )
        goto out_unlock;

recount:
    pod = nonpod = ram = 0;

    /* Figure out if we need to steal some freed memory for our cache */
    steal_for_cache =  ( p2m->pod.entry_count > p2m->pod.count );

    /* FIXME: Add contiguous; query for PSE entries? */
    for ( i=0; i<(1<<order); i++)
    {
        p2m_access_t a;
        p2m_type_t t;

        (void)p2m->get_entry(p2m, gpfn + i, &t, &a, 0, NULL, NULL);

        if ( t == p2m_populate_on_demand )
            pod++;
        else
        {
            nonpod++;
            if ( p2m_is_ram(t) )
                ram++;
        }
    }

    /* No populate-on-demand?  Don't need to steal anything?  Then we're done!*/
    if(!pod && !steal_for_cache)
        goto out_unlock;

    if ( !nonpod )
    {
        /* All PoD: Mark the whole region invalid and tell caller
         * we're done. */
        p2m_set_entry(p2m, gpfn, _mfn(INVALID_MFN), order, p2m_invalid,
                      p2m->default_access);
        p2m->pod.entry_count-=(1<<order);
        BUG_ON(p2m->pod.entry_count < 0);
        ret = 1;
        goto out_entry_check;
    }

    /* Try to grab entire superpages if possible.  Since the common case is for drivers
     * to pass back singleton pages, see if we can take the whole page back and mark the
     * rest PoD. */
    if ( steal_for_cache
         && p2m_pod_zero_check_superpage(p2m, gpfn & ~(SUPERPAGE_PAGES-1)))
    {
        /* Since order may be arbitrary, we may have taken more or less
         * than we were actually asked to; so just re-count from scratch */
        goto recount;
    }

    /* Process as long as:
     * + There are PoD entries to handle, or
     * + There is ram left, and we want to steal it
     */
    for ( i=0;
          i<(1<<order) && (pod>0 || (steal_for_cache && ram > 0));
          i++)
    {
        mfn_t mfn;
        p2m_type_t t;
        p2m_access_t a;

        mfn = p2m->get_entry(p2m, gpfn + i, &t, &a, 0, NULL, NULL);
        if ( t == p2m_populate_on_demand )
        {
            p2m_set_entry(p2m, gpfn + i, _mfn(INVALID_MFN), 0, p2m_invalid,
                          p2m->default_access);
            p2m->pod.entry_count--;
            BUG_ON(p2m->pod.entry_count < 0);
            pod--;
        }
        else if ( steal_for_cache && p2m_is_ram(t) )
        {
            struct page_info *page;

            ASSERT(mfn_valid(mfn));

            page = mfn_to_page(mfn);

            p2m_set_entry(p2m, gpfn + i, _mfn(INVALID_MFN), 0, p2m_invalid,
                          p2m->default_access);
            set_gpfn_from_mfn(mfn_x(mfn), INVALID_M2P_ENTRY);

            p2m_pod_cache_add(p2m, page, 0);

            steal_for_cache =  ( p2m->pod.entry_count > p2m->pod.count );

            nonpod--;
            ram--;
        }
    }    

    /* If there are no more non-PoD entries, tell decrease_reservation() that
     * there's nothing left to do. */
    if ( nonpod == 0 )
        ret = 1;

out_entry_check:
    /* If we've reduced our "liabilities" beyond our "assets", free some */
    if ( p2m->pod.entry_count < p2m->pod.count )
    {
        p2m_pod_set_cache_target(p2m, p2m->pod.entry_count, 0/*can't preempt*/);
    }

out_unlock:
    pod_unlock(p2m);
    gfn_unlock(p2m, gpfn, order);
    return ret;
}

void p2m_pod_dump_data(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    printk("    PoD entries=%ld cachesize=%ld\n",
           p2m->pod.entry_count, p2m->pod.count);
}


/* Search for all-zero superpages to be reclaimed as superpages for the
 * PoD cache. Must be called w/ pod lock held, must lock the superpage
 * in the p2m */
static int
p2m_pod_zero_check_superpage(struct p2m_domain *p2m, unsigned long gfn)
{
    mfn_t mfn, mfn0 = _mfn(INVALID_MFN);
    p2m_type_t type, type0 = 0;
    unsigned long * map = NULL;
    int ret=0, reset = 0;
    int i, j;
    int max_ref = 1;
    struct domain *d = p2m->domain;

    ASSERT(pod_locked_by_me(p2m));

    if ( !superpage_aligned(gfn) )
        goto out;

    /* Allow an extra refcount for one shadow pt mapping in shadowed domains */
    if ( paging_mode_shadow(d) )
        max_ref++;

    /* NOTE: this is why we don't enforce deadlock constraints between p2m 
     * and pod locks */
    gfn_lock(p2m, gfn, SUPERPAGE_ORDER);

    /* Look up the mfns, checking to make sure they're the same mfn
     * and aligned, and mapping them. */
    for ( i=0; i<SUPERPAGE_PAGES; i++ )
    {
        p2m_access_t a; 
        mfn = p2m->get_entry(p2m, gfn + i, &type, &a, 0, NULL, NULL);

        if ( i == 0 )
        {
            mfn0 = mfn;
            type0 = type;
        }

        /* Conditions that must be met for superpage-superpage:
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
        if ( !p2m_is_ram(type)
             || type != type0
             || ( (mfn_to_page(mfn)->count_info & PGC_allocated) == 0 )
             || ( (mfn_to_page(mfn)->count_info & (PGC_page_table|PGC_xen_heap)) != 0 )
             || ( (mfn_to_page(mfn)->count_info & PGC_xen_heap  ) != 0 )
             || ( (mfn_to_page(mfn)->count_info & PGC_count_mask) > max_ref )
             || !( ( i == 0 && superpage_aligned(mfn_x(mfn0)) )
                   || ( i != 0 && mfn_x(mfn) == (mfn_x(mfn0) + i) ) ) )
            goto out;
    }

    /* Now, do a quick check to see if it may be zero before unmapping. */
    for ( i=0; i<SUPERPAGE_PAGES; i++ )
    {
        /* Quick zero-check */
        map = map_domain_page(_mfn(mfn_x(mfn0) + i));

        for ( j=0; j<16; j++ )
            if( *(map+j) != 0 )
                break;

        unmap_domain_page(map);

        if ( j < 16 )
            goto out;

    }

    /* Try to remove the page, restoring old mapping if it fails. */
    p2m_set_entry(p2m, gfn, _mfn(0), PAGE_ORDER_2M,
                  p2m_populate_on_demand, p2m->default_access);

    /* Make none of the MFNs are used elsewhere... for example, mapped
     * via the grant table interface, or by qemu.  Allow one refcount for
     * being allocated to the domain. */
    for ( i=0; i < SUPERPAGE_PAGES; i++ )
    {
        mfn = _mfn(mfn_x(mfn0) + i);
        if ( (mfn_to_page(mfn)->count_info & PGC_count_mask) > 1 )
        {
            reset = 1;
            goto out_reset;
        }
    }

    /* Finally, do a full zero-check */
    for ( i=0; i < SUPERPAGE_PAGES; i++ )
    {
        map = map_domain_page(_mfn(mfn_x(mfn0) + i));

        for ( j=0; j<PAGE_SIZE/sizeof(*map); j++ )
            if( *(map+j) != 0 )
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
            u64 gfn, mfn;
            int d:16,order:16;
        } t;

        t.gfn = gfn;
        t.mfn = mfn_x(mfn);
        t.d = d->domain_id;
        t.order = 9;

        __trace_var(TRC_MEM_POD_ZERO_RECLAIM, 0, sizeof(t), &t);
    }

    /* Finally!  We've passed all the checks, and can add the mfn superpage
     * back on the PoD cache, and account for the new p2m PoD entries */
    p2m_pod_cache_add(p2m, mfn_to_page(mfn0), PAGE_ORDER_2M);
    p2m->pod.entry_count += SUPERPAGE_PAGES;

    ret = SUPERPAGE_PAGES;

out_reset:
    if ( reset )
        p2m_set_entry(p2m, gfn, mfn0, 9, type0, p2m->default_access);
    
out:
    gfn_unlock(p2m, gfn, SUPERPAGE_ORDER);
    return ret;
}

static void
p2m_pod_zero_check(struct p2m_domain *p2m, unsigned long *gfns, int count)
{
    mfn_t mfns[count];
    p2m_type_t types[count];
    unsigned long * map[count];
    struct domain *d = p2m->domain;

    int i, j;
    int max_ref = 1;

    /* Allow an extra refcount for one shadow pt mapping in shadowed domains */
    if ( paging_mode_shadow(d) )
        max_ref++;

    /* First, get the gfn list, translate to mfns, and map the pages. */
    for ( i=0; i<count; i++ )
    {
        p2m_access_t a;
        mfns[i] = p2m->get_entry(p2m, gfns[i], types + i, &a, 0, NULL, NULL);
        /* If this is ram, and not a pagetable or from the xen heap, and probably not mapped
           elsewhere, map it; otherwise, skip. */
        if ( p2m_is_ram(types[i])
             && ( (mfn_to_page(mfns[i])->count_info & PGC_allocated) != 0 ) 
             && ( (mfn_to_page(mfns[i])->count_info & (PGC_page_table|PGC_xen_heap)) == 0 ) 
             && ( (mfn_to_page(mfns[i])->count_info & PGC_count_mask) <= max_ref ) )
            map[i] = map_domain_page(mfns[i]);
        else
            map[i] = NULL;
    }

    /* Then, go through and check for zeroed pages, removing write permission
     * for those with zeroes. */
    for ( i=0; i<count; i++ )
    {
        if(!map[i])
            continue;

        /* Quick zero-check */
        for ( j=0; j<16; j++ )
            if( *(map[i]+j) != 0 )
                break;

        if ( j < 16 )
        {
            unmap_domain_page(map[i]);
            map[i] = NULL;
            continue;
        }

        /* Try to remove the page, restoring old mapping if it fails. */
        p2m_set_entry(p2m, gfns[i], _mfn(0), PAGE_ORDER_4K,
                      p2m_populate_on_demand, p2m->default_access);

        /* See if the page was successfully unmapped.  (Allow one refcount
         * for being allocated to a domain.) */
        if ( (mfn_to_page(mfns[i])->count_info & PGC_count_mask) > 1 )
        {
            unmap_domain_page(map[i]);
            map[i] = NULL;

            p2m_set_entry(p2m, gfns[i], mfns[i], PAGE_ORDER_4K,
                types[i], p2m->default_access);

            continue;
        }
    }

    /* Now check each page for real */
    for ( i=0; i < count; i++ )
    {
        if(!map[i])
            continue;

        for ( j=0; j<PAGE_SIZE/sizeof(*map[i]); j++ )
            if( *(map[i]+j) != 0 )
                break;

        unmap_domain_page(map[i]);

        /* See comment in p2m_pod_zero_check_superpage() re gnttab
         * check timing.  */
        if ( j < PAGE_SIZE/sizeof(*map[i]) )
        {
            p2m_set_entry(p2m, gfns[i], mfns[i], PAGE_ORDER_4K,
                types[i], p2m->default_access);
        }
        else
        {
            if ( tb_init_done )
            {
                struct {
                    u64 gfn, mfn;
                    int d:16,order:16;
                } t;

                t.gfn = gfns[i];
                t.mfn = mfn_x(mfns[i]);
                t.d = d->domain_id;
                t.order = 0;
        
                __trace_var(TRC_MEM_POD_ZERO_RECLAIM, 0, sizeof(t), &t);
            }

            /* Add to cache, and account for the new p2m PoD entry */
            p2m_pod_cache_add(p2m, mfn_to_page(mfns[i]), PAGE_ORDER_4K);
            p2m->pod.entry_count++;
        }
    }
    
}

#define POD_SWEEP_LIMIT 1024
#define POD_SWEEP_STRIDE  16
static void
p2m_pod_emergency_sweep(struct p2m_domain *p2m)
{
    unsigned long gfns[POD_SWEEP_STRIDE];
    unsigned long i, j=0, start, limit;
    p2m_type_t t;


    if ( p2m->pod.reclaim_single == 0 )
        p2m->pod.reclaim_single = p2m->pod.max_guest;

    start = p2m->pod.reclaim_single;
    limit = (start > POD_SWEEP_LIMIT) ? (start - POD_SWEEP_LIMIT) : 0;

    /* FIXME: Figure out how to avoid superpages */
    /* NOTE: Promote to globally locking the p2m. This will get complicated
     * in a fine-grained scenario. If we lock each gfn individually we must be
     * careful about spinlock recursion limits and POD_SWEEP_STRIDE. */
    p2m_lock(p2m);
    for ( i=p2m->pod.reclaim_single; i > 0 ; i-- )
    {
        p2m_access_t a;
        (void)p2m->get_entry(p2m, i, &t, &a, 0, NULL, NULL);
        if ( p2m_is_ram(t) )
        {
            gfns[j] = i;
            j++;
            BUG_ON(j > POD_SWEEP_STRIDE);
            if ( j == POD_SWEEP_STRIDE )
            {
                p2m_pod_zero_check(p2m, gfns, j);
                j = 0;
            }
        }
        /* Stop if we're past our limit and we have found *something*.
         *
         * NB that this is a zero-sum game; we're increasing our cache size
         * by re-increasing our 'debt'.  Since we hold the pod lock,
         * (entry_count - count) must remain the same. */
        if ( i < limit && (p2m->pod.count > 0 || hypercall_preempt_check()) )
            break;
    }

    if ( j )
        p2m_pod_zero_check(p2m, gfns, j);

    p2m_unlock(p2m);
    p2m->pod.reclaim_single = i ? i - 1 : i;

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
        unsigned long gfn = mrp->list[idx];

        if ( gfn != INVALID_GFN )
        {
            if ( gfn & POD_LAST_SUPERPAGE )
            {
                gfn &= ~POD_LAST_SUPERPAGE;

                if ( p2m_pod_zero_check_superpage(p2m, gfn) == 0 )
                {
                    unsigned int x;

                    for ( x = 0; x < SUPERPAGE_PAGES; ++x, ++gfn )
                        p2m_pod_zero_check(p2m, &gfn, 1);
                }
            }
            else
                p2m_pod_zero_check(p2m, &gfn, 1);

            mrp->list[idx] = INVALID_GFN;
        }

    } while ( (p2m->pod.count == 0) && (i < ARRAY_SIZE(mrp->list)) );
}

static void pod_eager_record(struct p2m_domain *p2m,
                             unsigned long gfn, unsigned int order)
{
    struct pod_mrp_list *mrp = &p2m->pod.mrp;

    ASSERT(mrp->list[mrp->idx] == INVALID_GFN);
    ASSERT(gfn != INVALID_GFN);

    mrp->list[mrp->idx++] =
        gfn | (order == PAGE_ORDER_2M ? POD_LAST_SUPERPAGE : 0);
    mrp->idx %= ARRAY_SIZE(mrp->list);
}

int
p2m_pod_demand_populate(struct p2m_domain *p2m, unsigned long gfn,
                        unsigned int order,
                        p2m_query_t q)
{
    struct domain *d = p2m->domain;
    struct page_info *p = NULL; /* Compiler warnings */
    unsigned long gfn_aligned;
    mfn_t mfn;
    int i;

    ASSERT(gfn_locked_by_me(p2m, gfn));
    pod_lock(p2m);

    /* This check is done with the pod lock held.  This will make sure that
     * even if d->is_dying changes under our feet, p2m_pod_empty_cache() 
     * won't start until we're done. */
    if ( unlikely(d->is_dying) )
        goto out_fail;

    
    /* Because PoD does not have cache list for 1GB pages, it has to remap
     * 1GB region to 2MB chunks for a retry. */
    if ( order == PAGE_ORDER_1G )
    {
        pod_unlock(p2m);
        gfn_aligned = (gfn >> order) << order;
        /* Note that we are supposed to call p2m_set_entry() 512 times to
         * split 1GB into 512 2MB pages here. But We only do once here because
         * p2m_set_entry() should automatically shatter the 1GB page into
         * 512 2MB pages. The rest of 511 calls are unnecessary.
         *
         * NOTE: In a fine-grained p2m locking scenario this operation
         * may need to promote its locking from gfn->1g superpage
         */
        p2m_set_entry(p2m, gfn_aligned, _mfn(0), PAGE_ORDER_2M,
                      p2m_populate_on_demand, p2m->default_access);
        return 0;
    }

    pod_eager_reclaim(p2m);

    /* Only sweep if we're actually out of memory.  Doing anything else
     * causes unnecessary time and fragmentation of superpages in the p2m. */
    if ( p2m->pod.count == 0 )
        p2m_pod_emergency_sweep(p2m);

    /* If the sweep failed, give up. */
    if ( p2m->pod.count == 0 )
        goto out_of_memory;

    /* Keep track of the highest gfn demand-populated by a guest fault */
    if ( gfn > p2m->pod.max_guest )
        p2m->pod.max_guest = gfn;

    /* Get a page f/ the cache.  A NULL return value indicates that the
     * 2-meg range should be marked singleton PoD, and retried */
    if ( (p = p2m_pod_cache_get(p2m, order)) == NULL )
        goto remap_and_retry;

    mfn = page_to_mfn(p);

    BUG_ON((mfn_x(mfn) & ((1 << order)-1)) != 0);

    gfn_aligned = (gfn >> order) << order;

    p2m_set_entry(p2m, gfn_aligned, mfn, order, p2m_ram_rw,
                  p2m->default_access);

    for( i = 0; i < (1UL << order); i++ )
    {
        set_gpfn_from_mfn(mfn_x(mfn) + i, gfn_aligned + i);
        paging_mark_dirty(d, mfn_x(mfn) + i);
    }
    
    p2m->pod.entry_count -= (1 << order);
    BUG_ON(p2m->pod.entry_count < 0);

    pod_eager_record(p2m, gfn_aligned, order);

    if ( tb_init_done )
    {
        struct {
            u64 gfn, mfn;
            int d:16,order:16;
        } t;

        t.gfn = gfn;
        t.mfn = mfn_x(mfn);
        t.d = d->domain_id;
        t.order = order;
        
        __trace_var(TRC_MEM_POD_POPULATE, 0, sizeof(t), &t);
    }

    pod_unlock(p2m);
    return 0;
out_of_memory:
    pod_unlock(p2m);

    printk("%s: Dom%d out of PoD memory! (tot=%"PRIu32" ents=%ld dom%d)\n",
           __func__, d->domain_id, d->tot_pages, p2m->pod.entry_count,
           current->domain->domain_id);
    domain_crash(d);
    return -1;
out_fail:
    pod_unlock(p2m);
    return -1;
remap_and_retry:
    BUG_ON(order != PAGE_ORDER_2M);
    pod_unlock(p2m);

    /* Remap this 2-meg region in singleton chunks */
    /* NOTE: In a p2m fine-grained lock scenario this might
     * need promoting the gfn lock from gfn->2M superpage */
    gfn_aligned = (gfn>>order)<<order;
    for(i=0; i<(1<<order); i++)
        p2m_set_entry(p2m, gfn_aligned+i, _mfn(0), PAGE_ORDER_4K,
                      p2m_populate_on_demand, p2m->default_access);
    if ( tb_init_done )
    {
        struct {
            u64 gfn;
            int d:16;
        } t;

        t.gfn = gfn;
        t.d = d->domain_id;
        
        __trace_var(TRC_MEM_POD_SUPERPAGE_SPLINTER, 0, sizeof(t), &t);
    }

    return 0;
}


int
guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                      unsigned int order)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long i, pod_count = 0;
    p2m_type_t ot;
    mfn_t omfn;
    int rc = 0;

    if ( !paging_mode_translate(d) )
        return -EINVAL;

    gfn_lock(p2m, gfn, order);

    P2M_DEBUG("mark pod gfn=%#lx\n", gfn);

    /* Make sure all gpfns are unused */
    for ( i = 0; i < (1UL << order); i++ )
    {
        p2m_access_t a;
        omfn = p2m->get_entry(p2m, gfn + i, &ot, &a, 0, NULL, NULL);
        if ( p2m_is_ram(ot) )
        {
            P2M_DEBUG("gfn_to_mfn returned type %d!\n", ot);
            rc = -EBUSY;
            goto out;
        }
        else if ( ot == p2m_populate_on_demand )
        {
            /* Count how man PoD entries we'll be replacing if successful */
            pod_count++;
        }
    }

    /* Now, actually do the two-way mapping */
    rc = p2m_set_entry(p2m, gfn, _mfn(0), order, p2m_populate_on_demand,
                       p2m->default_access);
    if ( rc == 0 )
    {
        pod_lock(p2m);
        p2m->pod.entry_count += 1 << order;
        p2m->pod.entry_count -= pod_count;
        BUG_ON(p2m->pod.entry_count < 0);
        pod_unlock(p2m);
    }

out:
    gfn_unlock(p2m, gfn, order);

    return rc;
}

