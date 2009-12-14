/******************************************************************************
 * arch/x86/mm/p2m.c
 *
 * physical-to-machine mappings for automatically-translated domains.
 *
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

/* Debugging and auditing of the P2M code? */
#define P2M_AUDIT     0
#define P2M_DEBUGGING 0

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


/* PTE flags for the various types of p2m entry */
#define P2M_BASE_FLAGS \
        (_PAGE_PRESENT | _PAGE_USER | _PAGE_DIRTY | _PAGE_ACCESSED)

#define SUPERPAGE_PAGES (1UL << 9)
#define superpage_aligned(_x)  (((_x)&(SUPERPAGE_PAGES-1))==0)

static unsigned long p2m_type_to_flags(p2m_type_t t) 
{
    unsigned long flags;
#ifdef __x86_64__
    flags = (unsigned long)(t & 0x3fff) << 9;
#else
    flags = (t & 0x7UL) << 9;
#endif
#ifndef HAVE_GRANT_MAP_P2M
    BUG_ON(p2m_is_grant(t));
#endif
    switch(t)
    {
    case p2m_invalid:
    default:
        return flags;
    case p2m_ram_rw:
    case p2m_grant_map_rw:
        return flags | P2M_BASE_FLAGS | _PAGE_RW;
    case p2m_ram_logdirty:
        return flags | P2M_BASE_FLAGS;
    case p2m_ram_ro:
    case p2m_grant_map_ro:
        return flags | P2M_BASE_FLAGS;
    case p2m_mmio_dm:
        return flags;
    case p2m_mmio_direct:
        return flags | P2M_BASE_FLAGS | _PAGE_RW | _PAGE_PCD;
    case p2m_populate_on_demand:
        return flags;
    }
}

#if P2M_AUDIT
static void audit_p2m(struct domain *d);
#else
# define audit_p2m(_d) do { (void)(_d); } while(0)
#endif /* P2M_AUDIT */

// Find the next level's P2M entry, checking for out-of-range gfn's...
// Returns NULL on error.
//
static l1_pgentry_t *
p2m_find_entry(void *table, unsigned long *gfn_remainder,
                   unsigned long gfn, u32 shift, u32 max)
{
    u32 index;

    index = *gfn_remainder >> shift;
    if ( index >= max )
    {
        P2M_DEBUG("gfn=0x%lx out of range "
                  "(gfn_remainder=0x%lx shift=%d index=0x%x max=0x%x)\n",
                  gfn, *gfn_remainder, shift, index, max);
        return NULL;
    }
    *gfn_remainder &= (1 << shift) - 1;
    return (l1_pgentry_t *)table + index;
}

// Walk one level of the P2M table, allocating a new table if required.
// Returns 0 on error.
//
static int
p2m_next_level(struct domain *d, mfn_t *table_mfn, void **table,
               unsigned long *gfn_remainder, unsigned long gfn, u32 shift,
               u32 max, unsigned long type)
{
    l1_pgentry_t *l1_entry;
    l1_pgentry_t *p2m_entry;
    l1_pgentry_t new_entry;
    void *next;
    int i;
    ASSERT(d->arch.p2m->alloc_page);

    if ( !(p2m_entry = p2m_find_entry(*table, gfn_remainder, gfn,
                                      shift, max)) )
        return 0;

    /* PoD: Not present doesn't imply empty. */
    if ( !l1e_get_flags(*p2m_entry) )
    {
        struct page_info *pg = d->arch.p2m->alloc_page(d);
        if ( pg == NULL )
            return 0;
        page_list_add_tail(pg, &d->arch.p2m->pages);
        pg->u.inuse.type_info = type | 1 | PGT_validated;
        pg->count_info |= 1;

        new_entry = l1e_from_pfn(mfn_x(page_to_mfn(pg)),
                                 __PAGE_HYPERVISOR|_PAGE_USER);

        switch ( type ) {
        case PGT_l3_page_table:
            paging_write_p2m_entry(d, gfn,
                                   p2m_entry, *table_mfn, new_entry, 4);
            break;
        case PGT_l2_page_table:
#if CONFIG_PAGING_LEVELS == 3
            /* for PAE mode, PDPE only has PCD/PWT/P bits available */
            new_entry = l1e_from_pfn(mfn_x(page_to_mfn(pg)), _PAGE_PRESENT);
#endif
            paging_write_p2m_entry(d, gfn,
                                   p2m_entry, *table_mfn, new_entry, 3);
            break;
        case PGT_l1_page_table:
            paging_write_p2m_entry(d, gfn,
                                   p2m_entry, *table_mfn, new_entry, 2);
            break;
        default:
            BUG();
            break;
        }
    }

    ASSERT(l1e_get_flags(*p2m_entry) & (_PAGE_PRESENT|_PAGE_PSE));

    /* split single large page into 4KB page in P2M table */
    if ( type == PGT_l1_page_table && (l1e_get_flags(*p2m_entry) & _PAGE_PSE) )
    {
        unsigned long flags, pfn;
        struct page_info *pg = d->arch.p2m->alloc_page(d);
        if ( pg == NULL )
            return 0;
        page_list_add_tail(pg, &d->arch.p2m->pages);
        pg->u.inuse.type_info = PGT_l1_page_table | 1 | PGT_validated;
        pg->count_info |= 1;
        
        /* New splintered mappings inherit the flags of the old superpage, 
         * with a little reorganisation for the _PAGE_PSE_PAT bit. */
        flags = l1e_get_flags(*p2m_entry);
        pfn = l1e_get_pfn(*p2m_entry);
        if ( pfn & 1 )           /* ==> _PAGE_PSE_PAT was set */
            pfn -= 1;            /* Clear it; _PAGE_PSE becomes _PAGE_PAT */
        else
            flags &= ~_PAGE_PSE; /* Clear _PAGE_PSE (== _PAGE_PAT) */
        
        l1_entry = __map_domain_page(pg);
        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            new_entry = l1e_from_pfn(pfn + i, flags);
            paging_write_p2m_entry(d, gfn,
                                   l1_entry+i, *table_mfn, new_entry, 1);
        }
        unmap_domain_page(l1_entry);
        
        new_entry = l1e_from_pfn(mfn_x(page_to_mfn(pg)),
                                 __PAGE_HYPERVISOR|_PAGE_USER);
        paging_write_p2m_entry(d, gfn,
                               p2m_entry, *table_mfn, new_entry, 2);
    }

    *table_mfn = _mfn(l1e_get_pfn(*p2m_entry));
    next = map_domain_page(mfn_x(*table_mfn));
    unmap_domain_page(*table);
    *table = next;

    return 1;
}

/*
 * Populate-on-demand functionality
 */
static
int set_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn, 
                  unsigned int page_order, p2m_type_t p2mt);

static int
p2m_pod_cache_add(struct domain *d,
                  struct page_info *page,
                  unsigned long order)
{
    int i;
    struct page_info *p;
    struct p2m_domain *p2md = d->arch.p2m;

#ifndef NDEBUG
    mfn_t mfn;

    mfn = page_to_mfn(page);

    /* Check to make sure this is a contiguous region */
    if( mfn_x(mfn) & ((1 << order) - 1) )
    {
        printk("%s: mfn %lx not aligned order %lu! (mask %lx)\n",
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

    ASSERT(p2m_locked_by_me(p2md));

    /*
     * Pages from domain_alloc and returned by the balloon driver aren't
     * guaranteed to be zero; but by reclaiming zero pages, we implicitly
     * promise to provide zero pages. So we scrub pages before using.
     */
    for ( i = 0; i < (1 << order); i++ )
    {
        char *b = map_domain_page(mfn_x(page_to_mfn(page)) + i);
        clear_page(b);
        unmap_domain_page(b);
    }

    spin_lock(&d->page_alloc_lock);

    /* First, take all pages off the domain list */
    for(i=0; i < 1 << order ; i++)
    {
        p = page + i;
        page_list_del(p, &d->page_list);
    }

    /* Then add the first one to the appropriate populate-on-demand list */
    switch(order)
    {
    case 9:
        page_list_add_tail(page, &p2md->pod.super); /* lock: page_alloc */
        p2md->pod.count += 1 << order;
        break;
    case 0:
        page_list_add_tail(page, &p2md->pod.single); /* lock: page_alloc */
        p2md->pod.count += 1 ;
        break;
    default:
        BUG();
    }

    /* Ensure that the PoD cache has never been emptied.  
     * This may cause "zombie domains" since the page will never be freed. */
    BUG_ON( d->arch.relmem != RELMEM_not_started );

    spin_unlock(&d->page_alloc_lock);

    return 0;
}

/* Get a page of size order from the populate-on-demand cache.  Will break
 * down 2-meg pages into singleton pages automatically.  Returns null if
 * a superpage is requested and no superpages are available.  Must be called
 * with the d->page_lock held. */
static struct page_info * p2m_pod_cache_get(struct domain *d,
                                            unsigned long order)
{
    struct p2m_domain *p2md = d->arch.p2m;
    struct page_info *p = NULL;
    int i;

    if ( order == 9 && page_list_empty(&p2md->pod.super) )
    {
        return NULL;
    }
    else if ( order == 0 && page_list_empty(&p2md->pod.single) )
    {
        unsigned long mfn;
        struct page_info *q;

        BUG_ON( page_list_empty(&p2md->pod.super) );

        /* Break up a superpage to make single pages. NB count doesn't
         * need to be adjusted. */
        p = page_list_remove_head(&p2md->pod.super);
        mfn = mfn_x(page_to_mfn(p));

        for ( i=0; i<SUPERPAGE_PAGES; i++ )
        {
            q = mfn_to_page(_mfn(mfn+i));
            page_list_add_tail(q, &p2md->pod.single);
        }
    }

    switch ( order )
    {
    case 9:
        BUG_ON( page_list_empty(&p2md->pod.super) );
        p = page_list_remove_head(&p2md->pod.super);
        p2md->pod.count -= 1 << order; /* Lock: page_alloc */
        break;
    case 0:
        BUG_ON( page_list_empty(&p2md->pod.single) );
        p = page_list_remove_head(&p2md->pod.single);
        p2md->pod.count -= 1;
        break;
    default:
        BUG();
    }

    /* Put the pages back on the domain page_list */
    for ( i = 0 ; i < (1 << order) ; i++ )
    {
        BUG_ON(page_get_owner(p + i) != d);
        page_list_add_tail(p + i, &d->page_list);
    }

    return p;
}

/* Set the size of the cache, allocating or freeing as necessary. */
static int
p2m_pod_set_cache_target(struct domain *d, unsigned long pod_target)
{
    struct p2m_domain *p2md = d->arch.p2m;
    int ret = 0;

    /* Increasing the target */
    while ( pod_target > p2md->pod.count )
    {
        struct page_info * page;
        int order;

        if ( (pod_target - p2md->pod.count) >= SUPERPAGE_PAGES )
            order = 9;
        else
            order = 0;
    retry:
        page = alloc_domheap_pages(d, order, 0);
        if ( unlikely(page == NULL) )
        {
            if ( order == 9 )
            {
                /* If we can't allocate a superpage, try singleton pages */
                order = 0;
                goto retry;
            }   
            
            printk("%s: Unable to allocate domheap page for pod cache.  target %lu cachesize %d\n",
                   __func__, pod_target, p2md->pod.count);
            ret = -ENOMEM;
            goto out;
        }

        p2m_pod_cache_add(d, page, order);
    }

    /* Decreasing the target */
    /* We hold the p2m lock here, so we don't need to worry about
     * cache disappearing under our feet. */
    while ( pod_target < p2md->pod.count )
    {
        struct page_info * page;
        int order, i;

        /* Grab the lock before checking that pod.super is empty, or the last
         * entries may disappear before we grab the lock. */
        spin_lock(&d->page_alloc_lock);

        if ( (p2md->pod.count - pod_target) > SUPERPAGE_PAGES
             && !page_list_empty(&p2md->pod.super) )
            order = 9;
        else
            order = 0;

        page = p2m_pod_cache_get(d, order);

        ASSERT(page != NULL);

        spin_unlock(&d->page_alloc_lock);

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
    unsigned pod_target;
    struct p2m_domain *p2md = d->arch.p2m;
    int ret = 0;
    unsigned long populated;

    p2m_lock(p2md);

    /* P == B: Nothing to do. */
    if ( p2md->pod.entry_count == 0 )
        goto out;

    /* Don't do anything if the domain is being torn down */
    if ( d->is_dying )
        goto out;

    /* T' < B: Don't reduce the cache size; let the balloon driver
     * take care of it. */
    if ( target < d->tot_pages )
        goto out;

    populated  = d->tot_pages - p2md->pod.count;

    pod_target = target - populated;

    /* B < T': Set the cache size equal to # of outstanding entries,
     * let the balloon driver fill in the rest. */
    if ( pod_target > p2md->pod.entry_count )
        pod_target = p2md->pod.entry_count;

    ASSERT( pod_target >= p2md->pod.count );

    ret = p2m_pod_set_cache_target(d, pod_target);

out:
    p2m_unlock(p2md);

    return ret;
}

void
p2m_pod_empty_cache(struct domain *d)
{
    struct p2m_domain *p2md = d->arch.p2m;
    struct page_info *page;

    /* After this barrier no new PoD activities can happen. */
    BUG_ON(!d->is_dying);
    spin_barrier(&p2md->lock);

    spin_lock(&d->page_alloc_lock);

    while ( (page = page_list_remove_head(&p2md->pod.super)) )
    {
        int i;
            
        for ( i = 0 ; i < SUPERPAGE_PAGES ; i++ )
        {
            BUG_ON(page_get_owner(page + i) != d);
            page_list_add_tail(page + i, &d->page_list);
        }

        p2md->pod.count -= SUPERPAGE_PAGES;
    }

    while ( (page = page_list_remove_head(&p2md->pod.single)) )
    {
        BUG_ON(page_get_owner(page) != d);
        page_list_add_tail(page, &d->page_list);

        p2md->pod.count -= 1;
    }

    BUG_ON(p2md->pod.count != 0);

    spin_unlock(&d->page_alloc_lock);
}

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
    struct p2m_domain *p2md = d->arch.p2m;
    int ret=0;
    int i;

    int steal_for_cache = 0;
    int pod = 0, nonpod = 0, ram = 0;
    

    /* If we don't have any outstanding PoD entries, let things take their
     * course */
    if ( p2md->pod.entry_count == 0 )
        goto out;

    /* Figure out if we need to steal some freed memory for our cache */
    steal_for_cache =  ( p2md->pod.entry_count > p2md->pod.count );

    p2m_lock(p2md);
    audit_p2m(d);

    if ( unlikely(d->is_dying) )
        goto out_unlock;

    /* See what's in here. */
    /* FIXME: Add contiguous; query for PSE entries? */
    for ( i=0; i<(1<<order); i++)
    {
        p2m_type_t t;

        gfn_to_mfn_query(d, gpfn + i, &t);

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
        set_p2m_entry(d, gpfn, _mfn(INVALID_MFN), order, p2m_invalid);
        p2md->pod.entry_count-=(1<<order); /* Lock: p2m */
        BUG_ON(p2md->pod.entry_count < 0);
        ret = 1;
        goto out_entry_check;
    }

    /* FIXME: Steal contig 2-meg regions for cache */

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

        mfn = gfn_to_mfn_query(d, gpfn + i, &t);
        if ( t == p2m_populate_on_demand )
        {
            set_p2m_entry(d, gpfn + i, _mfn(INVALID_MFN), 0, p2m_invalid);
            p2md->pod.entry_count--; /* Lock: p2m */
            BUG_ON(p2md->pod.entry_count < 0);
            pod--;
        }
        else if ( steal_for_cache && p2m_is_ram(t) )
        {
            struct page_info *page;

            ASSERT(mfn_valid(mfn));

            page = mfn_to_page(mfn);

            set_p2m_entry(d, gpfn + i, _mfn(INVALID_MFN), 0, p2m_invalid);
            set_gpfn_from_mfn(mfn_x(mfn), INVALID_M2P_ENTRY);

            p2m_pod_cache_add(d, page, 0);

            steal_for_cache =  ( p2md->pod.entry_count > p2md->pod.count );

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
    if ( p2md->pod.entry_count < p2md->pod.count )
    {
        p2m_pod_set_cache_target(d, p2md->pod.entry_count);
    }

out_unlock:
    audit_p2m(d);
    p2m_unlock(p2md);

out:
    return ret;
}

void
p2m_pod_dump_data(struct domain *d)
{
    struct p2m_domain *p2md = d->arch.p2m;
    
    printk("    PoD entries=%d cachesize=%d\n",
           p2md->pod.entry_count, p2md->pod.count);
}


/* Search for all-zero superpages to be reclaimed as superpages for the
 * PoD cache. Must be called w/ p2m lock held, page_alloc lock not held. */
static int
p2m_pod_zero_check_superpage(struct domain *d, unsigned long gfn)
{
    mfn_t mfn, mfn0 = _mfn(INVALID_MFN);
    p2m_type_t type, type0 = 0;
    unsigned long * map = NULL;
    int ret=0, reset = 0;
    int i, j;
    int max_ref = 1;

    if ( !superpage_aligned(gfn) )
        goto out;

    /* Allow an extra refcount for one shadow pt mapping in shadowed domains */
    if ( paging_mode_shadow(d) )
        max_ref++;

    /* Look up the mfns, checking to make sure they're the same mfn
     * and aligned, and mapping them. */
    for ( i=0; i<SUPERPAGE_PAGES; i++ )
    {
        
        mfn = gfn_to_mfn_query(d, gfn + i, &type);

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
        map = map_domain_page(mfn_x(mfn0) + i);

        for ( j=0; j<16; j++ )
            if( *(map+j) != 0 )
                break;

        unmap_domain_page(map);

        if ( j < 16 )
            goto out;

    }

    /* Try to remove the page, restoring old mapping if it fails. */
    set_p2m_entry(d, gfn,
                  _mfn(POPULATE_ON_DEMAND_MFN), 9,
                  p2m_populate_on_demand);

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
        map = map_domain_page(mfn_x(mfn0) + i);

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

    /* Finally!  We've passed all the checks, and can add the mfn superpage
     * back on the PoD cache, and account for the new p2m PoD entries */
    p2m_pod_cache_add(d, mfn_to_page(mfn0), 9);
    d->arch.p2m->pod.entry_count += SUPERPAGE_PAGES;

out_reset:
    if ( reset )
        set_p2m_entry(d, gfn, mfn0, 9, type0);
    
out:
    return ret;
}

static void
p2m_pod_zero_check(struct domain *d, unsigned long *gfns, int count)
{
    mfn_t mfns[count];
    p2m_type_t types[count];
    unsigned long * map[count];

    int i, j;
    int max_ref = 1;

    /* Allow an extra refcount for one shadow pt mapping in shadowed domains */
    if ( paging_mode_shadow(d) )
        max_ref++;

    /* First, get the gfn list, translate to mfns, and map the pages. */
    for ( i=0; i<count; i++ )
    {
        mfns[i] = gfn_to_mfn_query(d, gfns[i], types + i);
        /* If this is ram, and not a pagetable or from the xen heap, and probably not mapped
           elsewhere, map it; otherwise, skip. */
        if ( p2m_is_ram(types[i])
             && ( (mfn_to_page(mfns[i])->count_info & PGC_allocated) != 0 ) 
             && ( (mfn_to_page(mfns[i])->count_info & (PGC_page_table|PGC_xen_heap)) == 0 ) 
             && ( (mfn_to_page(mfns[i])->count_info & PGC_count_mask) <= max_ref ) )
            map[i] = map_domain_page(mfn_x(mfns[i]));
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
        set_p2m_entry(d, gfns[i],
                      _mfn(POPULATE_ON_DEMAND_MFN), 0,
                      p2m_populate_on_demand);

        /* See if the page was successfully unmapped.  (Allow one refcount
         * for being allocated to a domain.) */
        if ( (mfn_to_page(mfns[i])->count_info & PGC_count_mask) > 1 )
        {
            unmap_domain_page(map[i]);
            map[i] = NULL;

            set_p2m_entry(d, gfns[i], mfns[i], 0, types[i]);

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
            set_p2m_entry(d, gfns[i], mfns[i], 0, types[i]);
        }
        else
        {
            /* Add to cache, and account for the new p2m PoD entry */
            p2m_pod_cache_add(d, mfn_to_page(mfns[i]), 0);
            d->arch.p2m->pod.entry_count++;
        }
    }
    
}

#define POD_SWEEP_LIMIT 1024
static void
p2m_pod_emergency_sweep_super(struct domain *d)
{
    struct p2m_domain *p2md = d->arch.p2m;
    unsigned long i, start, limit;

    if ( p2md->pod.reclaim_super == 0 )
    {
        p2md->pod.reclaim_super = (p2md->pod.max_guest>>9)<<9;
        p2md->pod.reclaim_super -= SUPERPAGE_PAGES;
    }
    
    start = p2md->pod.reclaim_super;
    limit = (start > POD_SWEEP_LIMIT) ? (start - POD_SWEEP_LIMIT) : 0;

    for ( i=p2md->pod.reclaim_super ; i > 0 ; i-=SUPERPAGE_PAGES )
    {
        p2m_pod_zero_check_superpage(d, i);
        /* Stop if we're past our limit and we have found *something*.
         *
         * NB that this is a zero-sum game; we're increasing our cache size
         * by increasing our 'debt'.  Since we hold the p2m lock,
         * (entry_count - count) must remain the same. */
        if ( !page_list_empty(&p2md->pod.super) &&  i < limit )
            break;
    }

    p2md->pod.reclaim_super = i ? i - SUPERPAGE_PAGES : 0;

}

#define POD_SWEEP_STRIDE  16
static void
p2m_pod_emergency_sweep(struct domain *d)
{
    struct p2m_domain *p2md = d->arch.p2m;
    unsigned long gfns[POD_SWEEP_STRIDE];
    unsigned long i, j=0, start, limit;
    p2m_type_t t;


    if ( p2md->pod.reclaim_single == 0 )
        p2md->pod.reclaim_single = p2md->pod.max_guest;

    start = p2md->pod.reclaim_single;
    limit = (start > POD_SWEEP_LIMIT) ? (start - POD_SWEEP_LIMIT) : 0;

    /* FIXME: Figure out how to avoid superpages */
    for ( i=p2md->pod.reclaim_single ; i > 0 ; i-- )
    {
        gfn_to_mfn_query(d, i, &t );
        if ( p2m_is_ram(t) )
        {
            gfns[j] = i;
            j++;
            BUG_ON(j > POD_SWEEP_STRIDE);
            if ( j == POD_SWEEP_STRIDE )
            {
                p2m_pod_zero_check(d, gfns, j);
                j = 0;
            }
        }
        /* Stop if we're past our limit and we have found *something*.
         *
         * NB that this is a zero-sum game; we're increasing our cache size
         * by re-increasing our 'debt'.  Since we hold the p2m lock,
         * (entry_count - count) must remain the same. */
        if ( p2md->pod.count > 0 && i < limit )
            break;
    }

    if ( j )
        p2m_pod_zero_check(d, gfns, j);

    p2md->pod.reclaim_single = i ? i - 1 : i;

}

int
p2m_pod_demand_populate(struct domain *d, unsigned long gfn,
                        unsigned int order,
                        p2m_query_t q)
{
    struct page_info *p = NULL; /* Compiler warnings */
    unsigned long gfn_aligned;
    mfn_t mfn;
    struct p2m_domain *p2md = d->arch.p2m;
    int i;

    ASSERT(p2m_locked_by_me(d->arch.p2m));

    /* This check is done with the p2m lock held.  This will make sure that
     * even if d->is_dying changes under our feet, p2m_pod_empty_cache() 
     * won't start until we're done. */
    if ( unlikely(d->is_dying) )
        goto out_fail;

    /* If we're low, start a sweep */
    if ( order == 9 && page_list_empty(&p2md->pod.super) )
        p2m_pod_emergency_sweep_super(d);

    if ( page_list_empty(&p2md->pod.single) &&
         ( ( order == 0 )
           || (order == 9 && page_list_empty(&p2md->pod.super) ) ) )
        p2m_pod_emergency_sweep(d);

    /* Keep track of the highest gfn demand-populated by a guest fault */
    if ( q == p2m_guest && gfn > p2md->pod.max_guest )
        p2md->pod.max_guest = gfn;

    spin_lock(&d->page_alloc_lock);

    if ( p2md->pod.count == 0 )
        goto out_of_memory;

    /* Get a page f/ the cache.  A NULL return value indicates that the
     * 2-meg range should be marked singleton PoD, and retried */
    if ( (p = p2m_pod_cache_get(d, order)) == NULL )
        goto remap_and_retry;

    mfn = page_to_mfn(p);

    BUG_ON((mfn_x(mfn) & ((1 << order)-1)) != 0);

    spin_unlock(&d->page_alloc_lock);

    gfn_aligned = (gfn >> order) << order;

    set_p2m_entry(d, gfn_aligned, mfn, order, p2m_ram_rw);

    for( i = 0 ; i < (1UL << order) ; i++ )
        set_gpfn_from_mfn(mfn_x(mfn) + i, gfn_aligned + i);
    
    p2md->pod.entry_count -= (1 << order); /* Lock: p2m */
    BUG_ON(p2md->pod.entry_count < 0);

    return 0;
out_of_memory:
    spin_unlock(&d->page_alloc_lock);

    printk("%s: Out of populate-on-demand memory! tot_pages %" PRIu32 " pod_entries %" PRIi32 "\n",
           __func__, d->tot_pages, p2md->pod.entry_count);
    domain_crash(d);
out_fail:
    return -1;
remap_and_retry:
    BUG_ON(order != 9);
    spin_unlock(&d->page_alloc_lock);

    /* Remap this 2-meg region in singleton chunks */
    gfn_aligned = (gfn>>order)<<order;
    for(i=0; i<(1<<order); i++)
        set_p2m_entry(d, gfn_aligned+i, _mfn(POPULATE_ON_DEMAND_MFN), 0,
                      p2m_populate_on_demand);

    return 0;
}

/* Non-ept "lock-and-check" wrapper */
static int p2m_pod_check_and_populate(struct domain *d, unsigned long gfn,
                                      l1_pgentry_t *p2m_entry, int order,
                                      p2m_query_t q)
{
    /* Only take the lock if we don't already have it.  Otherwise it
     * wouldn't be safe to do p2m lookups with the p2m lock held */
    int do_locking = !p2m_locked_by_me(d->arch.p2m);
    int r;

    if ( do_locking )
        p2m_lock(d->arch.p2m);

    audit_p2m(d);

    /* Check to make sure this is still PoD */
    if ( p2m_flags_to_type(l1e_get_flags(*p2m_entry)) != p2m_populate_on_demand )
    {
        if ( do_locking )
            p2m_unlock(d->arch.p2m);
        return 0;
    }

    r = p2m_pod_demand_populate(d, gfn, order, q);

    audit_p2m(d);
    if ( do_locking )
        p2m_unlock(d->arch.p2m);

    return r;
}

// Returns 0 on error (out of memory)
static int
p2m_set_entry(struct domain *d, unsigned long gfn, mfn_t mfn, 
              unsigned int page_order, p2m_type_t p2mt)
{
    // XXX -- this might be able to be faster iff current->domain == d
    mfn_t table_mfn = pagetable_get_mfn(d->arch.phys_table);
    void *table =map_domain_page(mfn_x(table_mfn));
    unsigned long i, gfn_remainder = gfn;
    l1_pgentry_t *p2m_entry;
    l1_pgentry_t entry_content;
    l2_pgentry_t l2e_content;
    int rv=0;

#if CONFIG_PAGING_LEVELS >= 4
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L4_PAGETABLE_SHIFT - PAGE_SHIFT,
                         L4_PAGETABLE_ENTRIES, PGT_l3_page_table) )
        goto out;
#endif
    /*
     * When using PAE Xen, we only allow 33 bits of pseudo-physical
     * address in translated guests (i.e. 8 GBytes).  This restriction
     * comes from wanting to map the P2M table into the 16MB RO_MPT hole
     * in Xen's address space for translated PV guests.
     * When using AMD's NPT on PAE Xen, we are restricted to 4GB.
     */
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                         ((CONFIG_PAGING_LEVELS == 3)
                          ? (d->arch.hvm_domain.hap_enabled ? 4 : 8)
                          : L3_PAGETABLE_ENTRIES),
                         PGT_l2_page_table) )
        goto out;

    if ( page_order == 0 )
    {
        if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                             L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                             L2_PAGETABLE_ENTRIES, PGT_l1_page_table) )
            goto out;

        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   0, L1_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        
        if ( mfn_valid(mfn) || (p2mt == p2m_mmio_direct) )
            entry_content = l1e_from_pfn(mfn_x(mfn), p2m_type_to_flags(p2mt));
        else
            entry_content = l1e_empty();
        
        /* level 1 entry */
        paging_write_p2m_entry(d, gfn, p2m_entry, table_mfn, entry_content, 1);
    }
    else 
    {
        p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                                   L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                                   L2_PAGETABLE_ENTRIES);
        ASSERT(p2m_entry);
        
        /* FIXME: Deal with 4k replaced by 2meg pages */
        if ( (l1e_get_flags(*p2m_entry) & _PAGE_PRESENT) &&
             !(l1e_get_flags(*p2m_entry) & _PAGE_PSE) )
        {
            P2M_ERROR("configure P2M table 4KB L2 entry with large page\n");
            domain_crash(d);
            goto out;
        }
        
        if ( mfn_valid(mfn) || p2m_is_magic(p2mt) )
            l2e_content = l2e_from_pfn(mfn_x(mfn),
                                       p2m_type_to_flags(p2mt) | _PAGE_PSE);
        else
            l2e_content = l2e_empty();
        
        entry_content.l1 = l2e_content.l2;
        paging_write_p2m_entry(d, gfn, p2m_entry, table_mfn, entry_content, 2);
    }

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( mfn_valid(mfn) 
         && (gfn + (1UL << page_order) - 1 > d->arch.p2m->max_mapped_pfn) )
        d->arch.p2m->max_mapped_pfn = gfn + (1UL << page_order) - 1;

    if ( iommu_enabled && need_iommu(d) )
    {
        if ( p2mt == p2m_ram_rw )
            for ( i = 0; i < (1UL << page_order); i++ )
                iommu_map_page(d, gfn+i, mfn_x(mfn)+i );
        else
            for ( int i = 0; i < (1UL << page_order); i++ )
                iommu_unmap_page(d, gfn+i);
    }

    /* Success */
    rv = 1;

 out:
    unmap_domain_page(table);
    return rv;
}

static mfn_t
p2m_gfn_to_mfn(struct domain *d, unsigned long gfn, p2m_type_t *t,
               p2m_query_t q)
{
    mfn_t mfn;
    paddr_t addr = ((paddr_t)gfn) << PAGE_SHIFT;
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;

    ASSERT(paging_mode_translate(d));

    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */
    *t = p2m_mmio_dm;

    mfn = pagetable_get_mfn(d->arch.phys_table);

    if ( gfn > d->arch.p2m->max_mapped_pfn )
        /* This pfn is higher than the highest the p2m map currently holds */
        return _mfn(INVALID_MFN);

#if CONFIG_PAGING_LEVELS >= 4
    {
        l4_pgentry_t *l4e = map_domain_page(mfn_x(mfn));
        l4e += l4_table_offset(addr);
        if ( (l4e_get_flags(*l4e) & _PAGE_PRESENT) == 0 )
        {
            unmap_domain_page(l4e);
            return _mfn(INVALID_MFN);
        }
        mfn = _mfn(l4e_get_pfn(*l4e));
        unmap_domain_page(l4e);
    }
#endif
    {
        l3_pgentry_t *l3e = map_domain_page(mfn_x(mfn));
#if CONFIG_PAGING_LEVELS == 3
        /* On PAE hosts the p2m has eight l3 entries, not four (see
         * shadow_set_p2m_entry()) so we can't use l3_table_offset.
         * Instead, just count the number of l3es from zero.  It's safe
         * to do this because we already checked that the gfn is within
         * the bounds of the p2m. */
        l3e += (addr >> L3_PAGETABLE_SHIFT);
#else
        l3e += l3_table_offset(addr);
#endif
        if ( (l3e_get_flags(*l3e) & _PAGE_PRESENT) == 0 )
        {
            unmap_domain_page(l3e);
            return _mfn(INVALID_MFN);
        }
        mfn = _mfn(l3e_get_pfn(*l3e));
        unmap_domain_page(l3e);
    }

    l2e = map_domain_page(mfn_x(mfn));
    l2e += l2_table_offset(addr);

pod_retry_l2:
    if ( (l2e_get_flags(*l2e) & _PAGE_PRESENT) == 0 )
    {
        /* PoD: Try to populate a 2-meg chunk */
        if ( p2m_flags_to_type(l2e_get_flags(*l2e)) == p2m_populate_on_demand )
        {
            if ( q != p2m_query ) {
                if ( !p2m_pod_check_and_populate(d, gfn,
                                                       (l1_pgentry_t *)l2e, 9, q) )
                    goto pod_retry_l2;
            } else
                *t = p2m_populate_on_demand;
        }
    
        unmap_domain_page(l2e);
        return _mfn(INVALID_MFN);
    }
    else if ( (l2e_get_flags(*l2e) & _PAGE_PSE) )
    {
        mfn = _mfn(l2e_get_pfn(*l2e) + l1_table_offset(addr));
        *t = p2m_flags_to_type(l2e_get_flags(*l2e));
        unmap_domain_page(l2e);
        
        ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t));
        return (p2m_is_valid(*t)) ? mfn : _mfn(INVALID_MFN);
    }

    mfn = _mfn(l2e_get_pfn(*l2e));
    unmap_domain_page(l2e);

    l1e = map_domain_page(mfn_x(mfn));
    l1e += l1_table_offset(addr);
pod_retry_l1:
    if ( (l1e_get_flags(*l1e) & _PAGE_PRESENT) == 0 )
    {
        /* PoD: Try to populate */
        if ( p2m_flags_to_type(l1e_get_flags(*l1e)) == p2m_populate_on_demand )
        {
            if ( q != p2m_query ) {
                if ( !p2m_pod_check_and_populate(d, gfn,
                                                       (l1_pgentry_t *)l1e, 0, q) )
                    goto pod_retry_l1;
            } else
                *t = p2m_populate_on_demand;
        }
    
        unmap_domain_page(l1e);
        return _mfn(INVALID_MFN);
    }
    mfn = _mfn(l1e_get_pfn(*l1e));
    *t = p2m_flags_to_type(l1e_get_flags(*l1e));
    unmap_domain_page(l1e);

    ASSERT(mfn_valid(mfn) || !p2m_is_ram(*t));
    return (p2m_is_valid(*t) || p2m_is_grant(*t)) ? mfn : _mfn(INVALID_MFN);
}

/* Read the current domain's p2m table (through the linear mapping). */
static mfn_t p2m_gfn_to_mfn_current(unsigned long gfn, p2m_type_t *t,
                                    p2m_query_t q)
{
    mfn_t mfn = _mfn(INVALID_MFN);
    p2m_type_t p2mt = p2m_mmio_dm;
    paddr_t addr = ((paddr_t)gfn) << PAGE_SHIFT;
    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */

    if ( gfn <= current->domain->arch.p2m->max_mapped_pfn )
    {
        l1_pgentry_t l1e = l1e_empty(), *p2m_entry;
        l2_pgentry_t l2e = l2e_empty();
        int ret;

        ASSERT(gfn < (RO_MPT_VIRT_END - RO_MPT_VIRT_START) 
               / sizeof(l1_pgentry_t));

        /*
         * Read & process L2
         */
        p2m_entry = &__linear_l1_table[l1_linear_offset(RO_MPT_VIRT_START)
                                       + l2_linear_offset(addr)];

    pod_retry_l2:
        ret = __copy_from_user(&l2e,
                               p2m_entry,
                               sizeof(l2e));
        if ( ret != 0
             || !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
        {
            if( (l2e_get_flags(l2e) & _PAGE_PSE)
                && ( p2m_flags_to_type(l2e_get_flags(l2e))
                     == p2m_populate_on_demand ) )
            {
                /* The read has succeeded, so we know that the mapping
                 * exits at this point.  */
                if ( q != p2m_query )
                {
                    if ( !p2m_pod_check_and_populate(current->domain, gfn,
                                                            p2m_entry, 9, q) )
                        goto pod_retry_l2;

                    /* Allocate failed. */
                    p2mt = p2m_invalid;
                    printk("%s: Allocate failed!\n", __func__);
                    goto out;
                }
                else
                {
                    p2mt = p2m_populate_on_demand;
                    goto out;
                }
            }

            goto pod_retry_l1;
        }
        
        if (l2e_get_flags(l2e) & _PAGE_PSE)
        {
            p2mt = p2m_flags_to_type(l2e_get_flags(l2e));
            ASSERT(l2e_get_pfn(l2e) != INVALID_MFN || !p2m_is_ram(p2mt));

            if ( p2m_is_valid(p2mt) )
                mfn = _mfn(l2e_get_pfn(l2e) + l1_table_offset(addr));
            else
                p2mt = p2m_mmio_dm;

            goto out;
        }

        /*
         * Read and process L1
         */

        /* Need to __copy_from_user because the p2m is sparse and this
         * part might not exist */
    pod_retry_l1:
        p2m_entry = &phys_to_machine_mapping[gfn];

        ret = __copy_from_user(&l1e,
                               p2m_entry,
                               sizeof(l1e));
            
        if ( ret == 0 ) {
            p2mt = p2m_flags_to_type(l1e_get_flags(l1e));
            ASSERT(l1e_get_pfn(l1e) != INVALID_MFN || !p2m_is_ram(p2mt));

            if ( p2m_flags_to_type(l1e_get_flags(l1e))
                 == p2m_populate_on_demand )
            {
                /* The read has succeeded, so we know that the mapping
                 * exits at this point.  */
                if ( q != p2m_query )
                {
                    if ( !p2m_pod_check_and_populate(current->domain, gfn,
                                                            (l1_pgentry_t *)p2m_entry, 0, q) )
                        goto pod_retry_l1;

                    /* Allocate failed. */
                    p2mt = p2m_invalid;
                    goto out;
                }
                else
                {
                    p2mt = p2m_populate_on_demand;
                    goto out;
                }
            }

            if ( p2m_is_valid(p2mt) || p2m_is_grant(p2mt) )
                mfn = _mfn(l1e_get_pfn(l1e));
            else 
                /* XXX see above */
                p2mt = p2m_mmio_dm;
        }
    }
out:
    *t = p2mt;
    return mfn;
}

/* Init the datastructures for later use by the p2m code */
int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m;

    p2m = xmalloc(struct p2m_domain);
    if ( p2m == NULL )
        return -ENOMEM;

    d->arch.p2m = p2m;

    memset(p2m, 0, sizeof(*p2m));
    p2m_lock_init(p2m);
    INIT_PAGE_LIST_HEAD(&p2m->pages);
    INIT_PAGE_LIST_HEAD(&p2m->pod.super);
    INIT_PAGE_LIST_HEAD(&p2m->pod.single);

    p2m->set_entry = p2m_set_entry;
    p2m->get_entry = p2m_gfn_to_mfn;
    p2m->get_entry_current = p2m_gfn_to_mfn_current;
    p2m->change_entry_type_global = p2m_change_type_global;

    if ( is_hvm_domain(d) && d->arch.hvm_domain.hap_enabled &&
         (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) )
        ept_p2m_init(d);

    return 0;
}

void p2m_change_entry_type_global(struct domain *d,
                                  p2m_type_t ot, p2m_type_t nt)
{
    struct p2m_domain *p2m = d->arch.p2m;

    p2m_lock(p2m);
    p2m->change_entry_type_global(d, ot, nt);
    p2m_unlock(p2m);
}

static
int set_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn, 
                    unsigned int page_order, p2m_type_t p2mt)
{
    unsigned long todo = 1ul << page_order;
    unsigned int order;
    int rc = 1;

    while ( todo )
    {
        if ( is_hvm_domain(d) && d->arch.hvm_domain.hap_enabled )
            order = (((gfn | mfn_x(mfn) | todo) & (SUPERPAGE_PAGES - 1)) == 0) ?
                9 : 0;
        else
            order = 0;
        if ( !d->arch.p2m->set_entry(d, gfn, mfn, order, p2mt) )
            rc = 0;
        gfn += 1ul << order;
        if ( mfn_x(mfn) != INVALID_MFN )
            mfn = _mfn(mfn_x(mfn) + (1ul << order));
        todo -= 1ul << order;
    }

    return rc;
}

// Allocate a new p2m table for a domain.
//
// The structure of the p2m table is that of a pagetable for xen (i.e. it is
// controlled by CONFIG_PAGING_LEVELS).
//
// The alloc_page and free_page functions will be used to get memory to
// build the p2m, and to release it again at the end of day.
//
// Returns 0 for success or -errno.
//
int p2m_alloc_table(struct domain *d,
                    struct page_info * (*alloc_page)(struct domain *d),
                    void (*free_page)(struct domain *d, struct page_info *pg))

{
    mfn_t mfn = _mfn(INVALID_MFN);
    struct page_info *page, *p2m_top;
    unsigned int page_count = 0;
    unsigned long gfn = -1UL;
    struct p2m_domain *p2m = d->arch.p2m;

    p2m_lock(p2m);

    if ( pagetable_get_pfn(d->arch.phys_table) != 0 )
    {
        P2M_ERROR("p2m already allocated for this domain\n");
        p2m_unlock(p2m);
        return -EINVAL;
    }

    P2M_PRINTK("allocating p2m table\n");

    p2m->alloc_page = alloc_page;
    p2m->free_page = free_page;

    p2m_top = p2m->alloc_page(d);
    if ( p2m_top == NULL )
    {
        p2m_unlock(p2m);
        return -ENOMEM;
    }
    page_list_add_tail(p2m_top, &p2m->pages);

    p2m_top->count_info = 1;
    p2m_top->u.inuse.type_info =
#if CONFIG_PAGING_LEVELS == 4
        PGT_l4_page_table
#else
        PGT_l3_page_table
#endif
        | 1 | PGT_validated;

    d->arch.phys_table = pagetable_from_mfn(page_to_mfn(p2m_top));

    P2M_PRINTK("populating p2m table\n");

    /* Initialise physmap tables for slot zero. Other code assumes this. */
    if ( !set_p2m_entry(d, 0, _mfn(INVALID_MFN), 0,
                        p2m_invalid) )
        goto error;

    /* Copy all existing mappings from the page list and m2p */
    page_list_for_each(page, &d->page_list)
    {
        mfn = page_to_mfn(page);
        gfn = get_gpfn_from_mfn(mfn_x(mfn));
        page_count++;
        if (
#ifdef __x86_64__
            (gfn != 0x5555555555555555L)
#else
            (gfn != 0x55555555L)
#endif
             && gfn != INVALID_M2P_ENTRY
            && !set_p2m_entry(d, gfn, mfn, 0, p2m_ram_rw) )
            goto error;
    }

    P2M_PRINTK("p2m table initialised (%u pages)\n", page_count);
    p2m_unlock(p2m);
    return 0;

 error:
    P2M_PRINTK("failed to initialize p2m table, gfn=%05lx, mfn=%"
               PRI_mfn "\n", gfn, mfn_x(mfn));
    p2m_unlock(p2m);
    return -ENOMEM;
}

void p2m_teardown(struct domain *d)
/* Return all the p2m pages to Xen.
 * We know we don't have any extra mappings to these pages */
{
    struct page_info *pg;
    struct p2m_domain *p2m = d->arch.p2m;

    p2m_lock(p2m);
    d->arch.phys_table = pagetable_null();

    while ( (pg = page_list_remove_head(&p2m->pages)) )
        p2m->free_page(d, pg);
    p2m_unlock(p2m);
}

void p2m_final_teardown(struct domain *d)
{
    xfree(d->arch.p2m);
    d->arch.p2m = NULL;
}

#if P2M_AUDIT
static void audit_p2m(struct domain *d)
{
    struct page_info *page;
    struct domain *od;
    unsigned long mfn, gfn, m2pfn, lp2mfn = 0;
    int entry_count = 0;
    mfn_t p2mfn;
    unsigned long orphans_d = 0, orphans_i = 0, mpbad = 0, pmbad = 0;
    int test_linear;
    p2m_type_t type;

    if ( !paging_mode_translate(d) )
        return;

    //P2M_PRINTK("p2m audit starts\n");

    test_linear = ( (d == current->domain)
                    && !pagetable_is_null(current->arch.monitor_table) );
    if ( test_linear )
        flush_tlb_local();

    spin_lock(&d->page_alloc_lock);

    /* Audit part one: walk the domain's page allocation list, checking
     * the m2p entries. */
    page_list_for_each ( page, &d->page_list )
    {
        mfn = mfn_x(page_to_mfn(page));

        // P2M_PRINTK("auditing guest page, mfn=%#lx\n", mfn);

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
            orphans_i++;
            //P2M_PRINTK("orphaned guest page: mfn=%#lx has invalid gfn\n",
            //               mfn);
            continue;
        }

        if ( gfn == 0x55555555 )
        {
            orphans_d++;
            //P2M_PRINTK("orphaned guest page: mfn=%#lx has debug gfn\n",
            //               mfn);
            continue;
        }

        p2mfn = gfn_to_mfn_type_foreign(d, gfn, &type, p2m_query);
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

        if ( test_linear && (gfn <= d->arch.p2m->max_mapped_pfn) )
        {
            lp2mfn = mfn_x(gfn_to_mfn_query(d, gfn, &type));
            if ( lp2mfn != mfn_x(p2mfn) )
            {
                P2M_PRINTK("linear mismatch gfn %#lx -> mfn %#lx "
                           "(!= mfn %#lx)\n", gfn, lp2mfn, mfn_x(p2mfn));
            }
        }

        // P2M_PRINTK("OK: mfn=%#lx, gfn=%#lx, p2mfn=%#lx, lp2mfn=%#lx\n",
        //                mfn, gfn, p2mfn, lp2mfn);
    }

    spin_unlock(&d->page_alloc_lock);

    /* Audit part two: walk the domain's p2m table, checking the entries. */
    if ( pagetable_get_pfn(d->arch.phys_table) != 0 )
    {
        l2_pgentry_t *l2e;
        l1_pgentry_t *l1e;
        int i1, i2;

#if CONFIG_PAGING_LEVELS == 4
        l4_pgentry_t *l4e;
        l3_pgentry_t *l3e;
        int i3, i4;
        l4e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#else /* CONFIG_PAGING_LEVELS == 3 */
        l3_pgentry_t *l3e;
        int i3;
        l3e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#endif

        gfn = 0;
#if CONFIG_PAGING_LEVELS >= 4
        for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
        {
            if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
            {
                gfn += 1 << (L4_PAGETABLE_SHIFT - PAGE_SHIFT);
                continue;
            }
            l3e = map_domain_page(mfn_x(_mfn(l4e_get_pfn(l4e[i4]))));
#endif
            for ( i3 = 0;
                  i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8);
                  i3++ )
            {
                if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
                {
                    gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                    continue;
                }
                l2e = map_domain_page(mfn_x(_mfn(l3e_get_pfn(l3e[i3]))));
                for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
                {
                    if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                    {
                        if ( (l2e_get_flags(l2e[i2]) & _PAGE_PSE)
                             && ( p2m_flags_to_type(l2e_get_flags(l2e[i2]))
                                  == p2m_populate_on_demand ) )
                            entry_count+=SUPERPAGE_PAGES;
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                    
                    /* check for super page */
                    if ( l2e_get_flags(l2e[i2]) & _PAGE_PSE )
                    {
                        mfn = l2e_get_pfn(l2e[i2]);
                        ASSERT(mfn_valid(_mfn(mfn)));
                        for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++)
                        {
                            m2pfn = get_gpfn_from_mfn(mfn+i1);
                            if ( m2pfn != (gfn + i1) )
                            {
                                pmbad++;
                                P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                           " -> gfn %#lx\n", gfn+i1, mfn+i1,
                                           m2pfn);
                                BUG();
                            }
                        }
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }

                    l1e = map_domain_page(mfn_x(_mfn(l2e_get_pfn(l2e[i2]))));

                    for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                    {
                        p2m_type_t type;

                        type = p2m_flags_to_type(l1e_get_flags(l1e[i1]));
                        if ( !(l1e_get_flags(l1e[i1]) & _PAGE_PRESENT) )
                        {
                            if ( type == p2m_populate_on_demand )
                                entry_count++;
                            continue;
                        }
                        mfn = l1e_get_pfn(l1e[i1]);
                        ASSERT(mfn_valid(_mfn(mfn)));
                        m2pfn = get_gpfn_from_mfn(mfn);
                        if ( m2pfn != gfn &&
                             type != p2m_mmio_direct &&
                             !p2m_is_grant(type) )
                        {
                            pmbad++;
                            printk("mismatch: gfn %#lx -> mfn %#lx"
                                   " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                       " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            BUG();
                        }
                    }
                    unmap_domain_page(l1e);
                }
                unmap_domain_page(l2e);
            }
#if CONFIG_PAGING_LEVELS >= 4
            unmap_domain_page(l3e);
        }
#endif

#if CONFIG_PAGING_LEVELS == 4
        unmap_domain_page(l4e);
#else /* CONFIG_PAGING_LEVELS == 3 */
        unmap_domain_page(l3e);
#endif

    }

    if ( entry_count != d->arch.p2m->pod.entry_count )
    {
        printk("%s: refcounted entry count %d, audit count %d!\n",
               __func__,
               d->arch.p2m->pod.entry_count,
               entry_count);
        BUG();
    }
        
    //P2M_PRINTK("p2m audit complete\n");
    //if ( orphans_i | orphans_d | mpbad | pmbad )
    //    P2M_PRINTK("p2m audit found %lu orphans (%lu inval %lu debug)\n",
    //                   orphans_i + orphans_d, orphans_i, orphans_d,
    if ( mpbad | pmbad )
        P2M_PRINTK("p2m audit found %lu odd p2m, %lu bad m2p entries\n",
                   pmbad, mpbad);
}
#endif /* P2M_AUDIT */



static void
p2m_remove_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                unsigned int page_order)
{
    unsigned long i;
    mfn_t mfn_return;
    p2m_type_t t;

    if ( !paging_mode_translate(d) )
    {
        if ( need_iommu(d) )
            for ( i = 0; i < (1 << page_order); i++ )
                iommu_unmap_page(d, mfn + i);
        return;
    }

    P2M_DEBUG("removing gfn=%#lx mfn=%#lx\n", gfn, mfn);

    for ( i = 0; i < (1UL << page_order); i++ )
    {
        mfn_return = d->arch.p2m->get_entry(d, gfn + i, &t, p2m_query);
        if ( !p2m_is_grant(t) )
            set_gpfn_from_mfn(mfn+i, INVALID_M2P_ENTRY);
        ASSERT( !p2m_is_valid(t) || mfn + i == mfn_x(mfn_return) );
    }
    set_p2m_entry(d, gfn, _mfn(INVALID_MFN), page_order, p2m_invalid);
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                          unsigned long mfn, unsigned int page_order)
{
    p2m_lock(d->arch.p2m);
    audit_p2m(d);
    p2m_remove_page(d, gfn, mfn, page_order);
    audit_p2m(d);
    p2m_unlock(d->arch.p2m);
}

#if CONFIG_PAGING_LEVELS == 3
static int gfn_check_limit(
    struct domain *d, unsigned long gfn, unsigned int order)
{
    /*
     * 32bit AMD nested paging does not support over 4GB guest due to 
     * hardware translation limit. This limitation is checked by comparing
     * gfn with 0xfffffUL.
     */
    if ( !paging_mode_hap(d) || ((gfn + (1ul << order)) <= 0x100000UL) ||
         (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) )
        return 0;

    if ( !test_and_set_bool(d->arch.hvm_domain.svm.npt_4gb_warning) )
        dprintk(XENLOG_WARNING, "Dom%d failed to populate memory beyond"
                " 4GB: specify 'hap=0' domain config option.\n",
                d->domain_id);

    return -EINVAL;
}
#else
#define gfn_check_limit(d, g, o) 0
#endif

int
guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                      unsigned int order)
{
    struct p2m_domain *p2md = d->arch.p2m;
    unsigned long i;
    p2m_type_t ot;
    mfn_t omfn;
    int pod_count = 0;
    int rc = 0;

    BUG_ON(!paging_mode_translate(d));

    rc = gfn_check_limit(d, gfn, order);
    if ( rc != 0 )
        return rc;

    p2m_lock(p2md);
    audit_p2m(d);

    P2M_DEBUG("mark pod gfn=%#lx\n", gfn);

    /* Make sure all gpfns are unused */
    for ( i = 0; i < (1UL << order); i++ )
    {
        omfn = gfn_to_mfn_query(d, gfn + i, &ot);
        if ( p2m_is_ram(ot) )
        {
            printk("%s: gfn_to_mfn returned type %d!\n",
                   __func__, ot);
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
    if ( !set_p2m_entry(d, gfn, _mfn(POPULATE_ON_DEMAND_MFN), order,
                        p2m_populate_on_demand) )
        rc = -EINVAL;
    else
    {
        p2md->pod.entry_count += 1 << order; /* Lock: p2m */
        p2md->pod.entry_count -= pod_count;
        BUG_ON(p2md->pod.entry_count < 0);
    }

    audit_p2m(d);
    p2m_unlock(p2md);

out:
    return rc;

}

int
guest_physmap_add_entry(struct domain *d, unsigned long gfn,
                        unsigned long mfn, unsigned int page_order, 
                        p2m_type_t t)
{
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
                if ( (rc = iommu_map_page(d, mfn + i, mfn + i)) != 0 )
                {
                    while ( i-- > 0 )
                        iommu_unmap_page(d, mfn + i);
                    return rc;
                }
        }
        return 0;
    }

    rc = gfn_check_limit(d, gfn, page_order);
    if ( rc != 0 )
        return rc;

    p2m_lock(d->arch.p2m);
    audit_p2m(d);

    P2M_DEBUG("adding gfn=%#lx mfn=%#lx\n", gfn, mfn);

    /* First, remove m->p mappings for existing p->m mappings */
    for ( i = 0; i < (1UL << page_order); i++ )
    {
        omfn = gfn_to_mfn_query(d, gfn + i, &ot);
        if ( p2m_is_grant(ot) )
        {
            /* Really shouldn't be unmapping grant maps this way */
            domain_crash(d);
            p2m_unlock(d->arch.p2m);
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
            /* If we get here, we know the local domain owns the page,
               so it can't have been grant mapped in. */
            BUG_ON( p2m_is_grant(ot) );
            if ( p2m_is_ram(ot) )
            {
                ASSERT(mfn_valid(omfn));
                P2M_DEBUG("old gfn=%#lx -> mfn %#lx\n",
                          ogfn , mfn_x(omfn));
                if ( mfn_x(omfn) == (mfn + i) )
                    p2m_remove_page(d, ogfn, mfn + i, 0);
            }
        }
    }

    /* Now, actually do the two-way mapping */
    if ( mfn_valid(_mfn(mfn)) ) 
    {
        if ( !set_p2m_entry(d, gfn, _mfn(mfn), page_order, t) )
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
        if ( !set_p2m_entry(d, gfn, _mfn(INVALID_MFN), page_order, 
                            p2m_invalid) )
            rc = -EINVAL;
        else
        {
            d->arch.p2m->pod.entry_count -= pod_count; /* Lock: p2m */
            BUG_ON(d->arch.p2m->pod.entry_count < 0);
        }
    }

    audit_p2m(d);
    p2m_unlock(d->arch.p2m);

    return rc;
}

/* Walk the whole p2m table, changing any entries of the old type
 * to the new type.  This is used in hardware-assisted paging to 
 * quickly enable or diable log-dirty tracking */
void p2m_change_type_global(struct domain *d, p2m_type_t ot, p2m_type_t nt)
{
    unsigned long mfn, gfn, flags;
    l1_pgentry_t l1e_content;
    l1_pgentry_t *l1e;
    l2_pgentry_t *l2e;
    mfn_t l1mfn, l2mfn;
    int i1, i2;
    l3_pgentry_t *l3e;
    int i3;
#if CONFIG_PAGING_LEVELS == 4
    l4_pgentry_t *l4e;
    int i4;
#endif /* CONFIG_PAGING_LEVELS == 4 */

    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));

    if ( !paging_mode_translate(d) )
        return;

    if ( pagetable_get_pfn(d->arch.phys_table) == 0 )
        return;

    ASSERT(p2m_locked_by_me(d->arch.p2m));

#if CONFIG_PAGING_LEVELS == 4
    l4e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#else /* CONFIG_PAGING_LEVELS == 3 */
    l3e = map_domain_page(mfn_x(pagetable_get_mfn(d->arch.phys_table)));
#endif

#if CONFIG_PAGING_LEVELS >= 4
    for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
    {
        if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
        {
            continue;
        }
        l3e = map_domain_page(l4e_get_pfn(l4e[i4]));
#endif
        for ( i3 = 0;
              i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8);
              i3++ )
        {
            if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
            {
                continue;
            }
            l2mfn = _mfn(l3e_get_pfn(l3e[i3]));
            l2e = map_domain_page(l3e_get_pfn(l3e[i3]));
            for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
            {
                if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                {
                    continue;
                }

                if ( (l2e_get_flags(l2e[i2]) & _PAGE_PSE) )
                {
                    flags = l2e_get_flags(l2e[i2]);
                    if ( p2m_flags_to_type(flags) != ot )
                        continue;
                    mfn = l2e_get_pfn(l2e[i2]);
                    gfn = get_gpfn_from_mfn(mfn);
                    flags = p2m_type_to_flags(nt);
                    l1e_content = l1e_from_pfn(mfn, flags | _PAGE_PSE);
                    paging_write_p2m_entry(d, gfn, (l1_pgentry_t *)&l2e[i2],
                                           l2mfn, l1e_content, 2);
                    continue;
                }

                l1mfn = _mfn(l2e_get_pfn(l2e[i2]));
                l1e = map_domain_page(mfn_x(l1mfn));

                for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                {
                    flags = l1e_get_flags(l1e[i1]);
                    if ( p2m_flags_to_type(flags) != ot )
                        continue;
                    mfn = l1e_get_pfn(l1e[i1]);
                    gfn = get_gpfn_from_mfn(mfn);
                    /* create a new 1le entry with the new type */
                    flags = p2m_type_to_flags(nt);
                    l1e_content = l1e_from_pfn(mfn, flags);
                    paging_write_p2m_entry(d, gfn, &l1e[i1],
                                           l1mfn, l1e_content, 1);
                }
                unmap_domain_page(l1e);
            }
            unmap_domain_page(l2e);
        }
#if CONFIG_PAGING_LEVELS >= 4
        unmap_domain_page(l3e);
    }
#endif

#if CONFIG_PAGING_LEVELS == 4
    unmap_domain_page(l4e);
#else /* CONFIG_PAGING_LEVELS == 3 */
    unmap_domain_page(l3e);
#endif

}

/* Modify the p2m type of a single gfn from ot to nt, returning the 
 * entry's previous type */
p2m_type_t p2m_change_type(struct domain *d, unsigned long gfn, 
                           p2m_type_t ot, p2m_type_t nt)
{
    p2m_type_t pt;
    mfn_t mfn;

    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));

    p2m_lock(d->arch.p2m);

    mfn = gfn_to_mfn(d, gfn, &pt);
    if ( pt == ot )
        set_p2m_entry(d, gfn, mfn, 0, nt);

    p2m_unlock(d->arch.p2m);

    return pt;
}

int
set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    int rc = 0;
    p2m_type_t ot;
    mfn_t omfn;

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
    p2m_lock(d->arch.p2m);
    rc = set_p2m_entry(d, gfn, mfn, 0, p2m_mmio_direct);
    p2m_unlock(d->arch.p2m);
    if ( 0 == rc )
        gdprintk(XENLOG_ERR,
            "set_mmio_p2m_entry: set_p2m_entry failed! mfn=%08lx\n",
            gmfn_to_mfn(d, gfn));
    return rc;
}

int
clear_mmio_p2m_entry(struct domain *d, unsigned long gfn)
{
    int rc = 0;
    unsigned long mfn;

    if ( !paging_mode_translate(d) )
        return 0;

    mfn = gmfn_to_mfn(d, gfn);
    if ( INVALID_MFN == mfn )
    {
        gdprintk(XENLOG_ERR,
            "clear_mmio_p2m_entry: gfn_to_mfn failed! gfn=%08lx\n", gfn);
        return 0;
    }
    p2m_lock(d->arch.p2m);
    rc = set_p2m_entry(d, gfn, _mfn(INVALID_MFN), 0, 0);
    p2m_unlock(d->arch.p2m);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
