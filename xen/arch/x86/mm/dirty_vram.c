/*
 * arch/x86/mm/dirty_vram.c: Bookkeep/query dirty VRAM pages
 * with support for multiple frame buffers.
 *
 * Copyright (c) 2012, Citrix Systems, Inc. (Robert Phillips)
 * Parts of this code are Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2007 XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */


#include <xen/types.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <asm/shadow.h>
#include <asm/dirty_vram.h>
#include <asm/hap.h>
#include <asm/config.h>
#include "mm-locks.h"

#define DEBUG_stop_tracking_all_vram          0
#define DEBUG_allocating_dirty_vram_range     0
#define DEBUG_high_water_mark_for_vram_ranges 0
#define DEBUG_freeing_dirty_vram_range        0
#define DEBUG_allocate_paddr_links_page       0
#define DEBUG_update_vram_mapping             0
#define DEBUG_alloc_paddr_inject_fault        0
#define DEBUG_link_limit_exceeded             0

/* Allocates domain's dirty_vram structure */
dv_dirty_vram_t *
dirty_vram_alloc(struct domain *d)
{
    dv_dirty_vram_t *dirty_vram;
    ASSERT( paging_locked_by_me(d) );
    dirty_vram = d->arch.hvm_domain.dirty_vram = xzalloc(dv_dirty_vram_t);
    if ( dirty_vram )
    {
        INIT_LIST_HEAD(&dirty_vram->range_head);
        INIT_LIST_HEAD(&dirty_vram->ext_head);
    }
    return dirty_vram;
}

/*
 * Returns domain's dirty_vram structure,
 * allocating it if necessary
 */
dv_dirty_vram_t *
dirty_vram_find_or_alloc(struct domain *d)
{
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    ASSERT( paging_locked_by_me(d) );
    if ( !dirty_vram )
        dirty_vram = dirty_vram_alloc(d);
    return dirty_vram;
}


/* Free domain's dirty_vram structure */
void dirty_vram_free(struct domain *d)
{
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    ASSERT( paging_locked_by_me(d) );
    if ( dirty_vram )
    {
        struct list_head *curr, *next;
        /* Free all the ranges */
        list_for_each_safe(curr, next, &dirty_vram->range_head)
        {
            dv_range_t *range = list_entry(curr, dv_range_t, range_link);
#if DEBUG_stop_tracking_all_vram
            gdprintk(XENLOG_DEBUG, "[%05lx:%05lx] stop tracking all vram\n",
                     range->begin_pfn, range->end_pfn);
#endif
            xfree(range->pl_tab);
            xfree(range);
        }
        /* Free all the extension pages */
        list_for_each_safe(curr, next, &dirty_vram->ext_head)
        {
            struct dv_paddr_link_ext *ext =
                container_of(
                    curr, struct dv_paddr_link_ext, ext_link);
            struct page_info *pg = __virt_to_page(ext);
            d->arch.paging.free_page(d, pg);
        }

        xfree(dirty_vram);
        d->arch.hvm_domain.dirty_vram = NULL;
    }
}

/* Returns dirty vram range containing gfn, NULL if none */
struct dv_range *
dirty_vram_range_find_gfn(struct domain *d,
                          unsigned long gfn)
{
    struct dv_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;
    ASSERT( paging_locked_by_me(d) );
    if ( dirty_vram )
    {
        struct list_head *curr;
        list_for_each(curr, &dirty_vram->range_head)
        {
            dv_range_t *range = list_entry(curr, dv_range_t, range_link);
            if ( gfn >= range->begin_pfn &&
                 gfn <  range->end_pfn )
                return range;
        }
    }
    return NULL;
}

/*
 * Returns pointer to dirty vram range matching [begin_pfn .. end_pfn ),
 * NULL if none.
 */
dv_range_t *
dirty_vram_range_find(struct domain *d,
                      unsigned long begin_pfn,
                      unsigned long nr)
{
    unsigned long end_pfn = begin_pfn + nr;
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    ASSERT( paging_locked_by_me(d) );
    if ( dirty_vram )
    {
        struct list_head *curr;
        list_for_each(curr, &dirty_vram->range_head)
        {
            dv_range_t *range = list_entry(curr, dv_range_t, range_link);
            if ( begin_pfn == range->begin_pfn &&
                 end_pfn   == range->end_pfn )
                return range;
        }
    }
    return NULL;
}

/* Allocate specified dirty_vram range */
static dv_range_t *
_dirty_vram_range_alloc(struct domain *d,
                        unsigned long begin_pfn,
                        unsigned long nr)
{
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    dv_range_t *range = NULL;
    unsigned long end_pfn = begin_pfn + nr;
    dv_pl_entry_t *pl_tab = NULL;
    int i;

    ASSERT( paging_locked_by_me(d) );
    ASSERT( dirty_vram != NULL );

#if DEBUG_allocating_dirty_vram_range
    gdprintk(XENLOG_DEBUG,
             "[%05lx:%05lx] Allocating dirty vram range hap:%d\n",
             begin_pfn, end_pfn,
             d->arch.hvm_domain.hap_enabled);
#endif

    range = xzalloc(dv_range_t);
    if ( range == NULL )
        goto err_out;

    INIT_LIST_HEAD(&range->range_link);

    range->begin_pfn = begin_pfn;
    range->end_pfn = end_pfn;

    if ( !hap_enabled(d) )
    {
        if ( (pl_tab = xzalloc_array(dv_pl_entry_t, nr)) == NULL )
            goto err_out;

        for ( i = 0; i != nr; i++ )
        {
            pl_tab[i].mapping.sl1ma = INVALID_PADDR;
        }
    }

    range->pl_tab = pl_tab;
    range->mappings_hwm = 1;

    list_add(&range->range_link, &dirty_vram->range_head);
    if ( ++dirty_vram->nr_ranges > dirty_vram->ranges_hwm )
    {
        dirty_vram->ranges_hwm = dirty_vram->nr_ranges;
#if DEBUG_high_water_mark_for_vram_ranges
        gdprintk(XENLOG_DEBUG,
                 "High water mark for number of vram ranges is now:%d\n",
                 dirty_vram->ranges_hwm);
#endif
    }
    return range;

 err_out:
    xfree(pl_tab);
    xfree(range);
    return NULL;
}


/* Frees specified dirty_vram range */
void dirty_vram_range_free(struct domain *d,
                           dv_range_t *range)
{
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    ASSERT( paging_locked_by_me(d) );
    if ( dirty_vram )
    {
        int i, nr = range->end_pfn - range->begin_pfn;

#if DEBUG_freeing_dirty_vram_range
        gdprintk(XENLOG_DEBUG,
                 "[%05lx:%05lx] Freeing dirty vram range\n",
                 range->begin_pfn, range->end_pfn);
#endif

        if ( range->pl_tab )
        {
            for ( i = 0; i != nr; i++ )
            {
                dv_paddr_link_t *plx;
                plx = range->pl_tab[i].mapping.pl_next;
                /* Does current FB page have multiple mappings? */
                if ( plx ) /* yes */
                {
                    /* Find the last element in singly-linked list */
                    while ( plx->pl_next != NULL )
                        plx = plx->pl_next;
                    
                    /* Prepend whole list to the free list */
                    plx->pl_next = dirty_vram->pl_free;
                    dirty_vram->pl_free = range->pl_tab[i].mapping.pl_next;
                }
            }
            xfree(range->pl_tab);
            range->pl_tab = NULL;
        }

        /* Remove range from the linked list, free it, and adjust count*/
        list_del(&range->range_link);
        xfree(range);
        dirty_vram->nr_ranges--;
    }
}

/*
 * dirty_vram_range_alloc()
 * This function ensures that the new range does not overlap any existing
 * ranges -- deleting them if necessary -- and then calls
 * _dirty_vram_range_alloc to actually allocate the new range.
 */
dv_range_t *
dirty_vram_range_alloc(struct domain *d,
                        unsigned long begin_pfn,
                        unsigned long nr)
{
    unsigned long end_pfn = begin_pfn + nr;
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    dv_range_t *range;
    struct list_head *curr, *next;

    ASSERT( paging_locked_by_me(d) );
    ASSERT( dirty_vram != NULL );

    /*
     * Ranges cannot overlap so
     * free any range that overlaps [ begin_pfn .. end_pfn )
     */
    list_for_each_safe(curr, next, &dirty_vram->range_head)
    {
        dv_range_t *rng = list_entry(curr, dv_range_t, range_link);
        if ( ( ( rng->begin_pfn <= begin_pfn ) &&
               ( begin_pfn <  rng->end_pfn   )
                 ) ||
             ( ( begin_pfn <= rng->begin_pfn ) &&
               ( rng->begin_pfn < end_pfn    )
                 ) )
        {
            /* Different tracking, tear the previous down. */
            dirty_vram_range_free(d, rng);
        }
    }

    range = _dirty_vram_range_alloc(d, begin_pfn, nr);
    if ( !range )
        goto out;

 out:
    return range;
}

/*
 * dirty_vram_range_find_or_alloc()
 * Find the range for [begin_pfn:begin_pfn+nr).
 * If it doesn't exists, create it.
 */
dv_range_t *
dirty_vram_range_find_or_alloc(struct domain *d,
                                unsigned long begin_pfn,
                                unsigned long nr)
{
    dv_range_t *range;
    ASSERT( paging_locked_by_me(d) );
    range = dirty_vram_range_find(d, begin_pfn, nr);
    if ( !range )
        range = dirty_vram_range_alloc(d, begin_pfn, nr);
    
    return range;
}



/* Allocate a dv_paddr_link struct */
static dv_paddr_link_t *
alloc_paddr_link(struct domain *d)
{
    dv_paddr_link_t * pl = NULL;
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    dv_paddr_link_ext_t *ext = NULL;
    

    ASSERT( paging_locked_by_me(d) );
    BUILD_BUG_ON(sizeof(dv_paddr_link_ext_t) > PAGE_SIZE);
    /* Is the list of free pl's empty? */
    if ( dirty_vram->pl_free == NULL ) /* yes */
    {
        /*
         * Allocate another page of pl's.
         * Link them all together and point the free list head at them
         */
        int i;
        struct page_info *pg = d->arch.paging.alloc_page(d);

        ext = map_domain_page(pg);
        if ( ext == NULL )
            goto out;

#if DEBUG_allocate_paddr_links_page
        gdprintk(XENLOG_DEBUG, "Allocated another page of paddr_links\n");
#endif
        list_add(&ext->ext_link, &dirty_vram->ext_head);

        /* initialize and link together the new pl entries */
        for ( i = 0; i != ARRAY_SIZE(ext->entries); i++ )
        {
            ext->entries[i].sl1ma = INVALID_PADDR;
            ext->entries[i].pl_next = &ext->entries[i+1];
        }
        ext->entries[ARRAY_SIZE(ext->entries) - 1].pl_next = NULL;
        dirty_vram->pl_free = &ext->entries[0];
    }
    pl = dirty_vram->pl_free;
    dirty_vram->pl_free = pl->pl_next;

    pl->sl1ma = INVALID_PADDR;
    pl->pl_next = NULL;
 out:
    if ( ext )
        unmap_domain_page(ext);
    
    return pl;
}


/*
 * Free a paddr_link struct.
 *
 * The caller has walked the singly-linked list of elements
 * that have, as their head, an element in a pl_tab cell.
 * The list walks has reached the element to be freed.
 * (Each element is a dv_paddr_link_t struct.)
 *
 * @pl points to the element to be freed.
 * @ppl points to its predecessor element's next member.
 *
 * After linking the precessor to the element's successor,
 * we can free @pl by prepending it to the list of free
 * elements.
 *
 * As a boundary case (which happens to be the common case),
 * @pl points to a cell in the pl_tab rather than to some
 * extension element danging from that cell.
 * We recognize this case because @ppl is NULL.
 * In that case we promote the first extension element by
 * copying it into the pl_tab cell and free it.
 */

dv_paddr_link_t *
free_paddr_link(struct domain *d,
                dv_paddr_link_t **ppl,
                dv_paddr_link_t *pl)
{
    dv_dirty_vram_t *dirty_vram = d->arch.hvm_domain.dirty_vram;
    dv_paddr_link_t *npl; /* next pl */

    ASSERT( paging_locked_by_me(d) );
    /* extension mapping? */
    if ( ppl ) /* yes. free it */
    {
        ASSERT(pl == (*ppl));
        (*ppl) = npl = pl->pl_next;
    }
    else  /* main table */
    {
        /*
         * move 2nd mapping to main table.
         * and free 2nd mapping
         */
        dv_paddr_link_t * spl;
        spl = pl->pl_next;
        if ( spl == NULL )
        {
            pl->sl1ma = INVALID_PADDR;
            return pl;
        }
        pl->sl1ma = spl->sl1ma;
        pl->pl_next = spl->pl_next;
        npl = pl; /* reprocess main table entry again */
        pl = spl;
    }
    pl->sl1ma = INVALID_PADDR;
    pl->pl_next = dirty_vram->pl_free;
    dirty_vram->pl_free = pl;
    return npl;
}


/*
 * dirty_vram_range_update()
 *
 * This is called whenever a level 1 page table entry is modified.
 * If the L1PTE is being cleared, the function removes any paddr_links
 * that refer to it.
 * If the L1PTE is being set to a frame buffer page, a paddr_link is
 * created for that page's entry in pl_tab.
 * Returns 1 iff entry found and set or cleared.
 */
int dirty_vram_range_update(struct domain *d,
                            unsigned long gfn,
                            paddr_t sl1ma,
                            int set)
{
    int effective = 0;
    dv_range_t *range;
    unsigned long i;
    dv_paddr_link_t *pl;
    dv_paddr_link_t **ppl;
    int len = 0;

    ASSERT(paging_locked_by_me(d));
    range = dirty_vram_range_find_gfn(d, gfn);
    if ( !range )
        return effective;

    
    i = gfn - range->begin_pfn;
    pl = &range->pl_tab[ i ].mapping;
    ppl = NULL;

    /*
     * find matching entry (pl), if any, and its predecessor
     * in linked list (ppl)
     */
    while ( pl != NULL )
    {
        if ( pl->sl1ma == sl1ma || pl->sl1ma == INVALID_PADDR )
            break;
            
        ppl = &pl->pl_next;
        pl = *ppl;
        len++;
    }

    if ( set )
    {
        /* Did we find sl1ma in either the main table or the linked list? */
        if ( pl == NULL ) /* no, so we'll need to alloc a link */
        {
            ASSERT(ppl != NULL);
            
#if DEBUG_alloc_paddr_inject_fault
            {
                static int counter;
                
                /* Test stuck_dirty logic for some cases */
                if ( (++counter) % 4 == 0 )
                {
                    /* Simply mark the frame buffer page as always dirty */
                    range->pl_tab[ i ].stuck_dirty = 1;
                    gdprintk(XENLOG_DEBUG,
                             "[%lx] inject stuck dirty fault\n",
                             gfn );
                    goto out;
                }
            }
#endif
            /*
             * Have we reached the limit of mappings we're willing
             * to bookkeep?
             */
            if ( len > DV_ADDR_LINK_LIST_LIMIT ) /* yes */
            {
#if DEBUG_link_limit_exceeded
                if ( !range->pl_tab[ i ].stuck_dirty )
                    gdprintk(XENLOG_DEBUG,
                             "[%lx] link limit exceeded\n",
                             gfn );
#endif            
                /* Simply mark the frame buffer page as always dirty */
                range->pl_tab[ i ].stuck_dirty = 1;
                goto out;
            }

            /* alloc link and append it to list */
            (*ppl) = pl = alloc_paddr_link(d);
            /* Were we able to allocate a link? */
            if ( pl == NULL ) /* no */
            {
                /* Simply mark the frame buffer page as always dirty */
                range->pl_tab[ i ].stuck_dirty = 1;
                
                gdprintk(XENLOG_DEBUG,
                         "[%lx] alloc failure\n",
                         gfn );
                
                goto out;
            }
        }
        if ( pl->sl1ma != sl1ma )
        {
            ASSERT(pl->sl1ma == INVALID_PADDR);
            pl->sl1ma = sl1ma;
            range->nr_mappings++;
        }
        effective = 1;
        if ( len > range->mappings_hwm )
        {
            range->mappings_hwm = len;
#if DEBUG_update_vram_mapping
            gdprintk(XENLOG_DEBUG,
                     "[%lx] set      sl1ma:%lx hwm:%d mappings:%d "
                     "freepages:%d\n",
                     gfn, sl1ma,
                     range->mappings_hwm,
                     range->nr_mappings,
                     d->arch.paging.shadow.free_pages);
#endif
        }
    }
    else /* clear */
    {
        if ( pl && pl->sl1ma == sl1ma )
        {
#if DEBUG_update_vram_mapping
            gdprintk(XENLOG_DEBUG,
                     "[%lx] clear    sl1ma:%lx mappings:%d\n",
                     gfn, sl1ma,
                     range->nr_mappings - 1);
#endif
            free_paddr_link(d, ppl, pl);
            --range->nr_mappings;
            effective = 1;
        }
    }
 out:
    return effective;
}


/*
 * shadow_scan_dirty_flags()
 * This produces a dirty bitmap for the range by examining every
 * L1PTE referenced by some dv_paddr_link in the range's pl_tab table.
 * It tests and clears each such L1PTE's dirty flag.
 */
static int shadow_scan_dirty_flags(struct domain *d,
                                   dv_range_t *range,
                                   uint8_t *dirty_bitmap)
{
    int flush_tlb = 0;
    unsigned long i;
    unsigned long nr = range->end_pfn - range->begin_pfn;
    l1_pgentry_t *sl1e = NULL;

    ASSERT( paging_locked_by_me(d) );
    /* Iterate over VRAM to track dirty bits. */
    for ( i = 0; i < nr; i++ )
    {
        int dirty = 0, len = 1;
        dv_paddr_link_t *pl;
        /* Does the frame buffer have an incomplete set of mappings? */
        if ( unlikely(range->pl_tab[i].stuck_dirty) ) /* yes */
            dirty = 1;
        else /* The frame buffer's set of mappings is complete.  Scan it. */
            for ( pl = &range->pl_tab[i].mapping;
                  pl;
                  pl = pl->pl_next, len++ )
            {
                paddr_t sl1ma = pl->sl1ma;
                if ( sl1ma == INVALID_PADDR ) /* FB page is unmapped */
                    continue;

                if ( sl1e ) /* cleanup from previous iteration */
                    unmap_domain_page(sl1e);

                sl1e = map_domain_page(sl1ma >> PAGE_SHIFT);
                if ( l1e_get_flags(*sl1e) & _PAGE_DIRTY )
                {
                    dirty = 1;
                    /* Clear dirty so we can detect if page gets re-dirtied.
                     * Note: this is atomic, so we may clear a
                     * _PAGE_ACCESSED set by another processor.
                     */
                    l1e_remove_flags(*sl1e, _PAGE_DIRTY);
                    flush_tlb = 1;
                }
            } /* for */
        
        if ( dirty )
            dirty_bitmap[i >> 3] |= (1 << (i & 7));

    }
    
    if ( sl1e )
        unmap_domain_page(sl1e);

    return flush_tlb;
}


/*
 * shadow_track_dirty_vram()
 * This is the API called by the guest to determine which pages in the range
 * from [begin_pfn:begin_pfn+nr) have been dirtied since the last call.
 * It creates the domain's dv_dirty_vram on demand.
 * It creates ranges on demand when some [begin_pfn:nr) is first encountered.
 * To collect the dirty bitmask it calls shadow_scan_dirty_flags().
 * It copies the dirty bitmask into guest storage.
 */
int shadow_track_dirty_vram(struct domain *d,
                            unsigned long begin_pfn,
                            unsigned long nr,
                            XEN_GUEST_HANDLE_64(uint8) guest_dirty_bitmap)
{
    int rc = 0;
    unsigned long end_pfn = begin_pfn + nr;
    int flush_tlb = 0;
    dv_range_t *range;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    uint8_t *dirty_bitmap = NULL;

    /*
     * This range test is tricky.
     *
     * The range [begin_pfn..end_pfn) is an open interval, so end_pfn
     * is a pfn beyond the end of the range.
     *
     * p2m->max_mapped_pfn is a valid PFN so p2m->max_mapped_pfn + 1 is an
     * invalid PFN.
     *
     * If end_pfn is beyond *that* then the range is invalid.
     */
    if ( end_pfn < begin_pfn
         || begin_pfn > p2m->max_mapped_pfn
         || end_pfn > p2m->max_mapped_pfn + 1 )
        return -EINVAL;

    paging_lock(d);

    if ( !nr )
    {
        dirty_vram_free(d);
        goto out;
    }

    if ( guest_handle_is_null(guest_dirty_bitmap) )
        goto out;

    if ( !dirty_vram_find_or_alloc(d) )
    {
        rc = -ENOMEM;
        goto out;
    }

    range = dirty_vram_range_find(d, begin_pfn, nr);
    if ( !range )
    {
        range = dirty_vram_range_alloc(d, begin_pfn, nr);
        if ( range )
            sh_find_all_vram_mappings(d->vcpu[0], range);
    }
    if ( range )
    {
        int size = ( nr + BITS_PER_BYTE - 1 ) / BITS_PER_BYTE;
        
        rc = -ENOMEM;
        dirty_bitmap = xzalloc_bytes( size );
        if ( !dirty_bitmap )
            goto out;

        flush_tlb |= shadow_scan_dirty_flags(d, range, dirty_bitmap);

        rc = -EFAULT;
        if ( copy_to_guest(guest_dirty_bitmap,
                           dirty_bitmap,
                           size) == 0 )
            rc = 0;
    }
    
    if ( flush_tlb )
        flush_tlb_mask(d->domain_dirty_cpumask);

out:
    paging_unlock(d);
    
    if ( dirty_bitmap )
        xfree(dirty_bitmap);
    return rc;
}


/************************************************/
/*          HAP VRAM TRACKING SUPPORT           */
/************************************************/

/*
 * hap_track_dirty_vram()
 * Create the domain's dv_dirty_vram struct on demand.
 * Create a dirty vram range on demand when some [begin_pfn:begin_pfn+nr] is
 * first encountered.
 * Collect the guest_dirty bitmask, a bit mask of the dirty vram pages, by
 * calling paging_log_dirty_range(), which interrogates each vram
 * page's p2m type looking for pages that have been made writable.
 */
int hap_track_dirty_vram(struct domain *d,
                         unsigned long begin_pfn,
                         unsigned long nr,
                         XEN_GUEST_HANDLE_64(uint8) guest_dirty_bitmap)
{
    long rc = 0;
    dv_dirty_vram_t *dirty_vram;
    uint8_t *dirty_bitmap = NULL;

    if ( nr )
    {
        dv_range_t *range = NULL;
        int size = ( nr + BITS_PER_BYTE - 1 ) / BITS_PER_BYTE;
        
        if ( !paging_mode_log_dirty(d) )
        {
            hap_logdirty_init(d);
            rc = paging_log_dirty_enable(d);
            if ( rc )
                goto out;
        }

        rc = -ENOMEM;
        dirty_bitmap = xzalloc_bytes( size );
        if ( !dirty_bitmap )
            goto out;
        
        paging_lock(d);
        
        dirty_vram = d->arch.hvm_domain.dirty_vram;
        if ( !dirty_vram ) 
        {
            rc = -ENOMEM;
            if ( !(dirty_vram = dirty_vram_alloc(d)) )
            {
                paging_unlock(d);
                goto out;
            }
        }
        
        range = dirty_vram_range_find(d, begin_pfn, nr);
        if ( !range )
        {
            rc = -ENOMEM;
            if ( !(range = dirty_vram_range_alloc(d, begin_pfn, nr)) )
            {
                paging_unlock(d);
                goto out;
            }
            
            paging_unlock(d);
            
            /* set l1e entries of range within P2M table to be read-only. */
            p2m_change_type_range(d, begin_pfn, begin_pfn + nr,
                                  p2m_ram_rw, p2m_ram_logdirty);
            
            flush_tlb_mask(d->domain_dirty_cpumask);
            
            memset(dirty_bitmap, 0xff, size); /* consider all pages dirty */
        }
        else
        {
            paging_unlock(d);
            
            domain_pause(d);
            
            /* get the bitmap */
            paging_log_dirty_range(d, begin_pfn, nr, dirty_bitmap);
            
            domain_unpause(d);
        }
        
        
        rc = -EFAULT;
        if ( copy_to_guest(guest_dirty_bitmap,
                           dirty_bitmap,
                           size) == 0 )
        {
            rc = 0;
        }
    }
    else {
        paging_lock(d);
        
        dirty_vram = d->arch.hvm_domain.dirty_vram;
        if ( dirty_vram )
        {
            /*
             * If zero pages specified while tracking dirty vram
             * then stop tracking
             */
            dirty_vram_free(d);
        
        }
        
        paging_unlock(d);
    }
out:
    if ( dirty_bitmap )
        xfree(dirty_bitmap);
    
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
