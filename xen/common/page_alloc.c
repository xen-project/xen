/******************************************************************************
 * page_alloc.c
 * 
 * Simple buddy heap allocator for Xen.
 * 
 * Copyright (c) 2002-2004 K A Fraser
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <asm/page.h>
#include <xen/spinlock.h>
#include <xen/slab.h>
#include <xen/irq.h>
#include <asm/domain_page.h>

extern char opt_badpage[];

/*********************
 * ALLOCATION BITMAP
 *  One bit per page of memory. Bit set => page is allocated.
 */

static unsigned long  bitmap_size; /* in bytes */
static unsigned long *alloc_bitmap;
#define PAGES_PER_MAPWORD (sizeof(unsigned long) * 8)

#define allocated_in_map(_pn) \
(alloc_bitmap[(_pn)/PAGES_PER_MAPWORD] & (1<<((_pn)&(PAGES_PER_MAPWORD-1))))


/*
 * Hint regarding bitwise arithmetic in map_{alloc,free}:
 *  -(1<<n)  sets all bits >= n. 
 *  (1<<n)-1 sets all bits <  n.
 * Variable names in map_{alloc,free}:
 *  *_idx == Index into `alloc_bitmap' array.
 *  *_off == Bit offset within an element of the `alloc_bitmap' array.
 */

static void map_alloc(unsigned long first_page, unsigned long nr_pages)
{
    unsigned long start_off, end_off, curr_idx, end_idx;

#ifndef NDEBUG
    unsigned long i;
    /* Check that the block isn't already allocated. */
    for ( i = 0; i < nr_pages; i++ )
        ASSERT(!allocated_in_map(first_page + i));
#endif

    curr_idx  = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] |= ((1<<end_off)-1) & -(1<<start_off);
    }
    else 
    {
        alloc_bitmap[curr_idx] |= -(1<<start_off);
        while ( ++curr_idx < end_idx ) alloc_bitmap[curr_idx] = ~0L;
        alloc_bitmap[curr_idx] |= (1<<end_off)-1;
    }
}


static void map_free(unsigned long first_page, unsigned long nr_pages)
{
    unsigned long start_off, end_off, curr_idx, end_idx;

#ifndef NDEBUG
    unsigned long i;
    /* Check that the block isn't already freed. */
    for ( i = 0; i < nr_pages; i++ )
        ASSERT(allocated_in_map(first_page + i));
#endif

    curr_idx = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] &= -(1<<end_off) | ((1<<start_off)-1);
    }
    else 
    {
        alloc_bitmap[curr_idx] &= (1<<start_off)-1;
        while ( ++curr_idx != end_idx ) alloc_bitmap[curr_idx] = 0;
        alloc_bitmap[curr_idx] &= -(1<<end_off);
    }
}



/*************************
 * BINARY BUDDY ALLOCATOR
 */

#define MEMZONE_XEN 0
#define MEMZONE_DOM 1
#define NR_ZONES    2

/* Up to 2^10 pages can be allocated at once. */
#define MIN_ORDER  0
#define MAX_ORDER 10
#define NR_ORDERS (MAX_ORDER - MIN_ORDER + 1)
static struct list_head heap[NR_ZONES][NR_ORDERS];

static unsigned long avail[NR_ZONES];

#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

static spinlock_t heap_lock = SPIN_LOCK_UNLOCKED;


/* Initialise allocator to handle up to @max_pages. */
unsigned long init_heap_allocator(
    unsigned long bitmap_start, unsigned long max_pages)
{
    int i, j;
    unsigned long bad_pfn;
    char *p;

    memset(avail, 0, sizeof(avail));

    for ( i = 0; i < NR_ZONES; i++ )
        for ( j = 0; j < NR_ORDERS; j++ )
            INIT_LIST_HEAD(&heap[i][j]);

    bitmap_start = round_pgup(bitmap_start);

    /* Allocate space for the allocation bitmap. */
    bitmap_size  = max_pages / 8;
    bitmap_size  = round_pgup(bitmap_size);
    alloc_bitmap = (unsigned long *)phys_to_virt(bitmap_start);

    /* All allocated by default. */
    memset(alloc_bitmap, ~0, bitmap_size);

    /*
     * Process the bad-page list. Marking the page free in the bitmap will
     * indicate to init_heap_pages() that it should not be placed on the 
     * buddy lists.
     */
    p = opt_badpage;
    while ( *p != '\0' )
    {
        bad_pfn = simple_strtoul(p, &p, 0);

        if ( *p == ',' )
            p++;
        else if ( *p != '\0' )
            break;

        if ( (bad_pfn < max_pages) && allocated_in_map(bad_pfn) )
        {
            printk("Marking page %08lx as bad\n", bad_pfn);
            map_free(bad_pfn, 1);
        }
    }

    return bitmap_start + bitmap_size;
}

/* Hand the specified arbitrary page range to the specified heap zone. */
void init_heap_pages(int zone, struct pfn_info *pg, unsigned long nr_pages)
{
    unsigned long i, pfn = page_to_pfn(pg);

    /* Process each page in turn, skipping bad pages. */
    for ( i = 0; i < nr_pages; i++ )
    {
        if ( likely(allocated_in_map(pfn+i)) ) /* bad page? */
            free_heap_pages(zone, pg+i, 0);
    }
}


/* Allocate 2^@order contiguous pages. */
struct pfn_info *alloc_heap_pages(int zone, int order)
{
    int i;
    struct pfn_info *pg;
    unsigned long flags;

    if ( unlikely(order < MIN_ORDER) || unlikely(order > MAX_ORDER) )
        return NULL;

    spin_lock_irqsave(&heap_lock, flags);

    /* Find smallest order which can satisfy the request. */
    for ( i = order; i < NR_ORDERS; i++ )
	if ( !list_empty(&heap[zone][i]) )
	    break;

    if ( i == NR_ORDERS ) 
        goto no_memory;
 
    pg = list_entry(heap[zone][i].next, struct pfn_info, list);
    list_del(&pg->list);

    /* We may have to halve the chunk a number of times. */
    while ( i != order )
    {
        PFN_ORDER(pg) = --i;
        list_add_tail(&pg->list, &heap[zone][i]);
        pg += 1 << i;
    }
    
    map_alloc(page_to_pfn(pg), 1 << order);
    avail[zone] -= 1 << order;

    spin_unlock_irqrestore(&heap_lock, flags);

    return pg;

 no_memory:
    spin_unlock_irqrestore(&heap_lock, flags);
    return NULL;
}


/* Free 2^@order set of pages. */
void free_heap_pages(int zone, struct pfn_info *pg, int order)
{
    unsigned long mask;
    unsigned long flags;

    spin_lock_irqsave(&heap_lock, flags);

    map_free(page_to_pfn(pg), 1 << order);
    avail[zone] += 1 << order;
    
    /* Merge chunks as far as possible. */
    while ( order < MAX_ORDER )
    {
        mask = 1 << order;

        if ( (page_to_pfn(pg) & mask) )
        {
            /* Merge with predecessor block? */
            if ( allocated_in_map(page_to_pfn(pg)-mask) ||
                 (PFN_ORDER(pg-mask) != order) )
                break;
            list_del(&(pg-mask)->list);
            pg -= mask;
        }
        else
        {
            /* Merge with successor block? */
            if ( allocated_in_map(page_to_pfn(pg)+mask) ||
                 (PFN_ORDER(pg+mask) != order) )
                break;
            list_del(&(pg+mask)->list);
        }
        
        order++;
    }

    PFN_ORDER(pg) = order;
    list_add_tail(&pg->list, &heap[zone][order]);

    spin_unlock_irqrestore(&heap_lock, flags);
}


/*
 * Scrub all unallocated pages in all heap zones. This function is more
 * convoluted than appears necessary because we do not want to continuously
 * hold the lock or disable interrupts while scrubbing very large memory areas.
 */
void scrub_heap_pages(void)
{
    void *p;
    unsigned long pfn, flags;

    for ( pfn = 0; pfn < (bitmap_size * 8); pfn++ )
    {
        /* Quick lock-free check. */
        if ( allocated_in_map(pfn) )
            continue;
        
        spin_lock_irqsave(&heap_lock, flags);
        
        /* Re-check page status with lock held. */
        if ( !allocated_in_map(pfn) )
        {
            p = map_domain_mem(pfn << PAGE_SHIFT);
            clear_page(p);
            unmap_domain_mem(p);
        }
        
        spin_unlock_irqrestore(&heap_lock, flags);
    }
}



/*************************
 * XEN-HEAP SUB-ALLOCATOR
 */

void init_xenheap_pages(unsigned long ps, unsigned long pe)
{
    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    memguard_guard_range(__va(ps), pe - ps);
    init_heap_pages(MEMZONE_XEN, phys_to_page(ps), (pe - ps) >> PAGE_SHIFT);
}

unsigned long alloc_xenheap_pages(int order)
{
    struct pfn_info *pg;
    int i, attempts = 0;

 retry:
    if ( unlikely((pg = alloc_heap_pages(MEMZONE_XEN, order)) == NULL) )
        goto no_memory;

    memguard_unguard_range(page_to_virt(pg), 1 << (order + PAGE_SHIFT));

    for ( i = 0; i < (1 << order); i++ )
    {
        pg[i].count_info        = 0;
        pg[i].u.inuse.domain    = NULL;
        pg[i].u.inuse.type_info = 0;
    }

    return (unsigned long)page_to_virt(pg);

 no_memory:
    if ( attempts++ < 8 )
    {
        xmem_cache_reap();
        goto retry;
    }

    printk("Cannot handle page request order %d!\n", order);
    dump_slabinfo();
    return 0;
}

void free_xenheap_pages(unsigned long p, int order)
{
    memguard_guard_range((void *)p, 1 << (order + PAGE_SHIFT));    
    free_heap_pages(MEMZONE_XEN, virt_to_page(p), order);
}



/*************************
 * DOMAIN-HEAP SUB-ALLOCATOR
 */

void init_domheap_pages(unsigned long ps, unsigned long pe)
{
    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    init_heap_pages(MEMZONE_DOM, phys_to_page(ps), (pe - ps) >> PAGE_SHIFT);
}

struct pfn_info *alloc_domheap_pages(struct domain *d, int order)
{
    struct pfn_info *pg;
    unsigned long mask, flushed_mask, pfn_stamp, cpu_stamp;
    int i, j;

    ASSERT(!in_irq());

    if ( unlikely((pg = alloc_heap_pages(MEMZONE_DOM, order)) == NULL) )
        return NULL;

    flushed_mask = 0;
    for ( i = 0; i < (1 << order); i++ )
    {
        if ( (mask = (pg[i].u.free.cpu_mask & ~flushed_mask)) != 0 )
        {
            pfn_stamp = pg[i].tlbflush_timestamp;
            for ( j = 0; (mask != 0) && (j < smp_num_cpus); j++ )
            {
                if ( mask & (1<<j) )
                {
                    cpu_stamp = tlbflush_time[j];
                    if ( !NEED_FLUSH(cpu_stamp, pfn_stamp) )
                        mask &= ~(1<<j);
                }
            }
            
            if ( unlikely(mask != 0) )
            {
                flush_tlb_mask(mask);
                perfc_incrc(need_flush_tlb_flush);
                flushed_mask |= mask;
            }
        }

        pg[i].count_info        = 0;
        pg[i].u.inuse.domain    = NULL;
        pg[i].u.inuse.type_info = 0;
    }

    if ( d == NULL )
        return pg;

    spin_lock(&d->page_alloc_lock);

    if ( unlikely(test_bit(DF_DYING, &d->flags)) ||
         unlikely((d->tot_pages + (1 << order)) > d->max_pages) )
    {
        DPRINTK("Over-allocation for domain %u: %u > %u\n",
                d->id, d->tot_pages + (1 << order), d->max_pages);
        DPRINTK("...or the domain is dying (%d)\n", 
                !!test_bit(DF_DYING, &d->flags));
        spin_unlock(&d->page_alloc_lock);
        free_heap_pages(MEMZONE_DOM, pg, order);
        return NULL;
    }

    if ( unlikely(d->tot_pages == 0) )
        get_knownalive_domain(d);

    d->tot_pages += 1 << order;

    for ( i = 0; i < (1 << order); i++ )
    {
        pg[i].u.inuse.domain = d;
        wmb(); /* Domain pointer must be visible before updating refcnt. */
        pg[i].count_info |= PGC_allocated | 1;
        list_add_tail(&pg[i].list, &d->page_list);
    }

    spin_unlock(&d->page_alloc_lock);
    
    return pg;
}

void free_domheap_pages(struct pfn_info *pg, int order)
{
    int            i, drop_dom_ref;
    struct domain *d = pg->u.inuse.domain;
    void          *p;

    if ( unlikely(IS_XEN_HEAP_FRAME(pg)) )
    {
        /* NB. May recursively lock from domain_relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ )
            list_del(&pg[i].list);

        d->xenheap_pages -= 1 << order;
        drop_dom_ref = (d->xenheap_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);
    }
    else if ( likely(d != NULL) )
    {
        /* NB. May recursively lock from domain_relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ )
        {
            ASSERT((pg[i].u.inuse.type_info & PGT_count_mask) == 0);
            pg[i].tlbflush_timestamp  = tlbflush_current_time();
            pg[i].u.free.cpu_mask     = 1 << d->processor;
            list_del(&pg[i].list);

            /*
             * Normally we expect a domain to clear pages before freeing them,
             * if it cares about the secrecy of their contents. However, after
             * a domain has died we assume responsibility for erasure.
             */
            if ( unlikely(test_bit(DF_DYING, &d->flags)) )
            {
                p = map_domain_mem(page_to_phys(&pg[i]));
                clear_page(p);
                unmap_domain_mem(p);
            }
        }

        d->tot_pages -= 1 << order;
        drop_dom_ref = (d->tot_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);

        free_heap_pages(MEMZONE_DOM, pg, order);
    }
    else
    {
        /* Freeing an anonymous domain-heap page. */
        free_heap_pages(MEMZONE_DOM, pg, order);
        drop_dom_ref = 0;
    }

    if ( drop_dom_ref )
        put_domain(d);
}

unsigned long avail_domheap_pages(void)
{
    return avail[MEMZONE_DOM];
}

