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

static spinlock_t alloc_lock = SPIN_LOCK_UNLOCKED;


/*********************
 * ALLOCATION BITMAP
 *  One bit per page of memory. Bit set => page is allocated.
 */

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

    memguard_unguard_range(phys_to_virt(first_page << PAGE_SHIFT), 
                           nr_pages << PAGE_SHIFT);

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

    memguard_guard_range(phys_to_virt(first_page << PAGE_SHIFT), 
                         nr_pages << PAGE_SHIFT);

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

/* Linked lists of free chunks of different powers-of-two in size. */
#define NR_ORDERS 11 /* Up to 2^10 pages can be allocated at once. */
static struct list_head free_head[NR_ORDERS];

#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)


/*
 * Initialise allocator, placing addresses [@min,@max] in free pool.
 * @min and @max are PHYSICAL addresses.
 */
void __init init_page_allocator(unsigned long min, unsigned long max)
{
    int i;
    unsigned long range, bitmap_size;
    struct pfn_info *pg;

    for ( i = 0; i < NR_ORDERS; i++ )
        INIT_LIST_HEAD(&free_head[i]);

    min = round_pgup  (min);
    max = round_pgdown(max);

    /* Allocate space for the allocation bitmap. */
    bitmap_size  = (max+1) >> (PAGE_SHIFT+3);
    bitmap_size  = round_pgup(bitmap_size);
    alloc_bitmap = (unsigned long *)phys_to_virt(min);
    min         += bitmap_size;
    range        = max - min;

    /* All allocated by default. */
    memset(alloc_bitmap, ~0, bitmap_size);
    /* Free up the memory we've been given to play with. */
    map_free(min>>PAGE_SHIFT, range>>PAGE_SHIFT);
    
    pg = &frame_table[min >> PAGE_SHIFT];
    while ( range != 0 )
    {
        /*
         * Next chunk is limited by alignment of pg, but also must not be
         * bigger than remaining bytes.
         */
        for ( i = 0; i < NR_ORDERS; i++ )
            if ( ((page_to_pfn(pg) & (1 << i)) != 0) ||
                 ((1 << (i + PAGE_SHIFT + 1)) > range) )
                break;

        PFN_ORDER(pg) = i;
        list_add_tail(&pg->list, &free_head[i]);

        pg    += 1 << i;
        range -= 1 << (i + PAGE_SHIFT);
    }
}


/* Allocate 2^@order contiguous pages. Returns a VIRTUAL address. */
unsigned long alloc_xenheap_pages(int order)
{
    int i, attempts = 0;
    struct pfn_info *pg;
    unsigned long flags;

retry:
    spin_lock_irqsave(&alloc_lock, flags);

    /* Find smallest order which can satisfy the request. */
    for ( i = order; i < NR_ORDERS; i++ )
	if ( !list_empty(&free_head[i]) )
	    break;

    if ( i == NR_ORDERS ) 
        goto no_memory;
 
    pg = list_entry(free_head[i].next, struct pfn_info, list);
    list_del(&pg->list);

    /* We may have to halve the chunk a number of times. */
    while ( i != order )
    {
        PFN_ORDER(pg) = --i;
        list_add_tail(&pg->list, &free_head[i]);
        pg += 1 << i;
    }
    
    map_alloc(page_to_pfn(pg), 1<<order);

    spin_unlock_irqrestore(&alloc_lock, flags);

    return (unsigned long)page_to_virt(pg);

 no_memory:
    spin_unlock_irqrestore(&alloc_lock, flags);
        
    if ( attempts++ < 8 )
    {
        xmem_cache_reap();
        goto retry;
    }

    printk("Cannot handle page request order %d!\n", order);
    dump_slabinfo();

    return 0;
}


/* Free 2^@order pages at VIRTUAL address @p. */
void free_xenheap_pages(unsigned long p, int order)
{
    unsigned long mask;
    struct pfn_info *pg = virt_to_page(p);
    unsigned long flags;

    spin_lock_irqsave(&alloc_lock, flags);

    map_free(page_to_pfn(pg), 1<<order);
    
    /* Merge chunks as far as possible. */
    for ( ; ; )
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
    list_add_tail(&pg->list, &free_head[order]);

    spin_unlock_irqrestore(&alloc_lock, flags);
}
