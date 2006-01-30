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
#include <xen/perfc.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/shadow.h>
#include <xen/domain_page.h>
#include <asm/page.h>

/*
 * Comma-separated list of hexadecimal page numbers containing bad bytes.
 * e.g. 'badpage=0x3f45,0x8a321'.
 */
static char opt_badpage[100] = "";
string_param("badpage", opt_badpage);

#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

static spinlock_t page_scrub_lock = SPIN_LOCK_UNLOCKED;
LIST_HEAD(page_scrub_list);

/*********************
 * ALLOCATION BITMAP
 *  One bit per page of memory. Bit set => page is allocated.
 */

static unsigned long *alloc_bitmap;
#define PAGES_PER_MAPWORD (sizeof(unsigned long) * 8)

#define allocated_in_map(_pn)                 \
( !! (alloc_bitmap[(_pn)/PAGES_PER_MAPWORD] & \
     (1UL<<((_pn)&(PAGES_PER_MAPWORD-1)))) )

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
        alloc_bitmap[curr_idx] |= ((1UL<<end_off)-1) & -(1UL<<start_off);
    }
    else 
    {
        alloc_bitmap[curr_idx] |= -(1UL<<start_off);
        while ( ++curr_idx < end_idx ) alloc_bitmap[curr_idx] = ~0UL;
        alloc_bitmap[curr_idx] |= (1UL<<end_off)-1;
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

    curr_idx  = first_page / PAGES_PER_MAPWORD;
    start_off = first_page & (PAGES_PER_MAPWORD-1);
    end_idx   = (first_page + nr_pages) / PAGES_PER_MAPWORD;
    end_off   = (first_page + nr_pages) & (PAGES_PER_MAPWORD-1);

    if ( curr_idx == end_idx )
    {
        alloc_bitmap[curr_idx] &= -(1UL<<end_off) | ((1UL<<start_off)-1);
    }
    else 
    {
        alloc_bitmap[curr_idx] &= (1UL<<start_off)-1;
        while ( ++curr_idx != end_idx ) alloc_bitmap[curr_idx] = 0;
        alloc_bitmap[curr_idx] &= -(1UL<<end_off);
    }
}



/*************************
 * BOOT-TIME ALLOCATOR
 */

/* Initialise allocator to handle up to @max_page pages. */
physaddr_t init_boot_allocator(physaddr_t bitmap_start)
{
    unsigned long bitmap_size;

    bitmap_start = round_pgup(bitmap_start);

    /*
     * Allocate space for the allocation bitmap. Include an extra longword
     * of padding for possible overrun in map_alloc and map_free.
     */
    bitmap_size  = max_page / 8;
    bitmap_size += sizeof(unsigned long);
    bitmap_size  = round_pgup(bitmap_size);
    alloc_bitmap = (unsigned long *)phys_to_virt(bitmap_start);

    /* All allocated by default. */
    memset(alloc_bitmap, ~0, bitmap_size);

    return bitmap_start + bitmap_size;
}

void init_boot_pages(physaddr_t ps, physaddr_t pe)
{
    unsigned long bad_pfn;
    char *p;

    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    if ( pe <= ps )
        return;

    map_free(ps >> PAGE_SHIFT, (pe - ps) >> PAGE_SHIFT);

    /* Check new pages against the bad-page list. */
    p = opt_badpage;
    while ( *p != '\0' )
    {
        bad_pfn = simple_strtoul(p, &p, 0);

        if ( *p == ',' )
            p++;
        else if ( *p != '\0' )
            break;

        if ( (bad_pfn < max_page) && !allocated_in_map(bad_pfn) )
        {
            printk("Marking page %lx as bad\n", bad_pfn);
            map_alloc(bad_pfn, 1);
        }
    }
}

unsigned long alloc_boot_pages(unsigned long nr_pfns, unsigned long pfn_align)
{
    unsigned long pg, i;

    for ( pg = 0; (pg + nr_pfns) < max_page; pg += pfn_align )
    {
        for ( i = 0; i < nr_pfns; i++ )
            if ( allocated_in_map(pg + i) )
                 break;

        if ( i == nr_pfns )
        {
            map_alloc(pg, nr_pfns);
            return pg;
        }
    }

    return 0;
}



/*************************
 * BINARY BUDDY ALLOCATOR
 */

#define MEMZONE_XEN 0
#define MEMZONE_DOM 1
#define MEMZONE_DMADOM 2
#define NR_ZONES    3

#define pfn_dom_zone_type(_pfn)                                 \
    (((_pfn) <= MAX_DMADOM_PFN) ? MEMZONE_DMADOM : MEMZONE_DOM)

/* Up to 2^20 pages can be allocated at once. */
#define MAX_ORDER 20
static struct list_head heap[NR_ZONES][MAX_ORDER+1];

static unsigned long avail[NR_ZONES];

static spinlock_t heap_lock = SPIN_LOCK_UNLOCKED;

void end_boot_allocator(void)
{
    unsigned long i, j;
    int curr_free = 0, next_free = 0;

    memset(avail, 0, sizeof(avail));

    for ( i = 0; i < NR_ZONES; i++ )
        for ( j = 0; j <= MAX_ORDER; j++ )
            INIT_LIST_HEAD(&heap[i][j]);

    /* Pages that are free now go to the domain sub-allocator. */
    for ( i = 0; i < max_page; i++ )
    {
        curr_free = next_free;
        next_free = !allocated_in_map(i+1);
        if ( next_free )
            map_alloc(i+1, 1); /* prevent merging in free_heap_pages() */
        if ( curr_free )
            free_heap_pages(pfn_dom_zone_type(i), pfn_to_page(i), 0);
    }
}

/* Hand the specified arbitrary page range to the specified heap zone. */
void init_heap_pages(
    unsigned int zone, struct pfn_info *pg, unsigned long nr_pages)
{
    unsigned long i;

    ASSERT(zone < NR_ZONES);

    for ( i = 0; i < nr_pages; i++ )
        free_heap_pages(zone, pg+i, 0);
}


/* Allocate 2^@order contiguous pages. */
struct pfn_info *alloc_heap_pages(unsigned int zone, unsigned int order)
{
    int i;
    struct pfn_info *pg;

    ASSERT(zone < NR_ZONES);

    if ( unlikely(order > MAX_ORDER) )
        return NULL;

    spin_lock(&heap_lock);

    /* Find smallest order which can satisfy the request. */
    for ( i = order; i <= MAX_ORDER; i++ )
        if ( !list_empty(&heap[zone][i]) )
            goto found;

    /* No suitable memory blocks. Fail the request. */
    spin_unlock(&heap_lock);
    return NULL;

 found: 
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

    spin_unlock(&heap_lock);

    return pg;
}


/* Free 2^@order set of pages. */
void free_heap_pages(
    unsigned int zone, struct pfn_info *pg, unsigned int order)
{
    unsigned long mask;

    ASSERT(zone < NR_ZONES);
    ASSERT(order <= MAX_ORDER);

    spin_lock(&heap_lock);

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

    spin_unlock(&heap_lock);
}


/*
 * Scrub all unallocated pages in all heap zones. This function is more
 * convoluted than appears necessary because we do not want to continuously
 * hold the lock or disable interrupts while scrubbing very large memory areas.
 */
void scrub_heap_pages(void)
{
    void *p;
    unsigned long pfn;
    int cpu = smp_processor_id();

    printk("Scrubbing Free RAM: ");

    for ( pfn = 0; pfn < max_page; pfn++ )
    {
        /* Every 100MB, print a progress dot. */
        if ( (pfn % ((100*1024*1024)/PAGE_SIZE)) == 0 )
            printk(".");

        if ( unlikely(softirq_pending(cpu)) )
            do_softirq();

        /* Quick lock-free check. */
        if ( allocated_in_map(pfn) )
            continue;

        spin_lock_irq(&heap_lock);

        /* Re-check page status with lock held. */
        if ( !allocated_in_map(pfn) )
        {
            if ( IS_XEN_HEAP_FRAME(pfn_to_page(pfn)) )
            {
                p = page_to_virt(pfn_to_page(pfn));
                memguard_unguard_range(p, PAGE_SIZE);
                clear_page(p);
                memguard_guard_range(p, PAGE_SIZE);
            }
            else
            {
                p = map_domain_page(pfn);
                clear_page(p);
                unmap_domain_page(p);
            }
        }

        spin_unlock_irq(&heap_lock);
    }

    printk("done.\n");
}



/*************************
 * XEN-HEAP SUB-ALLOCATOR
 */

void init_xenheap_pages(physaddr_t ps, physaddr_t pe)
{
    unsigned long flags;

    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    if ( pe <= ps )
        return;

    memguard_guard_range(phys_to_virt(ps), pe - ps);

    /*
     * Yuk! Ensure there is a one-page buffer between Xen and Dom zones, to
     * prevent merging of power-of-two blocks across the zone boundary.
     */
    if ( !IS_XEN_HEAP_FRAME(phys_to_page(pe)) )
        pe -= PAGE_SIZE;

    local_irq_save(flags);
    init_heap_pages(MEMZONE_XEN, phys_to_page(ps), (pe - ps) >> PAGE_SHIFT);
    local_irq_restore(flags);
}


void *alloc_xenheap_pages(unsigned int order)
{
    unsigned long flags;
    struct pfn_info *pg;
    int i;

    local_irq_save(flags);
    pg = alloc_heap_pages(MEMZONE_XEN, order);
    local_irq_restore(flags);

    if ( unlikely(pg == NULL) )
        goto no_memory;

    memguard_unguard_range(page_to_virt(pg), 1 << (order + PAGE_SHIFT));

    for ( i = 0; i < (1 << order); i++ )
    {
        pg[i].count_info        = 0;
        pg[i].u.inuse._domain   = 0;
        pg[i].u.inuse.type_info = 0;
    }

    return page_to_virt(pg);

 no_memory:
    printk("Cannot handle page request order %d!\n", order);
    return NULL;
}


void free_xenheap_pages(void *v, unsigned int order)
{
    unsigned long flags;

    if ( v == NULL )
        return;

    memguard_guard_range(v, 1 << (order + PAGE_SHIFT));    

    local_irq_save(flags);
    free_heap_pages(MEMZONE_XEN, virt_to_page(v), order);
    local_irq_restore(flags);
}



/*************************
 * DOMAIN-HEAP SUB-ALLOCATOR
 */

void init_domheap_pages(physaddr_t ps, physaddr_t pe)
{
    unsigned long s_tot, e_tot, s_dma, e_dma, s_nrm, e_nrm;

    ASSERT(!in_irq());

    s_tot = round_pgup(ps) >> PAGE_SHIFT;
    e_tot = round_pgdown(pe) >> PAGE_SHIFT;

    s_dma = min(s_tot, MAX_DMADOM_PFN + 1);
    e_dma = min(e_tot, MAX_DMADOM_PFN + 1);
    if ( s_dma < e_dma )
        init_heap_pages(MEMZONE_DMADOM, pfn_to_page(s_dma), e_dma - s_dma);

    s_nrm = max(s_tot, MAX_DMADOM_PFN + 1);
    e_nrm = max(e_tot, MAX_DMADOM_PFN + 1);
    if ( s_nrm < e_nrm )
        init_heap_pages(MEMZONE_DOM, pfn_to_page(s_nrm), e_nrm - s_nrm);
}


struct pfn_info *alloc_domheap_pages(
    struct domain *d, unsigned int order, unsigned int flags)
{
    struct pfn_info *pg = NULL;
    cpumask_t mask;
    int i;

    ASSERT(!in_irq());

    if ( !(flags & ALLOC_DOM_DMA) )
        pg = alloc_heap_pages(MEMZONE_DOM, order);

    if ( pg == NULL )
        if ( (pg = alloc_heap_pages(MEMZONE_DMADOM, order)) == NULL )
            return NULL;

    mask = pg->u.free.cpumask;
    tlbflush_filter(mask, pg->tlbflush_timestamp);

    pg->count_info        = 0;
    pg->u.inuse._domain   = 0;
    pg->u.inuse.type_info = 0;

    for ( i = 1; i < (1 << order); i++ )
    {
        /* Add in any extra CPUs that need flushing because of this page. */
        cpumask_t extra_cpus_mask;
        cpus_andnot(extra_cpus_mask, pg[i].u.free.cpumask, mask);
        tlbflush_filter(extra_cpus_mask, pg[i].tlbflush_timestamp);
        cpus_or(mask, mask, extra_cpus_mask);

        pg[i].count_info        = 0;
        pg[i].u.inuse._domain   = 0;
        pg[i].u.inuse.type_info = 0;
    }

    if ( unlikely(!cpus_empty(mask)) )
    {
        perfc_incrc(need_flush_tlb_flush);
        flush_tlb_mask(mask);
    }

    if ( d == NULL )
        return pg;

    spin_lock(&d->page_alloc_lock);

    if ( unlikely(test_bit(_DOMF_dying, &d->domain_flags)) ||
         unlikely((d->tot_pages + (1 << order)) > d->max_pages) )
    {
        DPRINTK("Over-allocation for domain %u: %u > %u\n",
                d->domain_id, d->tot_pages + (1 << order), d->max_pages);
        DPRINTK("...or the domain is dying (%d)\n", 
                !!test_bit(_DOMF_dying, &d->domain_flags));
        spin_unlock(&d->page_alloc_lock);
        free_heap_pages(pfn_dom_zone_type(page_to_pfn(pg)), pg, order);
        return NULL;
    }

    if ( unlikely(d->tot_pages == 0) )
        get_knownalive_domain(d);

    d->tot_pages += 1 << order;

    for ( i = 0; i < (1 << order); i++ )
    {
        page_set_owner(&pg[i], d);
        wmb(); /* Domain pointer must be visible before updating refcnt. */
        pg[i].count_info |= PGC_allocated | 1;
        list_add_tail(&pg[i].list, &d->page_list);
    }

    spin_unlock(&d->page_alloc_lock);
    
    return pg;
}


void free_domheap_pages(struct pfn_info *pg, unsigned int order)
{
    int            i, drop_dom_ref;
    struct domain *d = page_get_owner(pg);

    ASSERT(!in_irq());

    if ( unlikely(IS_XEN_HEAP_FRAME(pg)) )
    {
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ )
            list_del(&pg[i].list);

        d->xenheap_pages -= 1 << order;
        drop_dom_ref = (d->xenheap_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);
    }
    else if ( likely(d != NULL) )
    {
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ )
        {
            shadow_drop_references(d, &pg[i]);
            ASSERT((pg[i].u.inuse.type_info & PGT_count_mask) == 0);
            pg[i].tlbflush_timestamp  = tlbflush_current_time();
            pg[i].u.free.cpumask      = d->domain_dirty_cpumask;
            list_del(&pg[i].list);
        }

        d->tot_pages -= 1 << order;
        drop_dom_ref = (d->tot_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);

        if ( likely(!test_bit(_DOMF_dying, &d->domain_flags)) )
        {
            free_heap_pages(pfn_dom_zone_type(page_to_pfn(pg)), pg, order);
        }
        else
        {
            /*
             * Normally we expect a domain to clear pages before freeing them,
             * if it cares about the secrecy of their contents. However, after
             * a domain has died we assume responsibility for erasure.
             */
            for ( i = 0; i < (1 << order); i++ )
            {
                spin_lock(&page_scrub_lock);
                list_add(&pg[i].list, &page_scrub_list);
                spin_unlock(&page_scrub_lock);
            }
        }
    }
    else
    {
        /* Freeing anonymous domain-heap pages. */
        for ( i = 0; i < (1 << order); i++ )
            pg[i].u.free.cpumask = CPU_MASK_NONE;
        free_heap_pages(pfn_dom_zone_type(page_to_pfn(pg)), pg, order);
        drop_dom_ref = 0;
    }

    if ( drop_dom_ref )
        put_domain(d);
}


unsigned long avail_domheap_pages(void)
{
    return avail[MEMZONE_DOM] + avail[MEMZONE_DMADOM];
}



/*************************
 * PAGE SCRUBBING
 */

static void page_scrub_softirq(void)
{
    struct list_head *ent;
    struct pfn_info  *pg;
    void             *p;
    int               i;
    s_time_t          start = NOW();

    /* Aim to do 1ms of work (ten percent of a 10ms jiffy). */
    do {
        spin_lock(&page_scrub_lock);

        if ( unlikely((ent = page_scrub_list.next) == &page_scrub_list) )
        {
            spin_unlock(&page_scrub_lock);
            return;
        }
        
        /* Peel up to 16 pages from the list. */
        for ( i = 0; i < 16; i++ )
        {
            if ( ent->next == &page_scrub_list )
                break;
            ent = ent->next;
        }
        
        /* Remove peeled pages from the list. */
        ent->next->prev = &page_scrub_list;
        page_scrub_list.next = ent->next;
        
        spin_unlock(&page_scrub_lock);
        
        /* Working backwards, scrub each page in turn. */
        while ( ent != &page_scrub_list )
        {
            pg = list_entry(ent, struct pfn_info, list);
            ent = ent->prev;
            p = map_domain_page(page_to_pfn(pg));
            clear_page(p);
            unmap_domain_page(p);
            free_heap_pages(pfn_dom_zone_type(page_to_pfn(pg)), pg, 0);
        }
    } while ( (NOW() - start) < MILLISECS(1) );
}

static __init int page_scrub_init(void)
{
    open_softirq(PAGE_SCRUB_SOFTIRQ, page_scrub_softirq);
    return 0;
}
__initcall(page_scrub_init);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
