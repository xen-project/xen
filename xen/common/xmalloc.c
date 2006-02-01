/******************************************************************************
 * Simple allocator for Xen.  If larger than a page, simply use the
 * page-order allocator.
 *
 * Copyright (C) 2005 Rusty Russell IBM Corporation
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

/*
 * TODO (Keir, 17/2/05):
 *  1. Use space in page_info to avoid xmalloc_hdr in allocated blocks.
 *  2. page_info points into free list to make xfree() O(1) complexity.
 *  3. Perhaps make this a sub-page buddy allocator? xmalloc() == O(1).
 *     (Disadvantage is potentially greater internal fragmentation).
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/spinlock.h>
#include <xen/timer.h>
#include <xen/cache.h>
#include <xen/prefetch.h>

static LIST_HEAD(freelist);
static spinlock_t freelist_lock = SPIN_LOCK_UNLOCKED;

struct xmalloc_hdr
{
    /* Total including this hdr. */
    size_t size;
    struct list_head freelist;
} __cacheline_aligned;

static void maybe_split(struct xmalloc_hdr *hdr, size_t size, size_t block)
{
    struct xmalloc_hdr *extra;
    size_t leftover = block - size;

    /* If enough is left to make a block, put it on free list. */
    if ( leftover >= (2 * sizeof(struct xmalloc_hdr)) )
    {
        extra = (struct xmalloc_hdr *)((unsigned long)hdr + size);
        extra->size = leftover;
        list_add(&extra->freelist, &freelist);
    }
    else
    {
        size = block;
    }

    hdr->size = size;
    /* Debugging aid. */
    hdr->freelist.next = hdr->freelist.prev = NULL;
}

static void *xmalloc_new_page(size_t size)
{
    struct xmalloc_hdr *hdr;
    unsigned long flags;

    hdr = alloc_xenheap_page();
    if ( hdr == NULL )
        return NULL;

    spin_lock_irqsave(&freelist_lock, flags);
    maybe_split(hdr, size, PAGE_SIZE);
    spin_unlock_irqrestore(&freelist_lock, flags);

    return hdr+1;
}

/* Big object?  Just use the page allocator. */
static void *xmalloc_whole_pages(size_t size)
{
    struct xmalloc_hdr *hdr;
    unsigned int pageorder = get_order_from_bytes(size);

    hdr = alloc_xenheap_pages(pageorder);
    if ( hdr == NULL )
        return NULL;

    hdr->size = (1 << (pageorder + PAGE_SHIFT));
    /* Debugging aid. */
    hdr->freelist.next = hdr->freelist.prev = NULL;

    return hdr+1;
}

/* Return size, increased to alignment with align. */
static inline size_t align_up(size_t size, size_t align)
{
    return (size + align - 1) & ~(align - 1);
}

void *_xmalloc(size_t size, size_t align)
{
    struct xmalloc_hdr *i;
    unsigned long flags;

    /* We currently always return cacheline aligned. */
    BUG_ON(align > SMP_CACHE_BYTES);

    /* Add room for header, pad to align next header. */
    size += sizeof(struct xmalloc_hdr);
    size = align_up(size, __alignof__(struct xmalloc_hdr));

    /* For big allocs, give them whole pages. */
    if ( size >= PAGE_SIZE )
        return xmalloc_whole_pages(size);

    /* Search free list. */
    spin_lock_irqsave(&freelist_lock, flags);
    list_for_each_entry( i, &freelist, freelist )
    {
        if ( i->size < size )
            continue;
        list_del(&i->freelist);
        maybe_split(i, size, i->size);
        spin_unlock_irqrestore(&freelist_lock, flags);
        return i+1;
    }
    spin_unlock_irqrestore(&freelist_lock, flags);

    /* Alloc a new page and return from that. */
    return xmalloc_new_page(size);
}

void xfree(const void *p)
{
    unsigned long flags;
    struct xmalloc_hdr *i, *tmp, *hdr;

    if ( p == NULL )
        return;

    hdr = (struct xmalloc_hdr *)p - 1;

    /* We know hdr will be on same page. */
    BUG_ON(((long)p & PAGE_MASK) != ((long)hdr & PAGE_MASK));

    /* Not previously freed. */
    BUG_ON(hdr->freelist.next || hdr->freelist.prev);

    /* Big allocs free directly. */
    if ( hdr->size >= PAGE_SIZE )
    {
        free_xenheap_pages(hdr, get_order_from_bytes(hdr->size));
        return;
    }

    /* Merge with other free block, or put in list. */
    spin_lock_irqsave(&freelist_lock, flags);
    list_for_each_entry_safe( i, tmp, &freelist, freelist )
    {
        unsigned long _i   = (unsigned long)i;
        unsigned long _hdr = (unsigned long)hdr;

        /* Do not merge across page boundaries. */
        if ( ((_i ^ _hdr) & PAGE_MASK) != 0 )
            continue;

        /* We follow this block?  Swallow it. */
        if ( (_i + i->size) == _hdr )
        {
            list_del(&i->freelist);
            i->size += hdr->size;
            hdr = i;
        }

        /* We precede this block? Swallow it. */
        if ( (_hdr + hdr->size) == _i )
        {
            list_del(&i->freelist);
            hdr->size += i->size;
        }
    }

    /* Did we merge an entire page? */
    if ( hdr->size == PAGE_SIZE )
    {
        BUG_ON((((unsigned long)hdr) & (PAGE_SIZE-1)) != 0);
        free_xenheap_pages(hdr, 0);
    }
    else
    {
        list_add(&hdr->freelist, &freelist);
    }

    spin_unlock_irqrestore(&freelist_lock, flags);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
