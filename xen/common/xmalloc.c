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
#include <xen/irq.h>
#include <xen/smp.h>

/*
 * XMALLOC_DEBUG:
 *  1. Free data blocks are filled with poison bytes.
 *  2. In-use data blocks have guard bytes at the start and end.
 */
#ifndef NDEBUG
#define XMALLOC_DEBUG 1
#endif

static LIST_HEAD(freelist);
static DEFINE_SPINLOCK(freelist_lock);

struct xmalloc_hdr
{
    /* Size is total including this header. */
    size_t size;
    struct list_head freelist;
} __cacheline_aligned;

static void add_to_freelist(struct xmalloc_hdr *hdr)
{
#if XMALLOC_DEBUG
    memset(hdr + 1, 0xa5, hdr->size - sizeof(*hdr));
#endif
    list_add(&hdr->freelist, &freelist);
}

static void del_from_freelist(struct xmalloc_hdr *hdr)
{
#if XMALLOC_DEBUG
    size_t i;
    unsigned char *data = (unsigned char *)(hdr + 1);
    for ( i = 0; i < (hdr->size - sizeof(*hdr)); i++ )
        BUG_ON(data[i] != 0xa5);
    BUG_ON((hdr->size <= 0) || (hdr->size >= PAGE_SIZE));
#endif
    list_del(&hdr->freelist);
}

static void *data_from_header(struct xmalloc_hdr *hdr)
{
#if XMALLOC_DEBUG
    /* Data block contain SMP_CACHE_BYTES of guard canary. */
    unsigned char *data = (unsigned char *)(hdr + 1);
    memset(data, 0x5a, SMP_CACHE_BYTES);
    memset(data + hdr->size - sizeof(*hdr) - SMP_CACHE_BYTES,
           0x5a, SMP_CACHE_BYTES);
    return data + SMP_CACHE_BYTES;
#else
    return hdr + 1;
#endif
}

static struct xmalloc_hdr *header_from_data(void *p)
{
#if XMALLOC_DEBUG
    unsigned char *data = (unsigned char *)p - SMP_CACHE_BYTES;
    struct xmalloc_hdr *hdr = (struct xmalloc_hdr *)data - 1;
    size_t i;

    /* Check header guard canary. */
    for ( i = 0; i < SMP_CACHE_BYTES; i++ )
        BUG_ON(data[i] != 0x5a);

    /* Check footer guard canary. */
    data += hdr->size - sizeof(*hdr) - SMP_CACHE_BYTES;
    for ( i = 0; i < SMP_CACHE_BYTES; i++ )
        BUG_ON(data[i] != 0x5a);

    return hdr;
#else
    return (struct xmalloc_hdr *)p - 1;
#endif
}

static void maybe_split(struct xmalloc_hdr *hdr, size_t size, size_t block)
{
    struct xmalloc_hdr *extra;
    size_t leftover = block - size;

    /* If enough is left to make a block, put it on free list. */
    if ( leftover >= (2 * sizeof(struct xmalloc_hdr)) )
    {
        extra = (struct xmalloc_hdr *)((unsigned long)hdr + size);
        extra->size = leftover;
        add_to_freelist(extra);
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

    return data_from_header(hdr);
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

    return data_from_header(hdr);
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

    ASSERT(!in_irq());

    /* We currently always return cacheline aligned. */
    BUG_ON(align > SMP_CACHE_BYTES);

#if XMALLOC_DEBUG
    /* Add room for canaries at start and end of data block. */
    size += 2 * SMP_CACHE_BYTES;
#endif

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
        del_from_freelist(i);
        maybe_split(i, size, i->size);
        spin_unlock_irqrestore(&freelist_lock, flags);
        return data_from_header(i);
    }
    spin_unlock_irqrestore(&freelist_lock, flags);

    /* Alloc a new page and return from that. */
    return xmalloc_new_page(size);
}

void xfree(void *p)
{
    unsigned long flags;
    struct xmalloc_hdr *i, *tmp, *hdr;

    ASSERT(!in_irq());

    if ( p == NULL )
        return;

    hdr = header_from_data(p);

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
            del_from_freelist(i);
            i->size += hdr->size;
            hdr = i;
        }

        /* We precede this block? Swallow it. */
        if ( (_hdr + hdr->size) == _i )
        {
            del_from_freelist(i);
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
        add_to_freelist(hdr);
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
