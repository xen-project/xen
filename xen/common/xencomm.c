/******************************************************************************
 * xencomm.c
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Tristan Gingold <tristan.gingold@bull.net>
 *          Isaku Yamahata <yamahata@valinux.co.jp> multiple page support
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/xencomm.h>
#include <public/xen.h>
#include <public/xencomm.h>

#undef DEBUG
#ifdef DEBUG
#define xc_dprintk(f, a...) printk("[xencomm]" f , ## a)
#else
#define xc_dprintk(f, a...) ((void)0)
#endif

static void *
xencomm_vaddr(unsigned long paddr, struct page_info *page)
{
    return (void*)((paddr & ~PAGE_MASK) | (unsigned long)page_to_virt(page));
}

/* get_page() to prevent another vcpu freeing the page. */
static int
xencomm_get_page(unsigned long paddr, struct page_info **page)
{
    unsigned long maddr = paddr_to_maddr(paddr);
    if ( maddr == 0 )
        return -EFAULT;
        
    *page = maddr_to_page(maddr);
    if ( !get_page(*page, current->domain) )
    {
        /*
         * This page might be a page granted by another domain, or this page 
         * is freed with decrease reservation hypercall at the same time.
         */
        gdprintk(XENLOG_WARNING,
                 "bad page is passed. paddr %#lx maddr %#lx\n",
                 paddr, maddr);
        return -EFAULT;
    }

    return 0;
}

/* check if struct desc doesn't cross page boundry */
static int
xencomm_desc_cross_page_boundary(unsigned long paddr)
{
    unsigned long offset = paddr & ~PAGE_MASK;
    if ( offset > PAGE_SIZE - sizeof(struct xencomm_desc) )
        return 1;
    return 0;
}

struct xencomm_ctxt {
    struct xencomm_desc __user *desc_in_paddr;
    uint32_t nr_addrs;

    struct page_info *page;
    unsigned long *address;
};

static uint32_t
xencomm_ctxt_nr_addrs(const struct xencomm_ctxt *ctxt)
{
    return ctxt->nr_addrs;
}

static unsigned long*
xencomm_ctxt_address(struct xencomm_ctxt *ctxt)
{
    return ctxt->address;
}

static int
xencomm_ctxt_init(const void *handle, struct xencomm_ctxt *ctxt)
{
    struct page_info *page;
    struct xencomm_desc *desc;
    int ret;

    /* Avoid unaligned access. */
    if ( ((unsigned long)handle % __alignof__(*desc)) != 0 )
        return -EINVAL;
    if ( xencomm_desc_cross_page_boundary((unsigned long)handle) )
        return -EINVAL;

    /* First we need to access the descriptor. */
    ret = xencomm_get_page((unsigned long)handle, &page);
    if ( ret )
        return ret;

    desc = xencomm_vaddr((unsigned long)handle, page);
    if ( desc->magic != XENCOMM_MAGIC )
    {
        printk("%s: error: %p magic was %#x\n", __func__, desc, desc->magic);
        put_page(page);
        return -EINVAL;
    }

    /* Copy before use: It is possible for a guest to modify concurrently. */
    ctxt->nr_addrs = desc->nr_addrs;
    ctxt->desc_in_paddr = (struct xencomm_desc*)handle;
    ctxt->page = page;
    ctxt->address = &desc->address[0];
    return 0;
}

/*
 * Calculate the vaddr of &ctxt->desc_in_paddr->address[i] and get_page().
 * And put the results in ctxt->page and ctxt->address.
 * If there is the previous page, put_page().
 *
 * A guest domain passes the array, ctxt->desc_in_paddr->address[].
 * It is gpaddr-contiguous, but not maddr-contiguous so that
 * we can't obtain the vaddr by simple offsetting.
 * We need to convert gpaddr, &ctxt->desc_in_paddr->address[i],
 * into maddr and then convert it to the xen virtual address in order
 * to access there.
 * The conversion can be optimized out by using the last result of
 * ctxt->address because we access the array sequentially.
 * The conversion, gpaddr -> maddr -> vaddr, is necessary only when
 * crossing page boundary.
 */
static int
xencomm_ctxt_next(struct xencomm_ctxt *ctxt, int i)
{
    unsigned long paddr;
    struct page_info *page;
    int ret;

    BUG_ON(i >= ctxt->nr_addrs);

    /* For i == 0 case we already calculated it in xencomm_ctxt_init(). */
    if ( i != 0 )
        ctxt->address++;

    if ( ((unsigned long)ctxt->address & ~PAGE_MASK) != 0 )
        return 0;

    /* Crossing page boundary: machine address must be calculated. */
    paddr = (unsigned long)&ctxt->desc_in_paddr->address[i];
    ret = xencomm_get_page(paddr, &page);
    if ( ret )
        return ret;

    put_page(ctxt->page);
    ctxt->page = page;
    ctxt->address = xencomm_vaddr(paddr, page);

    return 0;
}

static void
xencomm_ctxt_done(struct xencomm_ctxt *ctxt)
{
    put_page(ctxt->page);
}

static int
xencomm_copy_chunk_from(
    unsigned long to, unsigned long paddr, unsigned int  len)
{
    struct page_info *page;
    int res;

    do {
        res = xencomm_get_page(paddr, &page);
    } while ( res == -EAGAIN );

    if ( res )
        return res;

    xc_dprintk("%lx[%d] -> %lx\n",
               (unsigned long)xencomm_vaddr(paddr, page), len, to);

    memcpy((void *)to, xencomm_vaddr(paddr, page), len);
    put_page(page);

    return 0;
}

static unsigned long
xencomm_inline_from_guest(
    void *to, const void *from, unsigned int n, unsigned int skip)
{
    unsigned long src_paddr = xencomm_inline_addr(from) + skip;

    while ( n > 0 )
    {
        unsigned int chunksz, bytes;

        chunksz = PAGE_SIZE - (src_paddr % PAGE_SIZE);
        bytes   = min(chunksz, n);

        if ( xencomm_copy_chunk_from((unsigned long)to, src_paddr, bytes) )
            return n;
        src_paddr += bytes;
        to += bytes;
        n -= bytes;
    }

    /* Always successful. */
    return 0;
}

/**
 * xencomm_copy_from_guest: Copy a block of data from domain space.
 * @to:   Machine address.
 * @from: Physical address to a xencomm buffer descriptor.
 * @n:    Number of bytes to copy.
 * @skip: Number of bytes from the start to skip.
 *
 * Copy data from domain to hypervisor.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
unsigned long
xencomm_copy_from_guest(
    void *to, const void *from, unsigned int n, unsigned int skip)
{
    struct xencomm_ctxt ctxt;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if ( xencomm_is_inline(from) )
        return xencomm_inline_from_guest(to, from, n, skip);

    if ( xencomm_ctxt_init(from, &ctxt) )
        return n;

    /* Iterate through the descriptor, copying up to a page at a time */
    while ( (to_pos < n) && (i < xencomm_ctxt_nr_addrs(&ctxt)) )
    {
        unsigned long src_paddr;
        unsigned int pgoffset, chunksz, chunk_skip;

        if ( xencomm_ctxt_next(&ctxt, i) )
            goto out;
        src_paddr = *xencomm_ctxt_address(&ctxt);
        if ( src_paddr == XENCOMM_INVALID )
        {
            i++;
            continue;
        }

        pgoffset = src_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, skip);
        from_pos += chunk_skip;
        chunksz -= chunk_skip;
        skip -= chunk_skip;

        if ( skip == 0 && chunksz > 0 )
        {
            unsigned int bytes = min(chunksz, n - to_pos);

            if ( xencomm_copy_chunk_from((unsigned long)to + to_pos,
                                         src_paddr + chunk_skip, bytes) )
                goto out;
            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }

out:
    xencomm_ctxt_done(&ctxt);
    return n - to_pos;
}

static int
xencomm_copy_chunk_to(
    unsigned long paddr, unsigned long from, unsigned int  len)
{
    struct page_info *page;
    int res;

    do {
        res = xencomm_get_page(paddr, &page);
    } while ( res == -EAGAIN );

    if ( res )
        return res;

    xc_dprintk("%lx[%d] -> %lx\n", from, len,
               (unsigned long)xencomm_vaddr(paddr, page));

    memcpy(xencomm_vaddr(paddr, page), (void *)from, len);
    xencomm_mark_dirty((unsigned long)xencomm_vaddr(paddr, page), len);
    put_page(page);

    return 0;
}

static unsigned long
xencomm_inline_to_guest(
    void *to, const void *from, unsigned int n, unsigned int skip)
{
    unsigned long dest_paddr = xencomm_inline_addr(to) + skip;

    while ( n > 0 )
    {
        unsigned int chunksz, bytes;

        chunksz = PAGE_SIZE - (dest_paddr % PAGE_SIZE);
        bytes   = min(chunksz, n);

        if ( xencomm_copy_chunk_to(dest_paddr, (unsigned long)from, bytes) )
            return n;
        dest_paddr += bytes;
        from += bytes;
        n -= bytes;
    }

    /* Always successful. */
    return 0;
}

/**
 * xencomm_copy_to_guest: Copy a block of data to domain space.
 * @to:     Physical address to xencomm buffer descriptor.
 * @from:   Machine address.
 * @n:      Number of bytes to copy.
 * @skip: Number of bytes from the start to skip.
 *
 * Copy data from hypervisor to domain.
 *
 * Returns number of bytes that could not be copied.
 * On success, this will be zero.
 */
unsigned long
xencomm_copy_to_guest(
    void *to, const void *from, unsigned int n, unsigned int skip)
{
    struct xencomm_ctxt ctxt;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if ( xencomm_is_inline(to) )
        return xencomm_inline_to_guest(to, from, n, skip);

    if ( xencomm_ctxt_init(to, &ctxt) )
        return n;

    /* Iterate through the descriptor, copying up to a page at a time */
    while ( (from_pos < n) && (i < xencomm_ctxt_nr_addrs(&ctxt)) )
    {
        unsigned long dest_paddr;
        unsigned int pgoffset, chunksz, chunk_skip;

        if ( xencomm_ctxt_next(&ctxt, i) )
            goto out;
        dest_paddr = *xencomm_ctxt_address(&ctxt);
        if ( dest_paddr == XENCOMM_INVALID )
        {
            i++;
            continue;
        }

        pgoffset = dest_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, skip);
        to_pos += chunk_skip;
        chunksz -= chunk_skip;
        skip -= chunk_skip;

        if ( skip == 0 && chunksz > 0 )
        {
            unsigned int bytes = min(chunksz, n - from_pos);

            if ( xencomm_copy_chunk_to(dest_paddr + chunk_skip,
                                      (unsigned long)from + from_pos, bytes) )
                goto out;
            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }

out:
    xencomm_ctxt_done(&ctxt);
    return n - from_pos;
}

static int
xencomm_clear_chunk(
    unsigned long paddr, unsigned int  len)
{
    struct page_info *page;
    int res;

    do {
        res = xencomm_get_page(paddr, &page);
    } while ( res == -EAGAIN );

    if ( res )
        return res;

    memset(xencomm_vaddr(paddr, page), 0x00, len);
    xencomm_mark_dirty((unsigned long)xencomm_vaddr(paddr, page), len);
    put_page(page);

    return 0;
}

static unsigned long
xencomm_inline_clear_guest(
    void *to, unsigned int n, unsigned int skip)
{
    unsigned long dest_paddr = xencomm_inline_addr(to) + skip;

    while ( n > 0 )
    {
        unsigned int chunksz, bytes;

        chunksz = PAGE_SIZE - (dest_paddr % PAGE_SIZE);
        bytes   = min(chunksz, n);

        if ( xencomm_clear_chunk(dest_paddr, bytes) )
            return n;
        dest_paddr += bytes;
        n -= bytes;
    }

    /* Always successful. */
    return 0;
}

/**
 * xencomm_clear_guest: Clear a block of data in domain space.
 * @to:     Physical address to xencomm buffer descriptor.
 * @n:      Number of bytes to copy.
 * @skip: Number of bytes from the start to skip.
 *
 * Clear domain data
 *
 * Returns number of bytes that could not be cleared
 * On success, this will be zero.
 */
unsigned long
xencomm_clear_guest(
    void *to, unsigned int n, unsigned int skip)
{
    struct xencomm_ctxt ctxt;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if ( xencomm_is_inline(to) )
        return xencomm_inline_clear_guest(to, n, skip);

    if ( xencomm_ctxt_init(to, &ctxt) )
        return n;

    /* Iterate through the descriptor, copying up to a page at a time */
    while ( (from_pos < n) && (i < xencomm_ctxt_nr_addrs(&ctxt)) )
    {
        unsigned long dest_paddr;
        unsigned int pgoffset, chunksz, chunk_skip;

        if ( xencomm_ctxt_next(&ctxt, i) )
            goto out;
        dest_paddr = *xencomm_ctxt_address(&ctxt);
        if ( dest_paddr == XENCOMM_INVALID )
        {
            i++;
            continue;
        }

        pgoffset = dest_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, skip);
        to_pos += chunk_skip;
        chunksz -= chunk_skip;
        skip -= chunk_skip;

        if ( skip == 0 && chunksz > 0 )
        {
            unsigned int bytes = min(chunksz, n - from_pos);

            if ( xencomm_clear_chunk(dest_paddr + chunk_skip, bytes) )
                goto out;
            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }

out:
    xencomm_ctxt_done(&ctxt);
    return n - from_pos;
}

static int xencomm_inline_add_offset(void **handle, unsigned int bytes)
{
    *handle += bytes;
    return 0;
}

/* Offset page addresses in 'handle' to skip 'bytes' bytes. Set completely
 * exhausted pages to XENCOMM_INVALID. */
int xencomm_add_offset(void **handle, unsigned int bytes)
{
    struct xencomm_ctxt ctxt;
    int i = 0;
    int res = 0;

    if ( xencomm_is_inline(*handle) )
        return xencomm_inline_add_offset(handle, bytes);

    res = xencomm_ctxt_init(handle, &ctxt);
    if ( res != 0 )
        return res;

    /* Iterate through the descriptor incrementing addresses */
    while ( (bytes > 0) && (i < xencomm_ctxt_nr_addrs(&ctxt)) )
    {
        unsigned long *address;
        unsigned long dest_paddr;
        unsigned int pgoffset, chunksz, chunk_skip;

        res = xencomm_ctxt_next(&ctxt, i);
        if ( res )
            goto out;
        address = xencomm_ctxt_address(&ctxt);
        dest_paddr = *address;
        if ( dest_paddr == XENCOMM_INVALID )
        {
            i++;
            continue;
        }

        pgoffset = dest_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, bytes);
        if ( chunk_skip == chunksz )
            *address = XENCOMM_INVALID; /* exhausted this page */
        else
            *address += chunk_skip;
        bytes -= chunk_skip;

        i++;
    }

out:
    xencomm_ctxt_done(&ctxt);
    return res;
}

int xencomm_handle_is_null(void *handle)
{
    struct xencomm_ctxt ctxt;
    int i;
    int res = 1;

    if ( xencomm_is_inline(handle) )
        return xencomm_inline_addr(handle) == 0;

    if ( xencomm_ctxt_init(handle, &ctxt) )
        return 1;

    for ( i = 0; i < xencomm_ctxt_nr_addrs(&ctxt); i++ )
    {
        if ( xencomm_ctxt_next(&ctxt, i) )
            goto out;
        if ( *xencomm_ctxt_address(&ctxt) != XENCOMM_INVALID )
        {
            res = 0;
            goto out;
        }
    }

out:
    xencomm_ctxt_done(&ctxt);
    return res;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
