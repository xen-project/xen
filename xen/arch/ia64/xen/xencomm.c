/*
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
 */

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/guest_access.h>
#include <public/xen.h>
#include <public/xencomm.h>
#include <xen/errno.h>

#undef DEBUG
#ifdef DEBUG
static int xencomm_debug = 1; /* extremely verbose */
#else
#define xencomm_debug 0
#endif

static int
xencomm_copy_chunk_from(
    unsigned long to,
    unsigned long paddr,
    unsigned int  len)
{
    unsigned long maddr;
    struct page_info *page;

    while (1) {
	maddr = xencomm_paddr_to_maddr(paddr);
	if (xencomm_debug > 1)
	    printk("%lx[%d] -> %lx\n", maddr, len, to);
	if (maddr == 0)
	    return -EFAULT;

	page = virt_to_page(maddr);
	if (get_page(page, current->domain) == 0) {
	    if (page_get_owner(page) != current->domain) {
		/* This page might be a page granted by another domain  */
		panic_domain(NULL, "copy_from_guest from foreign domain\n");
	    }
	    /* Try again.  */
	    continue;
	}
	memcpy((void *)to, (void *)maddr, len);
	put_page(page);
	return 0;
    }
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
    void         *to,
    const void   *from,
    unsigned int n,
    unsigned int skip)
{
    struct xencomm_desc *desc;
    unsigned long desc_addr;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if (xencomm_debug)
        printk("xencomm_copy_from_guest: from=%lx+%u n=%u\n",
               (unsigned long)from, skip, n);

    if (XENCOMM_IS_INLINE(from)) {
        unsigned long src_paddr = XENCOMM_INLINE_ADDR(from);
            
        src_paddr += skip;

        while (n > 0) {
            unsigned int chunksz;
            unsigned int bytes;
	    int res;
            
            chunksz = PAGE_SIZE - (src_paddr % PAGE_SIZE);
            
            bytes = min(chunksz, n);

            res = xencomm_copy_chunk_from((unsigned long)to, src_paddr, bytes);
	    if (res != 0)
		return -EFAULT;
            src_paddr += bytes;
            to += bytes;
            n -= bytes;
        }
        
        /* Always successful.  */
        return 0;
    }

    /* first we need to access the descriptor */
    desc_addr = xencomm_paddr_to_maddr((unsigned long)from);
    if (desc_addr == 0)
        return -EFAULT;

    desc = (struct xencomm_desc *)desc_addr;
    if (desc->magic != XENCOMM_MAGIC) {
        printk("%s: error: %p magic was 0x%x\n",
               __func__, desc, desc->magic);
        return -EFAULT;
    }

    /* iterate through the descriptor, copying up to a page at a time */
    while ((to_pos < n) && (i < desc->nr_addrs)) {
        unsigned long src_paddr = desc->address[i];
        unsigned int pgoffset;
        unsigned int chunksz;
        unsigned int chunk_skip;

        if (src_paddr == XENCOMM_INVALID) {
            i++;
            continue;
        }

        pgoffset = src_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, skip);
        from_pos += chunk_skip;
        chunksz -= chunk_skip;
        skip -= chunk_skip;

        if (skip == 0 && chunksz > 0) {
            unsigned int bytes = min(chunksz, n - to_pos);
	    int res;

            if (xencomm_debug > 1)
                printk ("src_paddr=%lx i=%d, skip=%d\n",
                        src_paddr, i, chunk_skip);

            res = xencomm_copy_chunk_from((unsigned long)to + to_pos,
                                          src_paddr + chunk_skip, bytes);
            if (res != 0)
                return -EFAULT;

            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }

    return n - to_pos;
}

static int
xencomm_copy_chunk_to(
    unsigned long paddr,
    unsigned long from,
    unsigned int  len)
{
    unsigned long maddr;
    struct page_info *page;

    while (1) {
	maddr = xencomm_paddr_to_maddr(paddr);
	if (xencomm_debug > 1)
	    printk("%lx[%d] -> %lx\n", from, len, maddr);
	if (maddr == 0)
	    return -EFAULT;

	page = virt_to_page(maddr);
	if (get_page(page, current->domain) == 0) {
	    if (page_get_owner(page) != current->domain) {
		/* This page might be a page granted by another domain  */
		panic_domain(NULL, "copy_to_guest to foreign domain\n");
	    }
	    /* Try again.  */
	    continue;
	}
	memcpy((void *)maddr, (void *)from, len);
	put_page(page);
	return 0;
    }
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
    void         *to,
    const void   *from,
    unsigned int n,
    unsigned int skip)
{
    struct xencomm_desc *desc;
    unsigned long desc_addr;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if (xencomm_debug)
        printk ("xencomm_copy_to_guest: to=%lx+%u n=%u\n",
                (unsigned long)to, skip, n);

    if (XENCOMM_IS_INLINE(to)) {
        unsigned long dest_paddr = XENCOMM_INLINE_ADDR(to);
            
        dest_paddr += skip;

        while (n > 0) {
            unsigned int chunksz;
            unsigned int bytes;
            int res;

            chunksz = PAGE_SIZE - (dest_paddr % PAGE_SIZE);
            
            bytes = min(chunksz, n);

            res = xencomm_copy_chunk_to(dest_paddr, (unsigned long)from, bytes);
            if (res != 0)
                return res;

            dest_paddr += bytes;
            from += bytes;
            n -= bytes;
        }

        /* Always successful.  */
        return 0;
    }

    /* first we need to access the descriptor */
    desc_addr = xencomm_paddr_to_maddr((unsigned long)to);
    if (desc_addr == 0)
        return -EFAULT;

    desc = (struct xencomm_desc *)desc_addr;
    if (desc->magic != XENCOMM_MAGIC) {
        printk("%s error: %p magic was 0x%x\n", __func__, desc, desc->magic);
        return -EFAULT;
    }

    /* iterate through the descriptor, copying up to a page at a time */
    while ((from_pos < n) && (i < desc->nr_addrs)) {
        unsigned long dest_paddr = desc->address[i];
        unsigned int pgoffset;
        unsigned int chunksz;
        unsigned int chunk_skip;

        if (dest_paddr == XENCOMM_INVALID) {
            i++;
            continue;
        }

        pgoffset = dest_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, skip);
        to_pos += chunk_skip;
        chunksz -= chunk_skip;
        skip -= chunk_skip;
        dest_paddr += chunk_skip;

        if (skip == 0 && chunksz > 0) {
            unsigned int bytes = min(chunksz, n - from_pos);
            int res;

            res = xencomm_copy_chunk_to(dest_paddr,
                                        (unsigned long)from + from_pos, bytes);
            if (res != 0)
                return res;

            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }
    return n - from_pos;
}

/* Offset page addresses in 'handle' to skip 'bytes' bytes. Set completely
 * exhausted pages to XENCOMM_INVALID. */
void *
xencomm_add_offset(
    void         *handle,
    unsigned int bytes)
{
    struct xencomm_desc *desc;
    unsigned long desc_addr;
    int i = 0;

    if (XENCOMM_IS_INLINE(handle))
        return (void *)((unsigned long)handle + bytes);

    /* first we need to access the descriptor */
    desc_addr = xencomm_paddr_to_maddr((unsigned long)handle);
    if (desc_addr == 0)
        return NULL;

    desc = (struct xencomm_desc *)desc_addr;
    if (desc->magic != XENCOMM_MAGIC) {
        printk("%s error: %p magic was 0x%x\n", __func__, desc, desc->magic);
        return NULL;
    }

    /* iterate through the descriptor incrementing addresses */
    while ((bytes > 0) && (i < desc->nr_addrs)) {
        unsigned long dest_paddr = desc->address[i];
        unsigned int pgoffset;
        unsigned int chunksz;
        unsigned int chunk_skip;

        if (dest_paddr == XENCOMM_INVALID) {
            i++;
            continue;
        }

        pgoffset = dest_paddr % PAGE_SIZE;
        chunksz = PAGE_SIZE - pgoffset;

        chunk_skip = min(chunksz, bytes);
        if (chunk_skip == chunksz) {
            /* exhausted this page */
            desc->address[i] = XENCOMM_INVALID;
        } else {
            desc->address[i] += chunk_skip;
        }
        bytes -= chunk_skip;
	
	i++;
    }
    return handle;
}

int
xencomm_handle_is_null(
   void *ptr)
{
    if (XENCOMM_IS_INLINE(ptr))
        return XENCOMM_INLINE_ADDR(ptr) == 0;
    else {
        struct xencomm_desc *desc;
        unsigned long desc_addr;

        desc_addr = xencomm_paddr_to_maddr((unsigned long)ptr);
        if (desc_addr == 0)
            return 1;

        desc = (struct xencomm_desc *)desc_addr;
        return (desc->nr_addrs == 0);
    }
}
