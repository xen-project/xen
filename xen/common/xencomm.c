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
#include <xen/xencomm.h>
#include <public/xen.h>
#include <public/xencomm.h>


#undef DEBUG
#ifdef DEBUG
static int xencomm_debug = 1; /* extremely verbose */
#else
#define xencomm_debug 0
#endif

static unsigned long
xencomm_inline_from_guest(void *to, const void *from, unsigned int n,
        unsigned int skip)
{
    unsigned long src_paddr = xencomm_inline_addr(from);

    src_paddr += skip;

    while (n > 0) {
        unsigned int chunksz;
        unsigned long src_maddr;
        unsigned int bytes;

        chunksz = PAGE_SIZE - (src_paddr % PAGE_SIZE);

        bytes = min(chunksz, n);

        src_maddr = paddr_to_maddr(src_paddr);
        if (xencomm_debug)
            printk("%lx[%d] -> %lx\n", src_maddr, bytes, (unsigned long)to);
        memcpy(to, (void *)src_maddr, bytes);
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
xencomm_copy_from_guest(void *to, const void *from, unsigned int n,
        unsigned int skip)
{
    struct xencomm_desc *desc;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if (xencomm_is_inline(from))
        return xencomm_inline_from_guest(to, from, n, skip);

    /* first we need to access the descriptor */
    desc = (struct xencomm_desc *)paddr_to_maddr((unsigned long)from);
    if (desc == NULL)
        return n;

    if (desc->magic != XENCOMM_MAGIC) {
        printk("%s: error: %p magic was 0x%x\n",
               __func__, desc, desc->magic);
        return n;
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
            unsigned long src_maddr;
            unsigned long dest = (unsigned long)to + to_pos;
            unsigned int bytes = min(chunksz, n - to_pos);

            src_maddr = paddr_to_maddr(src_paddr + chunk_skip);
            if (src_maddr == 0)
                return n - to_pos;

            if (xencomm_debug)
                printk("%lx[%d] -> %lx\n", src_maddr, bytes, dest);
            memcpy((void *)dest, (void *)src_maddr, bytes);
            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }

    return n - to_pos;
}

static unsigned long
xencomm_inline_to_guest(void *to, const void *from, unsigned int n,
        unsigned int skip)
{
    unsigned long dest_paddr = xencomm_inline_addr(to);

    dest_paddr += skip;

    while (n > 0) {
        unsigned int chunksz;
        unsigned long dest_maddr;
        unsigned int bytes;

        chunksz = PAGE_SIZE - (dest_paddr % PAGE_SIZE);

        bytes = min(chunksz, n);

        dest_maddr = paddr_to_maddr(dest_paddr);
        if (xencomm_debug)
            printk("%lx[%d] -> %lx\n", (unsigned long)from, bytes, dest_maddr);
        memcpy((void *)dest_maddr, (void *)from, bytes);
        dest_paddr += bytes;
        from += bytes;
        n -= bytes;
    }

    /* Always successful.  */
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
xencomm_copy_to_guest(void *to, const void *from, unsigned int n,
        unsigned int skip)
{
    struct xencomm_desc *desc;
    unsigned int from_pos = 0;
    unsigned int to_pos = 0;
    unsigned int i = 0;

    if (xencomm_is_inline(to))
        return xencomm_inline_to_guest(to, from, n, skip);

    /* first we need to access the descriptor */
    desc = (struct xencomm_desc *)paddr_to_maddr((unsigned long)to);
    if (desc == NULL)
        return n;

    if (desc->magic != XENCOMM_MAGIC) {
        printk("%s error: %p magic was 0x%x\n", __func__, desc, desc->magic);
        return n;
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

        if (skip == 0 && chunksz > 0) {
            unsigned long dest_maddr;
            unsigned long source = (unsigned long)from + from_pos;
            unsigned int bytes = min(chunksz, n - from_pos);

            dest_maddr = paddr_to_maddr(dest_paddr + chunk_skip);
            if (dest_maddr == 0)
                return -1;

            if (xencomm_debug)
                printk("%lx[%d] -> %lx\n", source, bytes, dest_maddr);
            memcpy((void *)dest_maddr, (void *)source, bytes);
            from_pos += bytes;
            to_pos += bytes;
        }

        i++;
    }

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
    struct xencomm_desc *desc;
    int i = 0;

    if (xencomm_is_inline(*handle))
        return xencomm_inline_add_offset(handle, bytes);

    /* first we need to access the descriptor */
    desc = (struct xencomm_desc *)paddr_to_maddr((unsigned long)*handle);
    if (desc == NULL)
        return -1;

    if (desc->magic != XENCOMM_MAGIC) {
        printk("%s error: %p magic was 0x%x\n", __func__, desc, desc->magic);
        return -1;
    }

    /* iterate through the descriptor incrementing addresses */
    while ((bytes > 0) && (i < desc->nr_addrs)) {
        unsigned long dest_paddr = desc->address[i];
        unsigned int pgoffset;
        unsigned int chunksz;
        unsigned int chunk_skip;

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
    }
    return 0;
}

int xencomm_handle_is_null(void *handle)
{
    struct xencomm_desc *desc;
    int i;

    if (xencomm_is_inline(handle))
        return xencomm_inline_addr(handle) == 0;

    desc = (struct xencomm_desc *)paddr_to_maddr((unsigned long)handle);
    if (desc == NULL)
        return 1;

    for (i = 0; i < desc->nr_addrs; i++)
        if (desc->address[i] != XENCOMM_INVALID)
            return 0;

    return 1;
}

