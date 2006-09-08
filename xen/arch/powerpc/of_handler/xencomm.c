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
 */

#include "ofh.h"

static int __xencomm_init(struct xencomm_desc *desc, void *buffer,
        unsigned long bytes)
{
    int recorded = 0;
    int i = 0;

    /* record the physical pages used */
    while ((recorded < bytes) && (i < desc->nr_addrs)) {
        unsigned long paddr = (unsigned long)buffer + recorded;
        int offset;
        int chunksz;

        offset = (unsigned long)paddr % PAGE_SIZE; /* handle partial pages */
        chunksz = MIN(PAGE_SIZE - offset, (unsigned long)bytes - recorded);

        desc->address[i++] = paddr;
        recorded += chunksz;
    }

    if (recorded < bytes)
        return -1;

    desc->magic = XENCOMM_MAGIC;

    return 0;
}

static void *__xencomm_alloc_mini(void *area, int arealen)
{
    unsigned long base = (unsigned long)area;
    unsigned int left_in_page;

    left_in_page = PAGE_SIZE - base % PAGE_SIZE;

    /* we probably fit right at the front of area */
    if (left_in_page >= sizeof(struct xencomm_mini)) {
        return area;
    }

    /* if not, see if area is big enough to advance to the next page */
    if ((arealen - left_in_page) >= sizeof(struct xencomm_mini))
        return (void *)(base + left_in_page);

    /* area was too small */
    return NULL;
}

/* allocate a xencomm_mini out of a preallocated memory area */
int xencomm_create_mini(void *area, int arealen, void *buffer,
            unsigned long bytes, struct xencomm_desc **ret)
{
    struct xencomm_desc *desc = __xencomm_alloc_mini(area, arealen);
    if (!desc)
        return -1;

    desc->nr_addrs = XENCOMM_MINI_ADDRS;
    if (__xencomm_init(desc, buffer, bytes))
        return -1;

    *ret = desc;
    return 0;
}
