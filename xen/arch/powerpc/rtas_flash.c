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
 * Copyright (C) IBM Corp. 2007
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include "rtas.h"

static int rtas_manage_flash(int token, struct rtas_args *ra)
{
    struct rtas_args r;
    ulong sz = (3 + ra->ra_nargs + ra->ra_nrets) * sizeof (int);
    int ret;

    if (ra->ra_nargs != 1 || ra->ra_nrets != 1) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }
    memcpy(&r, ra, sz);
    r.ra_token = token;

    ret = rtas_call(&r);
    ra->ra_args[ra->ra_nargs] = r.ra_args[r.ra_nargs];
    return ret;
}
struct rtas_token rt_manage_flash = {
    .name = "ibm,manage-flash-image",
    .proxy = rtas_manage_flash,
    .token = -1
};

static int rtas_validate_flash(int token, struct rtas_args *ra)
{
    ulong length = ra->ra_args[1];
    char *buffer;
    char *local;
    struct rtas_args r;
    ulong sz = (3 + ra->ra_nargs + ra->ra_nrets) * sizeof (int);
    int ret;

    if (ra->ra_nargs != 2 || ra->ra_nrets != 2) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }

    /* the original pointer can be in memory that is too high so we
     * need to do it locally */
    buffer = rtas_remote_addr(ra->ra_args[0], length);
    if (buffer == NULL) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }
        
    local = xmalloc_bytes(length);
    if (local == NULL) {
        printk("%s: could not allocate local buffer size: 0x%lx\n",
               __func__, length);
        ra->ra_args[ra->ra_nargs] = RTAS_HW;
        return -1;
    }
    /* RTAS is 32bits so we need to make sure that that local
     * buffer is in that range */
    BUG_ON(((ulong)local + length) & ~0xffffffffUL);

    /* copy the remote buffer to the local one */
    memcpy(local, buffer, length);

    memcpy(&r, ra, sz);
    r.ra_token = token;
    r.ra_args[0] = (unsigned)(ulong)local;
    ret = rtas_call(&r);
    ra->ra_args[ra->ra_nargs] = r.ra_args[r.ra_nargs];
    ra->ra_args[ra->ra_nargs + 1] = r.ra_args[r.ra_nargs + 1];
    xfree(local);
    return ret;
}

struct rtas_token rt_validate_flash = {
    .name = "ibm,validate-flash-image",
    .proxy = rtas_validate_flash,
    .token = -1
};

/* flash data structs */
struct flash_block {
    u64 addr;
    u64 length;
};
struct flash_block_list {
    struct {
        u64 ver:8;
        u64 bytes:56;
    } header;
    u64 *next;
    struct flash_block blocks[0];
};

static int safe_to_flash;
static int rtas_update_reboot_flash(int token, struct rtas_args *ra)
{
    struct rtas_args r;
    ulong sz = (3 + ra->ra_nargs + ra->ra_nrets) * sizeof (int);
    int ret;
    void *local;
    struct flash_block_list *l;
    ulong blocks;
    
    if (ra->ra_nargs != 1 || ra->ra_nrets != 1) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }

    if (!safe_to_flash) {
        printk("%s: this has not been fully tested yet\n", __func__);
        ra->ra_args[ra->ra_nargs] = RTAS_HW;
        return -1;
    }

    /* we only need to relocate the first block address to 4G, for now
     * lets just bug on that */
    local = rtas_remote_addr(ra->ra_args[0], 16);
    BUG_ON((ulong)local & ~0xffffffffUL);

    /* now we run through the block list and translate base addresses */
    l = (struct flash_block_list *)local;

    /* header and next count as one block */
    blocks = (l->header.bytes / sizeof (struct flash_block)) - 1;
    if (blocks == 0) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }

    /* go thru the block lists */
    do {
        int i = 0;

        /* go thru the block in the list */
        for (i = 0; i < blocks; i++) {
            void *addr;

            addr = rtas_remote_addr(l->blocks[i].addr, l->blocks[i].length);
            BUG_ON(addr == NULL);
            l->blocks[i].addr = (u64)addr;
        }
        l = (struct flash_block_list *)l->next;
    } while (l != NULL);

    memcpy(&r, ra, sz);
    r.ra_token = token;

    /* this arguement is a pointer to a block list */
    r.ra_args[0] = (unsigned)(ulong)local;

    ret = rtas_call(&r);
    ra->ra_args[ra->ra_nargs] = r.ra_args[r.ra_nargs];
    return ret;
}

struct rtas_token rt_update_reboot_flash = {
    .name = "ibm,update-flash-64-and-reboot",
    .proxy = rtas_update_reboot_flash,
    .token = -1
};
