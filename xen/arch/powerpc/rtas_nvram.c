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

static int rtas_nvram_store(int token, struct rtas_args *ra)
{
    ulong length = ra->ra_args[2];
    char *buffer;
    char *local;
    struct rtas_args r;
    ulong sz = (3 + ra->ra_nargs + ra->ra_nrets) * sizeof (int);
    int ret;

    if (ra->ra_nargs != 3 || ra->ra_nrets != 2) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }

    /* the original pointer can be in memory that is too high so we
     * need to do it locally */
    buffer = rtas_remote_addr(ra->ra_args[1], length);
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
    r.ra_args[1] = (unsigned)(ulong)local;

    ret = rtas_call(&r);
    ra->ra_args[ra->ra_nargs] = r.ra_args[r.ra_nargs];
    ra->ra_args[ra->ra_nargs + 1] = r.ra_args[r.ra_nargs + 1];
    xfree(local);
    return ret;
}

struct rtas_token rt_nvram_store = {
    .name = "nvram-store",
    .proxy = rtas_nvram_store,
    .token = -1
};

static int rtas_nvram_fetch(int token, struct rtas_args *ra)
{
    ulong length = ra->ra_args[2];
    char *buffer;
    char *local;
    struct rtas_args r;
    ulong sz = (3 + ra->ra_nargs + ra->ra_nrets) * sizeof (int);
    int ret;

    if (ra->ra_nargs != 3 || ra->ra_nrets != 2) {
        ra->ra_args[ra->ra_nargs] = RTAS_PARAMETER;
        return -1;
    }
    /* the original pointer can be in ememory that is too high so
     * we need to do it locally */
    buffer = rtas_remote_addr(ra->ra_args[1], length);

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

    memcpy(&r, ra, sz);
    r.ra_token = token;
    r.ra_args[1] = (unsigned)(ulong)local;

    ret = rtas_call(&r);
    ra->ra_args[ra->ra_nargs] = r.ra_args[r.ra_nargs];
    ra->ra_args[ra->ra_nargs + 1] = r.ra_args[r.ra_nargs + 1];
    if (r.ra_args[r.ra_nargs] >= 0) {
        /* copy from local to remote */
        sz = r.ra_args[r.ra_nargs + 1];
        memcpy(buffer, local, sz);
    }
    xfree(local);
    return ret;
}

struct rtas_token rt_nvram_fetch = {
    .name = "nvram-fetch",
    .proxy = rtas_nvram_fetch,
    .token = -1
};

