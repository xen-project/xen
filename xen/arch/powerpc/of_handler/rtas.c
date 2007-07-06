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

#include "ofh.h"
#include <stdarg.h>
#include <xen/lib.h>
extern char _rtas_image_start[];
extern char _rtas_image_end[];

static int
rtas_instantiate_rtas(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 1) {
            void *rtas_base_address = (void *)(ulong)argp[0];
            u32 sz = (_rtas_image_end - _rtas_image_start);

            memcpy(rtas_base_address,
                   DRELA(&_rtas_image_start[0], b), sz);
            retp[0] = (ulong)rtas_base_address;

            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}


static struct ofh_methods _rtas_methods[] = {
    { "instantiate-rtas", rtas_instantiate_rtas },
    { NULL, NULL},
};

static struct ofh_ihandle _ih_rtas = {
    .ofi_methods = _rtas_methods,
};

static int rtas_open(u32 b)
{
    u32 ih = DRELA((u32)&_ih_rtas, b);

    return ih;
}

void ofh_rtas_init(ulong b)
{
    static const char path[] = "/rtas";
    ofdn_t n;
    void *m = ofd_mem(b);
    u32 sz;

    n = ofd_node_find(m, DRELA(&path[0], b));
    if (n <= 0)
        return;

    sz = (_rtas_image_end - _rtas_image_start);
    /* Round size up to a multiple of 0x1000 */
    sz = ALIGN_UP(sz, PAGE_SIZE);

    ofd_prop_add(m, n, DRELA((const char *)"rtas-size", b),
                 &sz, sizeof(sz));

    /* create an IO node */
    ofd_io_create(m, n, (ulong)rtas_open);
}
