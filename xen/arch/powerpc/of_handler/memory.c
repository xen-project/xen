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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include "ofh.h"

struct of_malloc_s {
    u32 ofm_start;
    u32 ofm_end;
};
static struct of_malloc_s claimed[64];

static s32
claim(ulong b, u32 virt, u32 size, u32 align, s32 *baseaddr)
{
    struct of_malloc_s *cp;
    u32 i;
    s32 e;
    u32 end;

    if (align != 0) {
        /* we don't do this now */
        return OF_FAILURE;
    }

    end = virt + size;

    /* you cannot claim OF's own space */
    if (virt >= (u32)ofh_start && end < (u32)_end) {
        return OF_FAILURE;
    }

    cp = DRELA(&claimed[0], b);
    /* don't care about speed at the moment */
    e = -1;
    for (i = 0; i < sizeof (claimed)/sizeof (claimed[0]); i++) {
        if (cp[i].ofm_end == 0) {
            if (e == -1) {
                e = i;
            }
            continue;
        }
        if (virt >= cp[i].ofm_start && virt < cp[i].ofm_end) {
            return OF_FAILURE;
        }
        if (end >= cp[i].ofm_start && end < cp[i].ofm_end) {
            return OF_FAILURE;
        }
    }
    /* e points to the first empty */
    cp[e].ofm_start = virt;
    cp[e].ofm_end = end;
    *baseaddr = virt;
    return OF_SUCCESS;
}

s32
ofh_claim(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            u32 virt = argp[0];
            u32 size = argp[1];
            u32 align = argp[2];
            s32 *baseaddr = &retp[0];

            return claim(b, virt, size, align, baseaddr);
        }
    }
    return OF_FAILURE;
}

static s32
release(ulong b, u32 virt, u32 size)
{
    struct of_malloc_s *cp;
    u32 i;
    u32 end;

    end = virt + size;

    /* you cannot release OF's own space */
    if (virt >= (u32)ofh_start && end < (u32)_end) {
        return OF_FAILURE;
    }

    cp = DRELA(&claimed[0], b);
    /* don't care about speed at the moment */
    for (i = 0; i < sizeof (claimed)/sizeof (claimed[0]); i++) {
        if (virt == cp[i].ofm_start && end == cp[i].ofm_end) {
            cp[i].ofm_start = 0;
            cp[i].ofm_end = 0;
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_release(u32 nargs, u32 nrets, s32 argp[],
        s32 retp[] __attribute__ ((unused)),
        ulong b)
{
    if (nargs == 2) {
        if (nrets == 0) {
            u32 virt = argp[0];
            u32 size = argp[1];

            return release(b, virt, size);
        }
    }
    return OF_FAILURE;
}
