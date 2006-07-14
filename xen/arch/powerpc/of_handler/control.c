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

s32
ofh_boot(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    b=b;
    nargs = nargs;
    nrets = nrets;
    argp = argp;
    retp = retp;
    return OF_FAILURE;
}

s32
ofh_enter(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    b=b;
    nargs = nargs;
    nrets = nrets;
    argp = argp;
    retp = retp;
    return OF_FAILURE;
}

s32
ofh_exit(u32 nargs __attribute__ ((unused)),
        u32 nrets  __attribute__ ((unused)),
        s32 argp[]  __attribute__ ((unused)),
        s32 retp[] __attribute__ ((unused)),
        ulong b)
{
    static const char msg[] = "OFH: exit method called\n";
    s32 dummy;

    ofh_cons_write(DRELA(&msg[0], b), sizeof (msg), &dummy);

    for (;;) {
        /* kill domain here */
    }
    return OF_FAILURE;
}

s32
ofh_chain(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    b=b;
    nargs = nargs;
    nrets = nrets;
    argp = argp;
    retp = retp;
    return OF_FAILURE;
}

s32
ofh_quiesce(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 0) {
        if (nrets == 0) {
            void *mem = ofd_mem(b);
            (void)nargs;
            (void)nrets;
            (void)argp;
            (void)retp;
            (void)mem;

            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}
