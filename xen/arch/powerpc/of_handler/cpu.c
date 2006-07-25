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
ofh_start_cpu(u32 nargs, u32 nrets, s32 argp[],
        s32 retp[] __attribute__ ((unused)),
        ulong b __attribute__ ((unused)))
{
    if (nargs == 3) {
        if (nrets == 0) {
            ofdn_t ph = argp[0];
            u32 pc = argp[1];
            u32 arg = argp[2];

            (void)ph; (void)pc; (void)arg;
            return OF_FAILURE;
        }
    }
    return OF_FAILURE;
}

s32
ofh_stop_self(u32 nargs, u32 nrets,
        s32 argp[] __attribute__ ((unused)),
        s32 retp[] __attribute__ ((unused)),
        ulong b __attribute__ ((unused)))
{
    if (nargs == 0) {
        if (nrets == 0) {
            return OF_FAILURE;
        }
    }
    return OF_FAILURE;
}

s32
ofh_idle_self(u32 nargs, u32 nrets,
        s32 argp[] __attribute__ ((unused)),
        s32 retp[] __attribute__ ((unused)),
        ulong b __attribute__ ((unused)))
{
    if (nargs == 0) {
        if (nrets == 0) {
            return OF_FAILURE;
        }
    }
    return OF_FAILURE;
}
s32
ofh_resume_cpu(u32 nargs, u32 nrets, s32 argp[],
        s32 retp[] __attribute__ ((unused)),
        ulong b __attribute__ ((unused)))
{
    if (nargs == 1) {
        if (nrets == 0) {
            ofdn_t ph = argp[0];

            (void)ph;
            return OF_FAILURE;
        }
    }
    return OF_FAILURE;
}
