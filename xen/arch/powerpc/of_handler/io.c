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
#include "xen/lib.h"

s32
ofh_open(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 1) {
            const char *devspec = (const char *)(ulong)argp[0];
            s32 *ih = &retp[0];
            ofdn_t p;
            void *mem = ofd_mem(b);

            p = ofd_node_find(mem, devspec);
            if (p > 0) {
                ofdn_t io;
                io = ofd_node_io(mem, p);
                if (io > 0) {
                    void *f = (void *)(ulong)ofd_io_open(mem, io);
                    if (f != 0) {
                        *ih = leap(b, 0, NULL, NULL,
                                   b, f);
                        return OF_SUCCESS;
                    }
                }
            }
            *ih = 0;
        }
    }
    return OF_FAILURE;
}

s32
ofh_close(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 0) {
            argp = argp;
            retp = retp;
            b = b;
            return  OF_FAILURE;
        }
    }
    return OF_FAILURE;
}
s32
ofh_read(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            struct ofh_ihandle *ih =
                (struct ofh_ihandle *)(ulong)argp[0];

            if (ih->ofi_read != NULL) {
                void *addr = (void *)(ulong)argp[1];
                u32 sz = argp[2];
                s32 *actual = &retp[0];
                void *f = ih->ofi_read;

                if (f != 0) {
                    return io_leap(ih->ofi_chan, addr, sz, actual,
                                b, f);
                }
            }
        }
    }
    return OF_FAILURE;
}

s32
ofh_write(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            struct ofh_ihandle *ih =
                (struct ofh_ihandle *)(ulong)argp[0];

            if (ih->ofi_write != NULL) {
                void *addr = (void *)(ulong)argp[1];
                u32 sz = argp[2];
                s32 *actual = &retp[0];
                void *f = ih->ofi_write;

                if (f != 0) {
                    return io_leap(ih->ofi_chan, addr, sz, actual,
                                b, f);
                }
            }
        }
    }
    return OF_FAILURE;
}

s32
ofh_seek(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    b=b;
    nargs = nargs;
    nrets = nrets;
    argp = argp;
    retp = retp;
    return OF_FAILURE;
}

static ofh_func_t *
method_lookup(struct ofh_ihandle *ih, const char *name, ulong b)
{
    struct ofh_methods *m = DRELA(ih->ofi_methods, b);

    while (m != NULL && m->ofm_name != NULL ) {
        if (strcmp(name, DRELA(m->ofm_name, b)) == 0) {
            return m->ofm_method;
        }
    }
    return NULL;
}


s32
ofh_call_method(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs > 2) {
        if (nrets > 1) {
            const char *method = (const char *)(ulong)argp[0];
            struct ofh_ihandle *ih =
                (struct ofh_ihandle *)(ulong)argp[1];
            ofh_func_t *f;

            f = method_lookup(ih, method, b);
            if (f != NULL) {
                /* set catch methods return 0 on success */
                retp[0] = leap(nargs - 2, nrets - 1,
                               &argp[2], &retp[1], b, f);
                return OF_SUCCESS;
            }
        }
    }
    return OF_FAILURE;
}

