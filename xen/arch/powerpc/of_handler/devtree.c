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
#include <of-devtree.h> 

s32
ofh_peer(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            s32 *sib_ph = &retp[0];
            void *mem = ofd_mem(b);

            *sib_ph = ofd_node_peer(mem, ph);
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_child(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            s32 *ch_ph = &retp[0];
            void *mem = ofd_mem(b);

            *ch_ph = ofd_node_child(mem, ph);
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_parent(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            s32 *parent_ph = &retp[0];
            void *mem = ofd_mem(b);

            *parent_ph = ofd_node_parent(mem, ph);
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_instance_to_package(u32 nargs, u32 nrets, s32 argp[], s32 retp[],
        ulong b __attribute__ ((unused)))
{
    if (nargs == 1) {
        if (nrets == 1) {
            struct ofh_ihandle *ih =
                (struct ofh_ihandle *)(ulong)argp[0];
            s32 *p = &retp[0];

            *p = (s32)ih->ofi_node;
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_getproplen(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 2) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            const char *name = (const char *)(ulong)argp[1];
            s32 *size = &retp[0];
            void *mem = ofd_mem(b);

            *size = ofd_getproplen(mem, ph, name);
            if (*size >= 0) {
                return OF_SUCCESS;
            }
        }
    }
    return OF_FAILURE;
}

s32
ofh_getprop(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 4) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            const char *name = (const char *)(ulong)argp[1];
            void *buf = (void *)(ulong)argp[2];
            ulong buflen = argp[3];
            s32 *size = &retp[0];
            void *mem = ofd_mem(b);

            *size = ofd_getprop(mem, ph, name, buf, buflen);
            if (*size > 0) {
                return OF_SUCCESS;
            }
        }
    }
    return OF_FAILURE;
}

s32
ofh_nextprop(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            const char *prev = (const char *)(ulong)argp[1];
            char *name = (char *)(ulong)argp[2];
            s32 *flag = &retp[0];
            void *mem = ofd_mem(b);

            *flag = ofd_nextprop(mem, ph, prev, name);
            if (*flag > 0) {
                *flag = 1;
            }
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_setprop(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 4) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            const char *name = (const char *)(ulong)argp[1];
            const void *buf = (void *)(ulong)argp[2];
            ulong buflen = argp[3];
            s32 *size = &retp[0];
            void *mem = ofd_mem(b);

            *size = ofd_setprop(mem, ph, name, buf, buflen);
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_canon(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            const char *dev_spec = (const char *)(ulong)argp[0];
            char *buf = (char *)(ulong)argp[1];
            u32 sz = argp[2];
            s32 *len = &retp[0];
            void *mem = ofd_mem(b);
            ofdn_t ph;

            ph = ofd_node_find(mem, dev_spec);
            if (ph > 0) {
                *len = ofd_node_to_path(mem, ph, buf, sz);
                return OF_SUCCESS;
            }
        }
    }
    return OF_FAILURE;
}

s32 ofh_active_package = -1;

s32
ofh_finddevice(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 1) {
        if (nrets == 1) {
            s32 *ap = DRELA(&ofh_active_package, b);
            const char *devspec = (const char *)(ulong)argp[0];
            s32 *ph = &retp[0];
            void *mem = ofd_mem(b);

            /* good enuff */
            if (devspec[0] == '\0') {
                if (*ap == -1) {
                    *ph = -1;
                    return OF_FAILURE;
                }
                *ph = *ap;
            } else {
                *ph = ofd_node_find(mem, devspec);
                if (*ph <= 0) {
                    *ph = -1;
                    return OF_FAILURE;
                }
            }
            *ap = *ph;
            return OF_SUCCESS;
        }
    }
    return OF_FAILURE;
}

s32
ofh_instance_to_path(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            struct ofh_ihandle *ih =
                (struct ofh_ihandle *)((ulong)argp[0]);
            char *buf = (char *)(ulong)argp[1];
            u32 sz = argp[2];
            s32 *len = &retp[0];
            ofdn_t ph;
            void *mem = ofd_mem(b);

            ph = ih->ofi_node;
            if (ph > 0) {
                *len = ofd_node_to_path(mem, ph, buf, sz);
                return OF_SUCCESS;
            }
        }
    }
    return OF_FAILURE;
}

s32
ofh_package_to_path(u32 nargs, u32 nrets, s32 argp[], s32 retp[], ulong b)
{
    if (nargs == 3) {
        if (nrets == 1) {
            ofdn_t ph = argp[0];
            char *buf = (char *)(ulong)argp[1];
            u32 sz = argp[2];
            s32 *len = &retp[0];
            void *mem = ofd_mem(b);

            if (ph > 0) {
                *len = ofd_node_to_path(mem, ph, buf, sz);
                return OF_SUCCESS;
            }
        }
    }
    return OF_FAILURE;
}



