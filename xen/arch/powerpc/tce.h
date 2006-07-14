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

#ifndef _TCE_H
#define _TCE_H

#include <xen/config.h>
#include <xen/types.h>

union tce {
    u64 tce_dword;
    struct tce_bits {
        /* the bits here reflect the definition in Linux */
        /* the RPA considers all 52 bits to be the RPN */
        u64 tce_cache   : 6;
        u64 _tce_r0     : 6; /* reserved */
        u64 tce_rpn     :40; /* Real Page Number */

        /* The RPA considers the next 10 bits reserved */
        u64 tce_v       : 1; /* Valid bit */
        u64 tce_vlps    : 1; /* Valid for LPs */
        u64 tce_lpx     : 8; /* LP index */

        /* the RPA defines the following two bits as:
         *   00: no access
         *   01: System Address read only
         *   10: System Address write only
         *   11: read/write
         */
        u64 tce_write   : 1;
        u64 tce_read    : 1;
    } tce_bits;
};

union tce_bdesc {
    u64 lbd_dword;
    struct lbd_bits {
        u64 lbd_ctrl_v          : 1;
        u64 lbd_ctrl_vtoggle    : 1;
        u64 _lbd_ctrl_res0      : 6;
        u64 lbd_len             :24;
        u64 lbd_addr            :32;
    } lbd_bits;
};

struct tce_data {
    ulong t_entries;
    ulong t_base;
    ulong t_alloc_size;
    union tce *t_tce;
};

#endif /* _TCE_H */

