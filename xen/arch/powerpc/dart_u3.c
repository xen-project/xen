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

#undef DEBUG

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <public/xen.h>
#include <asm/io.h>
#include <asm/current.h>
#include "tce.h"
#include "iommu.h"
#include "dart.h"

union dart_ctl {
    u32 dc_word;
    struct {
        u32 dc_base:20;
        u32 dc_stop_access:1;
        u32 dc_invtlb:1;
        u32 dc_enable:1;
        u32 dc_size:9;
    } reg;
};

static u32 volatile *dart_ctl_reg;

static void u3_inv_all(void)
{
    union dart_ctl dc;
    ulong r = 0;
    int l = 0;

    for (;;) {
        dc.dc_word = in_32(dart_ctl_reg);
        dc.reg.dc_invtlb = 1;
        out_32(dart_ctl_reg, dc.dc_word);

        do {
            dc.dc_word = in_32(dart_ctl_reg);
            r++;
        } while ((dc.reg.dc_invtlb == 1) && (r < (1 << l)));

        if (r == (1 << l)) {
            if (l < 4) {
                l++;
                dc.dc_word = in_32(dart_ctl_reg);
                dc.reg.dc_invtlb = 0;
                out_32(dart_ctl_reg, dc.dc_word);
                continue;
            } else {
                panic(" broken U3???\n");
            }
        }
        return;
    }
}

static void u3_inv_entry(ulong pg)
{
    /* sadly single entry invalidation has been reported not to work */
    u3_inv_all();
}

static struct dart_ops u3_ops = {
    .do_inv_all = u3_inv_all,
    .do_inv_entry = u3_inv_entry,
};

struct dart_ops *u3_init(ulong base, ulong table, ulong dart_pages)
{
    union dart_ctl dc;

    dart_ctl_reg = (u32 *)base;

    dc.dc_word = 0;

    dc.reg.dc_base = table >> PAGE_SHIFT;
    dc.reg.dc_size = dart_pages;
    dc.reg.dc_enable = 1;


    printk("Initializing DART Model U3: reg: %p word: %x\n",
           dart_ctl_reg, dc.dc_word);

    out_32(dart_ctl_reg, dc.dc_word);

    return &u3_ops;
}
