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
#define INVALIDATE_ALL

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <public/xen.h>
#include <asm/io.h>
#include <asm/current.h>
#include "tce.h"
#include "iommu.h"
#include "dart.h"

#define TOO_MANY_RETRIES ~0

union dart_ctl {
    u32 dc_word;
    struct {
        u32 dc_darten:1;      /* DART Enable (0:disabled) */
        u32 dc_ione:1;        /* Invalidate one DART TLB entry (using ILPN) */
        u32 dc_iall:1;        /* Invalidate all DART TLB entries */
        u32 dc_idle:1;        /* DART is idle */
        u32 dc_peen:1;        /* Parity Checking is enabled */
        u32 dc_ilpn:27;       /* 27-bit Logical Page Address for 
                               * invalidating one TLB entry */
    } dc_bits;
};

union dart_base {
    u32 db_word;
    struct {
        u32 _db_resv:8;
        u32 db_dartbase:24;     /* Base Address of DART (4K byte Alignment) */
    } db_bits;
};

union dart_size {
    u32 ds_word;
    struct {
        u32 _ds_resv:15;
        u32 ds_dartsize:17;     /* Size of Dart in 4K-Byte Pages */
    } ds_bits;
};

union dart_excp {
    u32 de_word;
    struct {
        u32 de_rqsrc:1;    /* Request Source.  [0:PCIE, 1:HT] */
        u32 de_lpn:27;     /* 27Ðbit Logical Address of Exception [25:51] */
        u32 de_rqop:1;     /* Request operation.  [0:Read, 1:Write] */
        u32 de_xcd:3;      /* Exception code */
    } de_bits;
};

struct dart {
    /* 0x00 */
    union dart_ctl d_dartcntl;
    u32 _pad0x04_0x10[3];
    /* 0x10 */
    union dart_base d_dartbase;
    u32 _pad0x14_0x20[3];
    /* 0x20 */
    union dart_size d_dartsize;
    u32 _pad0x24_0x30[3];
    /* 0x30 */
    union dart_excp d_dartexcp;
    u32 _pad0x34_0x40[3];
};

static volatile struct dart *dart;

static void u4_inv_all(void)
{
    union dart_ctl dc;
    ulong r = 0;
    int l = 0;

    for (;;) {
        dc.dc_word = in_32(&dart->d_dartcntl.dc_word);
        dc.dc_bits.dc_iall = 1;
        out_32(&dart->d_dartcntl.dc_word, dc.dc_word);

        do {
            dc.dc_word = in_32(&dart->d_dartcntl.dc_word);
            r++;
        } while ((dc.dc_bits.dc_iall == 1) && (r < (1 << l)));

        if (r == (1 << l)) {
            if (l < 4) {
                l++;
                dc.dc_word = in_32(&dart->d_dartcntl.dc_word);
                dc.dc_bits.dc_iall = 0;
                out_32(&dart->d_dartcntl.dc_word, dc.dc_word);
                continue;
            } else {
                panic(" broken U4???\n");
            }
        }
        return;
    }
}

static void u4_inv_entry(ulong pgn)
{
#ifdef INVALIDATE_ALL
    return u4_inv_all();
#else
    union dart_ctl dc;
    ulong retries = 0;

    return u4_inv_all();

    dc.dc_word = in_32(&dart->d_dartcntl.dc_word);
    dc.dc_bits.dc_ilpn = pgn;
    dc.dc_bits.dc_ione = 1;
    out_32(&dart->d_dartcntl.dc_word, dc.dc_word);

    /* wait for completion */
    /* FIXME: since we do this from the HV do we need to wait?! */
    do {
        dc.dc_word = in_32(&dart->d_dartcntl.dc_word);
        retries++;
        if (retries > 1000000)
            panic("WAY! too long\n");
    } while (dc.dc_bits.dc_ione != 0);
#endif
}

static struct dart_ops u4_ops = {
    .do_inv_all = u4_inv_all,
    .do_inv_entry = u4_inv_entry,
};

struct dart_ops *u4_init(ulong base, ulong table, ulong dart_pages)
{
    union dart_base db;
    union dart_size ds;
    union dart_ctl dc;

    dart = (struct dart *)base;

    db.db_word = 0;
    db.db_bits.db_dartbase = table >> PAGE_SHIFT;

    ds.ds_word = 0;
    ds.ds_bits.ds_dartsize = dart_pages;

    dc.dc_word = in_32(&dart->d_dartcntl.dc_word);
    if (dc.dc_bits.dc_darten == 1) {
        panic("%s: dart is already enabled: 0x%x\n", __func__, dc.dc_word);
    }
    dc.dc_bits.dc_darten = 1;   /* enable it */

    printk("Initializing DART Model U4: ctl: 0x%x base: 0x%x size: 0x%x\n",
           dc.dc_word, db.db_word, ds.ds_word);

    out_32(&dart->d_dartbase.db_word, db.db_word);
    out_32(&dart->d_dartsize.ds_word, ds.ds_word);
    out_32(&dart->d_dartcntl.dc_word, dc.dc_word);

    return &u4_ops;
}
