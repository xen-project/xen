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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/cache.h>
#include <xen/init.h>
#include "tce.h"
#include "iommu.h"
#include "dart.h"
#include "oftree.h"
#include "of-devtree.h"

#undef DEBUG
#ifdef DEBUG
#define DBG(fmt...) printk(fmt)
static int dbg_after;
#define DBG_SET_AFTER dbg_after = 1;
#define DBG_AFTER(fmt...) if (dbg_after) DBG(fmt)
#else
#define DBG(fmt...)
#define DBG_SET_AFTER
#define DBG_AFTER(fmt...)
#endif

/* Max size of 512 pages */
#define U3_LOG_MAX_PAGES 9

#define DART_DEF_BASE   0xf8033000UL
#define DART_NONE 0
#define DART_U3 3
#define DART_U4 4
#define DART_WRITE 0x1
#define DART_READ 0x2

static ulong dummy_page;
static ulong dart_entries;
static struct dart_ops *dops;
static u32 *dart_table;

union dart_entry {
    u32 de_word;
    struct {
        u32 de_v:1;             /* valid */
        u32 de_rp:1;             /* read protected */
        u32 de_wp:1;             /* write protected */
        u32 _de_res:5;
        u32 de_ppn:24;         /* 24 bit Physical Page Number
                                 * representing address [28:51] */
    } de_bits;
};

struct dma_window {
    u32 dw_liobn;
    u32 dw_base_hi;
    u64 dw_base;
    u64 dw_size;
};

struct dart_info {
    struct dma_window di_window;
    ulong di_base;
    int di_model;
};

static u32 dart_encode(int perm, ulong rpn)
{
    union dart_entry e;

    e.de_word = 0;
    e.de_bits.de_v = 1;
    e.de_bits.de_ppn = rpn;

    /* protect the page */
    e.de_bits.de_rp = 1;
    e.de_bits.de_wp = 1;
    if (perm & DART_READ) {
        e.de_bits.de_rp = 0;
    }
    if (perm & DART_WRITE) {
        e.de_bits.de_wp = 0;
    }
    return e.de_word;
}

static void dart_fill(ulong index, int perm, ulong rpg, ulong num_pg)
{
    u32 volatile *entry = dart_table + index;
    ulong i = 0;
    ulong last_flush = 0;

    while (1) {
        entry[i] = dart_encode(perm, rpg);
        ++i;
        ++rpg;
        if (i == num_pg) break;

        if ((((ulong)&entry[i]) % cpu_caches.dline_size) == 0) {
            last_flush = (ulong)&entry[i - 1];
            dcbst(last_flush);
        }
    }
    dcbst((ulong) &entry[i - 1]);
}

static void dart_clear(ulong index, ulong num_pg)
{
    u32 *entry = dart_table + index;
    ulong i = 0;
    ulong rpg = dummy_page;
    ulong last_flush = 0;

    while (1) {
        entry[i] = dart_encode(DART_READ | DART_WRITE, rpg);
        ++i;
        if (i == num_pg) break;

        if ((((ulong)&entry[i]) % cpu_caches.dline_size) == 0) {
            last_flush = (ulong)&entry[i - 1];
            dcbst(last_flush);
        }
    }
    dcbst((ulong)&entry[i - 1]);
}

static int dart_put(ulong ioba, union tce tce)
{
    ulong index = ioba >> PAGE_SHIFT;

    if (index > dart_entries) {
        return -1;
    }

    if (tce.tce_bits.tce_vlps  != 0 || tce.tce_bits.tce_lpx != 0) {
        panic("no support for large TCEs\n");
    }

    if (tce.tce_bits.tce_read == 0 &&
        tce.tce_bits.tce_write == 0) {
        /* the TCE table is inited by the domain by a bunch of 0
         * perminssion puts.  We are only interesting in debugging the
         * ones after the first put */
        DBG_AFTER(">DART[0x%lx] clear\n", index);
        dart_clear(index, 1);
    } else {
        unsigned perm = 0;

        if (tce.tce_bits.tce_read)
            perm |= DART_READ;
        if (tce.tce_bits.tce_write)
            perm |= DART_WRITE;

        DBG("<DART[0x%lx]: ioba: 0x%lx perm:%x[%c%c] rpn:0x%lx\n",
            index, ioba, perm,
            (perm & DART_READ) ? 'R' : '-',
            (perm & DART_WRITE) ? 'W' : '-',
            (ulong)tce.tce_bits.tce_rpn);
        DBG_SET_AFTER;

        dart_fill(index, perm, tce.tce_bits.tce_rpn, 1);
    }
    dops->do_inv_entry(tce.tce_bits.tce_rpn);
    
    return 0;
}

static int find_dart(struct dart_info *di)
{
    int rc;
    void *ofd_p;
    ofdn_t n;
    char compat[128];

    if (on_systemsim()) {
        DBG("%s: systemsim does not support a dart\n", __func__);
        return -1;
    }

    ofd_p = (void *)oftree;
    n = ofd_node_find(ofd_p, "/ht");
    if (n <= 0)
        return -1;

    /* get the defaults from the HT node model */
    rc = ofd_getprop(ofd_p, n, "compatible", compat, sizeof (compat));
    if (rc <= 0)
        return -1;

    if (ofd_strstr(compat, rc, "u4"))
        di->di_model = DART_U4;
    else if (ofd_strstr(compat, rc, "u3"))
        di->di_model = DART_U3;
    else {
        DBG("%s: not a U3 or U4\n", __func__);
        return -1;
    }
        
    di->di_base = DART_DEF_BASE;

    /* FIXME: this should actually be the HT reg value */
    di->di_window.dw_liobn = 0;
    di->di_window.dw_base_hi = 0;
    di->di_window.dw_base = 0;

    /* lets see if the devtree has more info */
    n = ofd_node_find(ofd_p, "/dart");
    if (n > 0) {
        ulong base;

        rc = ofd_getprop(ofd_p, n, "compatible", compat, sizeof (compat));
        if (rc > 0) {
            if (strstr(compat, "u4")) {
                di->di_model = DART_U4;
            }
        }

        rc = ofd_getprop(ofd_p, n, "reg", &base, sizeof (base));
        if (rc > 0) {
            di->di_base = base;
        }
    }
    return 0;
}

static int init_dart(void)
{
    ulong log_pgs;
    void *ofd_p;
    ofdn_t n;
    struct dart_info di;

    if (find_dart(&di))
        return 0;

    /* Max size of 512 pages == 2MB == 1<<21. That siz is good enough for U4 */
    log_pgs = U3_LOG_MAX_PAGES;
    dart_table = alloc_xenheap_pages(log_pgs);
    BUG_ON(dart_table == NULL);

    dart_entries = (1UL << (log_pgs + PAGE_SHIFT)) / sizeof (union dart_entry);
    di.di_window.dw_size = dart_entries << PAGE_SHIFT;

    /* Linux uses a dummy page, filling "empty" DART entries with a
       reference to this page to capture stray DMA's */
    dummy_page = (ulong)alloc_xenheap_pages(0);
    clear_page((void *)dummy_page);
    dummy_page >>= PAGE_SHIFT;

    printk("Initializing DART 0x%lx: tbl: %p[0x%lx] entries: 0x%lx\n",
           di.di_base, dart_table, 1UL << log_pgs, dart_entries);
           
    /* register this iommu */
    iommu_register(di.di_window.dw_liobn, dart_put);

    switch (di.di_model) {
    case DART_U3:
        dops = u3_init(di.di_base, (ulong)dart_table, 1UL << log_pgs);
        break;
    case DART_U4:
        dops = u4_init(di.di_base, (ulong)dart_table, 1UL << log_pgs);
        break;
    }

    dart_clear(0, dart_entries);
    dops->do_inv_all();

    /* fix up the devtree */
    ofd_p = (void *)oftree;
    n = ofd_node_find(ofd_p, "/ht");
    if (n > 0) {
        di.di_window.dw_size = dart_entries << PAGE_SHIFT;
        ofd_prop_add(ofd_p, n, "ibm,dma-window", &di.di_window,
                     sizeof (di.di_window));
    } else {
        panic("%s: no /ht node\n", __func__);
    }
    return 0;
}
__initcall(init_dart);
