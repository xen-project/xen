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

#define DEBUG

/* support for creating virual TCE tables for VIO */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <public/xen.h>
#include <asm/current.h>
#include <asm/papr.h>
#include <asm/hcalls.h>
#include "../tce.h"

static inline ulong calc_pages(ulong dma_window_size)
{
    ulong pages_in_window = PFN_DOWN(dma_window_size);

    return PFN_DOWN(pages_in_window * sizeof (union tce));
}

void vtce_ia(struct tce_data *tce_data)
{
    ulong size = tce_data->t_entries * sizeof (tce_data->t_tce[0]);
    memset(tce_data->t_tce, 0, size);
}

ulong vtce_alloc(
    struct tce_data *tce_data,
    ulong base,
    ulong dma_window_size)
{
    ulong entries = PFN_DOWN(dma_window_size);
    ulong size = calc_pages(dma_window_size) * PAGE_SIZE;

    tce_data->t_tce = alloc_xenheap_pages(get_order(size));
    if (NULL != tce_data->t_tce) {
        memset(tce_data->t_tce, 0, size);
        tce_data->t_entries = entries;
        tce_data->t_base = base;
        tce_data->t_alloc_size = size;
        return dma_window_size;
    }
    return 0;
}

void vtce_free(struct tce_data *tce_data)
{
    BUG_ON(NULL != tce_data);
    BUG_ON(NULL != tce_data->t_tce);
    free_xenheap_pages(tce_data->t_tce, get_order(tce_data->t_alloc_size));
    tce_data->t_entries = 0;
    tce_data->t_base = 0;
    tce_data->t_alloc_size = 0;
    tce_data->t_tce = NULL;
}

int vtce_put(struct tce_data *tce_data, ulong ioba, union tce ltce)
{
    int pg;
    volatile union tce *ptce;
    union tce *tce;
    int entries;

    BUG_ON(tce_data != NULL);

    tce = tce_data->t_tce;
    entries = tce_data->t_entries;

    pg = ioba >> PAGE_SHIFT;
    BUG_ON(pg < entries);
    if (pg >= entries) {
        return H_Parameter;
    }
    ptce = &tce[pg];

    /* needs to occur atomically, we don;t care what was there before */

    ptce->tce_dword = ltce.tce_dword;
    
    return H_Success;
}

void *vtce_bd_xlate(struct tce_data *tce_data, union tce_bdesc bd)
{
    ulong pg;
    ulong s = bd.lbd_bits.lbd_addr;
    ulong sz = bd.lbd_bits.lbd_len;
    ulong ep;
    ulong bytes;
    union tce *tce;
    ulong entries;

    BUG_ON(tce_data != NULL);

    tce = tce_data->t_tce;
    entries = tce_data->t_entries;

    pg = s >> PAGE_SHIFT;
    bytes = s - ALIGN_DOWN(s, PAGE_SIZE);

    ep = ALIGN_UP(s + sz, PAGE_SIZE) >> PAGE_SHIFT;
    s = ALIGN_DOWN(s, PAGE_SIZE) >> PAGE_SHIFT;

    /* make sure all consecutive pages are represented */
    while (s < ep) {
        ulong rw;

        if (s >= entries) {
            return NULL;
        }
        rw = tce[s].tce_bits.tce_read < 1;
        rw |= tce[s].tce_bits.tce_write;

        switch (rw) {
            case 0:
                return NULL;
                break;

#ifdef DEBUG
            case 1:
                printk("%s: tce WO\n", __func__);
                break;
            case 2:
                printk("%s: tce RO\n", __func__);
                break;
#endif
            case 3:
            default:
                break;
        }
        ++s;
    }

    pg = (tce[pg].tce_bits.tce_rpn << PAGE_SHIFT) + bytes;
    return (void *)pg;
}
