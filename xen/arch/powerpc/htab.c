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
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/sched.h>

static ulong htab_calc_sdr1(ulong htab_addr, ulong log_htab_size)
{
    ulong sdr1_htabsize;

    ASSERT((htab_addr & ((1UL << log_htab_size) - 1)) == 0);
    ASSERT(log_htab_size <= SDR1_HTABSIZE_MAX);
    ASSERT(log_htab_size >= HTAB_MIN_LOG_SIZE);

    sdr1_htabsize = log_htab_size - LOG_PTEG_SIZE - SDR1_HTABSIZE_BASEBITS;

    return (htab_addr | (sdr1_htabsize & SDR1_HTABSIZE_MASK));
}

void htab_alloc(struct domain *d, uint order)
{
    ulong htab_raddr;
    ulong log_htab_bytes = order + PAGE_SHIFT;
    ulong htab_bytes = 1UL << log_htab_bytes;

    /* XXX use alloc_domheap_pages instead? */
    htab_raddr = (ulong)alloc_xenheap_pages(order);
    ASSERT(htab_raddr != 0);
    /* XXX check alignment guarantees */
    ASSERT((htab_raddr & (htab_bytes - 1)) == 0);

    /* XXX slow. move memset out to service partition? */
    memset((void *)htab_raddr, 0, htab_bytes);

    d->arch.htab.order = order;
    d->arch.htab.log_num_ptes = log_htab_bytes - LOG_PTE_SIZE;
    d->arch.htab.sdr1 = htab_calc_sdr1(htab_raddr, log_htab_bytes);
    d->arch.htab.map = (union pte *)htab_raddr;
    d->arch.htab.shadow = xmalloc_array(ulong,
                                        1UL << d->arch.htab.log_num_ptes);
    ASSERT(d->arch.htab.shadow != NULL);
}

void htab_free(struct domain *d)
{
    ulong htab_raddr = GET_HTAB(d);

    free_xenheap_pages((void *)htab_raddr, d->arch.htab.order);
    xfree(d->arch.htab.shadow);
}

