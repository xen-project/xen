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
 * Copyright (C) IBM Corp. 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/shadow.h>

static ulong htab_calc_sdr1(ulong htab_addr, ulong log_htab_size)
{
    ulong sdr1_htabsize;

    ASSERT((htab_addr & ((1UL << log_htab_size) - 1)) == 0);
    ASSERT(log_htab_size <= SDR1_HTABSIZE_MAX);
    ASSERT(log_htab_size >= HTAB_MIN_LOG_SIZE);

    sdr1_htabsize = log_htab_size - LOG_PTEG_SIZE - SDR1_HTABSIZE_BASEBITS;

    return (htab_addr | (sdr1_htabsize & SDR1_HTABSIZE_MASK));
}

static ulong htab_alloc(struct domain *d, uint order)
{
    ulong htab_raddr;
    uint log_htab_bytes = order + PAGE_SHIFT;
    uint htab_bytes = 1UL << log_htab_bytes;

    /* we use xenheap pages to keep domheap pages usefull for domains */

    if (order < 6)
        order = 6;              /* architectural minimum is 2^18 */
    if (order > 34)
        order = 34;             /* architectural minimum is 2^46 */

    htab_raddr = (ulong)alloc_xenheap_pages(order);
    if (htab_raddr > 0) {
        ASSERT((htab_raddr & (htab_bytes - 1)) == 0);

        d->arch.htab.order = order;
        d->arch.htab.log_num_ptes = log_htab_bytes - LOG_PTE_SIZE;
        d->arch.htab.sdr1 = htab_calc_sdr1(htab_raddr, log_htab_bytes);
        d->arch.htab.map = (union pte *)htab_raddr;
    }
    return htab_raddr;
}

static void htab_free(struct domain *d)
{
    ulong htab_raddr = GET_HTAB(d);

    free_xenheap_pages((void *)htab_raddr, d->arch.htab.order);
}


unsigned int shadow_teardown(struct domain *d)
{
    htab_free(d);
    return 0;
}

unsigned int shadow_set_allocation(struct domain *d, 
                                    unsigned int megabytes,
                                    int *preempted)
{
    uint pages;
    uint p;
    uint order;
    ulong addr;
    

    if (d->arch.htab.order)
        return -EBUSY;

    if (megabytes == 0) {
        /* old management tools */
        megabytes = 1;          /* 1/64th of 64M */
        printk("%s: WARNING!!: Update your managment tools\n"
               "    using %d MiB htab\n",
               __func__, megabytes);
    }
    pages = megabytes << (20 - PAGE_SHIFT);
    order = fls(pages) - 1;     /* log2 truncated */
    if (pages & ((1 << order) - 1))
        ++order;                /* round up */

    addr = htab_alloc(d, order);

    if (addr == 0)
        return -ENOMEM;

    /* XXX make this a continuation */
    for (p = 0; p < (1 << order); p++)
        clear_page((void *)(addr + (p << PAGE_SHIFT)));

    return 0;
}

int shadow_domctl(struct domain *d, 
                  xen_domctl_shadow_op_t *sc,
                  XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    if ( unlikely(d == current->domain) )
    {
        gdprintk(XENLOG_INFO, "Don't try to do a shadow op on yourself!\n");
        return -EINVAL;
    }

    switch ( sc->op )
    {
    case XEN_DOMCTL_SHADOW_OP_OFF:
         gdprintk(XENLOG_INFO, "Shadow is mandatory!\n");
         return -EINVAL;

    case XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION:
        sc->mb = shadow_get_allocation(d);
        return 0;

    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION: {
        int rc;
        int preempted = 0;

        rc = shadow_set_allocation(d, sc->mb, &preempted);

        if (preempted)
            /* Not finished.  Set up to re-run the call. */
            rc = hypercall_create_continuation(
                __HYPERVISOR_domctl, "h", u_domctl);
        else 
            /* Finished.  Return the new allocation */
            sc->mb = shadow_get_allocation(d);
        return rc;
    }

    default:
        printk("Bad shadow op %u\n", sc->op);
        BUG();
        return -EINVAL;
    }
}
