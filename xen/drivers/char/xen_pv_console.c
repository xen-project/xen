/******************************************************************************
 * drivers/char/xen_pv_console.c
 *
 * A frontend driver for Xen's PV console.
 * Can be used when Xen is running on top of Xen in pv-in-pvh mode.
 * (Linux's name for this is hvc console)
 *
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/lib.h>
#include <xen/hypercall.h>
#include <xen/pv_console.h>

#include <asm/fixmap.h>
#include <asm/guest.h>

#include <public/io/console.h>

static struct xencons_interface *cons_ring;
static evtchn_port_t cons_evtchn;
static serial_rx_fn cons_rx_handler;
static DEFINE_SPINLOCK(tx_lock);

bool pv_console;

void pv_console_init(void)
{
    long r;
    uint64_t raw_pfn = 0, raw_evtchn = 0;

    if ( !xen_guest )
    {
        printk("PV console init failed: xen_guest mode is not active!\n");
        return;
    }

    r = xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_PFN, &raw_pfn);
    if ( r < 0 )
        goto error;

    r = xen_hypercall_hvm_get_param(HVM_PARAM_CONSOLE_EVTCHN, &raw_evtchn);
    if ( r < 0 )
        goto error;

    set_fixmap(FIX_PV_CONSOLE, raw_pfn << PAGE_SHIFT);
    cons_ring = (struct xencons_interface *)fix_to_virt(FIX_PV_CONSOLE);
    cons_evtchn = raw_evtchn;

    printk("Initialised PV console at 0x%p with pfn %#lx and evtchn %#x\n",
            cons_ring, raw_pfn, cons_evtchn);
    pv_console = true;

    return;

 error:
    printk("Couldn't initialise PV console\n");
}

void __init pv_console_set_rx_handler(serial_rx_fn fn)
{
    cons_rx_handler = fn;
}

void __init pv_console_init_postirq(void)
{
    if ( !cons_ring )
        return;

    xen_hypercall_evtchn_unmask(cons_evtchn);
}

static void notify_daemon(void)
{
    xen_hypercall_evtchn_send(cons_evtchn);
}

evtchn_port_t pv_console_evtchn(void)
{
    return cons_evtchn;
}

size_t pv_console_rx(struct cpu_user_regs *regs)
{
    char c;
    XENCONS_RING_IDX cons, prod;
    size_t recv = 0;

    if ( !cons_ring )
        return 0;

    prod = ACCESS_ONCE(cons_ring->in_prod);
    cons = cons_ring->in_cons;

    /*
     * Latch pointers before accessing the ring. Included compiler barrier also
     * ensures that pointers are really read only once into local variables.
     */
    smp_rmb();

    ASSERT((prod - cons) <= sizeof(cons_ring->in));

    while ( cons != prod )
    {
        c = cons_ring->in[MASK_XENCONS_IDX(cons++, cons_ring->in)];
        if ( cons_rx_handler )
            cons_rx_handler(c, regs);
        recv++;
    }

    /* No need for a mem barrier because every character was already consumed */
    barrier();
    ACCESS_ONCE(cons_ring->in_cons) = cons;
    notify_daemon();

    return recv;
}

static size_t pv_ring_puts(const char *buf, size_t nr)
{
    XENCONS_RING_IDX cons, prod;
    size_t sent = 0, avail;
    bool put_r = false;

    while ( sent < nr || put_r )
    {
        cons = ACCESS_ONCE(cons_ring->out_cons);
        prod = cons_ring->out_prod;

        /*
         * Latch pointers before accessing the ring. Included compiler barrier
         * ensures that pointers are really read only once into local variables.
         */
        smp_rmb();

        ASSERT((prod - cons) <= sizeof(cons_ring->out));
        avail = sizeof(cons_ring->out) - (prod - cons);

        if ( avail == 0 )
        {
            /* Wait for xenconsoled to consume our output */
            xen_hypercall_sched_op(SCHEDOP_yield, NULL);
            continue;
        }

        while ( avail && (sent < nr || put_r) )
        {
            if ( put_r )
            {
                cons_ring->out[MASK_XENCONS_IDX(prod++, cons_ring->out)] = '\r';
                put_r = false;
            }
            else
            {
                cons_ring->out[MASK_XENCONS_IDX(prod++, cons_ring->out)] =
                    buf[sent];

                /* Send '\r' for every '\n' */
                if ( buf[sent] == '\n' )
                    put_r = true;
                sent++;
            }
            avail--;
        }

        /* Write to the ring before updating the pointer */
        smp_wmb();
        ACCESS_ONCE(cons_ring->out_prod) = prod;
        notify_daemon();
    }

    return sent;
}

void pv_console_puts(const char *buf, size_t nr)
{
    unsigned long flags;

    if ( !cons_ring )
        return;

    spin_lock_irqsave(&tx_lock, flags);
    pv_ring_puts(buf, nr);
    spin_unlock_irqrestore(&tx_lock, flags);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
