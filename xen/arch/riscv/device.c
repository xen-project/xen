/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/device_tree.h>
#include <xen/dt-overlay.h>
#include <xen/errno.h>
#include <xen/iocap.h>
#include <xen/rangeset.h>
#include <xen/sched.h>

#include <asm/intc.h>

int __overlay_init map_irq_to_domain(struct domain *d, unsigned int irq,
                                     bool need_mapping, const char *devname)
{
    int res;

    res = irq_permit_access(d, irq);
    if ( res )
    {
        printk(XENLOG_ERR "Unable to permit %pd access to IRQ %u\n", d, irq);
        return res;
    }

    if ( need_mapping )
    {
        /*
         * -EEXIST merely means that the IRQ has already been reserved, which
         * legitimately happens when the IRQ is shared between devices. Any
         * other failure has to be fatal: the IRQ would otherwise be routed to
         * the domain without domain_vintc_deinit() ever releasing it again.
         */
        res = vintc_reserve_virq(d, irq);
        if ( res && (res != -EEXIST) )
        {
            printk(XENLOG_ERR "Unable to reserve vIRQ %u for %pd\n", irq, d);
            return res;
        }

        res = route_irq_to_guest(d, irq, irq, devname);
        if ( res < 0 )
        {
            printk(XENLOG_ERR "Unable to map IRQ%u to %pd\n", irq, d);
            return res;
        }
    }

    dt_dprintk("  - IRQ: %u\n", irq);

    return 0;
}

int __overlay_init map_device_irqs_to_domain(struct domain *d,
                                             struct dt_device_node *dev,
                                             bool need_mapping,
                                             struct rangeset *irq_ranges)
{
    unsigned int i, nirq = dt_number_of_irq(dev);

    if ( irq_ranges )
        return -EOPNOTSUPP;

    /* Give permission and map IRQs */
    for ( i = 0; i < nirq; i++ )
    {
        int res, irq;
        struct dt_raw_irq rirq;

        res = dt_device_get_raw_irq(dev, i, &rirq);
        if ( res )
        {
            printk(XENLOG_ERR "Unable to retrieve irq %u for %s\n",
                   i, dt_node_full_name(dev));
            return res;
        }

        /*
         * Don't map IRQs that have no physical meaning
         * ie: IRQs whose controller is not APLIC/IMSIC/PLIC.
         */
        if ( rirq.controller != dt_interrupt_controller )
        {
            dt_dprintk("irq %u not connected to primary controller. Connected to %s\n",
                       i, dt_node_full_name(rirq.controller));
            continue;
        }

        irq = platform_get_irq(dev, i);
        if ( irq < 0 )
        {
            printk("Unable to get irq %u for %s\n", i, dt_node_full_name(dev));
            return irq;
        }

        res = map_irq_to_domain(d, irq, need_mapping, dt_node_name(dev));
        if ( res )
            return res;
    }

    return 0;
}
