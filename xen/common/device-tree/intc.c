/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>

void __init intc_dt_preinit(void)
{
    struct dt_device_node *node;
    uint8_t num_intc = 0;

    dt_for_each_device_node( dt_host, node )
    {
        if ( !dt_get_property(node, "interrupt-controller", NULL) )
            continue;

        if ( !dt_get_parent(node) )
            continue;

        if ( !device_init(node, DEVICE_INTERRUPT_CONTROLLER, NULL) )
        {
            /* NOTE: Only one interrupt controller is supported */
            num_intc = 1;
            break;
        }
    }

    if ( !num_intc )
        panic("Unable to find compatible interrupt controller in the device tree\n");

    /* Set the interrupt controller as the primary interrupt controller */
    dt_interrupt_controller = node;
    dt_device_set_used_by(node, DOMID_XEN);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
