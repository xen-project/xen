/* SPDX-License-Identifier: MIT */

/*
 * xen/arch/riscv/aplic.c
 *
 * RISC-V Advanced Platform-Level Interrupt Controller support
 *
 * Copyright (c) 2023-2024 Microchip.
 * Copyright (c) 2024-2025 Vates
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/sections.h>
#include <xen/types.h>

#include <asm/device.h>
#include <asm/intc.h>

static struct intc_info __ro_after_init aplic_info = {
    .hw_version = INTC_APLIC,
};

static int __init aplic_preinit(struct dt_device_node *node, const void *dat)
{
    if ( aplic_info.node )
    {
        printk("XEN doesn't support more than one S mode APLIC\n");
        return -ENODEV;
    }

    /* don't process if APLIC node is not for S mode */
    if ( dt_get_property(node, "riscv,children", NULL) )
        return -ENODEV;

    aplic_info.node = node;

    return 0;
}

static const struct dt_device_match __initconstrel aplic_dt_match[] =
{
    DT_MATCH_COMPATIBLE("riscv,aplic"),
    { /* sentinel */ },
};

DT_DEVICE_START(aplic, "APLIC", DEVICE_INTERRUPT_CONTROLLER)
    .dt_match = aplic_dt_match,
    .init = aplic_preinit,
DT_DEVICE_END
