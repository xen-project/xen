/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>

#include <asm/intc.h>

static const struct intc_hw_operations *__ro_after_init intc_hw_ops;

void __init register_intc_ops(const struct intc_hw_operations *ops)
{
    intc_hw_ops = ops;
}

void __init intc_preinit(void)
{
    if ( acpi_disabled )
        intc_dt_preinit();
    else
        panic("ACPI interrupt controller preinit() isn't implemented\n");
}
