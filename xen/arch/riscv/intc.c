/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>

void __init intc_preinit(void)
{
    if ( acpi_disabled )
        intc_dt_preinit();
    else
        panic("ACPI interrupt controller preinit() isn't implemented\n");
}
