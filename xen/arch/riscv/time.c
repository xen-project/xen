/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sections.h>

unsigned long __ro_after_init cpu_khz; /* CPU clock frequency in kHz. */
uint64_t __ro_after_init boot_clock_cycles;

/* Set up the timer on the boot CPU (early init function) */
static void __init preinit_dt_xen_time(void)
{
    static const struct dt_device_match __initconstrel timer_ids[] =
    {
        DT_MATCH_PATH("/cpus"),
        { /* sentinel */ },
    };
    struct dt_device_node *timer;
    uint32_t rate;

    timer = dt_find_matching_node(NULL, timer_ids);
    if ( !timer )
        panic("Unable to find a compatible timer in the device tree\n");

    dt_device_set_used_by(timer, DOMID_XEN);

    if ( !dt_property_read_u32(timer, "timebase-frequency", &rate) )
        panic("Unable to find clock frequency\n");

    cpu_khz = rate / 1000;
}

void __init preinit_xen_time(void)
{
    if ( acpi_disabled )
        preinit_dt_xen_time();
    else
        panic("%s: ACPI isn't supported\n", __func__);

    boot_clock_cycles = get_cycles();
}
