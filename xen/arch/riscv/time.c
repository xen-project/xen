/* SPDX-License-Identifier: GPL-2.0-only */
#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sections.h>
#include <xen/time.h>
#include <xen/types.h>

#include <asm/csr.h>
#include <asm/sbi.h>

unsigned long __ro_after_init cpu_khz; /* CPU clock frequency in kHz. */
uint64_t __ro_after_init boot_clock_cycles;

s_time_t get_s_time(void)
{
    uint64_t ticks = get_cycles() - boot_clock_cycles;

    return ticks_to_ns(ticks);
}

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

int reprogram_timer(s_time_t timeout)
{
    uint64_t deadline, now;
    int rc;

    if ( timeout == 0 )
    {
        /* Disable timer interrupt */
        csr_clear(CSR_SIE, BIT(IRQ_S_TIMER, UL));

        return 1;
    }

    deadline = ns_to_ticks(timeout) + boot_clock_cycles;
    now = get_cycles();
    if ( deadline <= now )
        return 0;

    /*
     * TODO: When the SSTC extension is supported, it would be preferable to
     *       use the supervisor timer registers directly here for better
     *       performance, since an SBI call and mode switch would no longer
     *       be required.
     *
     *       This would also reduce reliance on a specific SBI implementation.
     *       For example, it is not ideal to panic() if sbi_set_timer() returns
     *       a non-zero value. Currently it can return 0 or -ENOSUPP, and
     *       without SSTC we still need an implementation because only the
     *       M-mode timer is available, and it can only be programmed in
     *       M-mode.
     */
    if ( (rc = sbi_set_timer(deadline)) )
        panic("%s: timer wasn't set because: %d\n", __func__, rc);

    /* Enable timer interrupt */
    csr_set(CSR_SIE, BIT(IRQ_S_TIMER, UL));

    return 1;
}

void __init preinit_xen_time(void)
{
    if ( acpi_disabled )
        preinit_dt_xen_time();
    else
        panic("%s: ACPI isn't supported\n", __func__);

    boot_clock_cycles = get_cycles();
}
