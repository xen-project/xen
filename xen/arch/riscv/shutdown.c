/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/shutdown.h>

#include <asm/sbi.h>

void machine_halt(void)
{
    sbi_shutdown();

    /* TODO: Cope with sbi_shutdown() not being implemented. */

    for ( ;; )
        asm volatile ( "wfi" );

    unreachable();
}

void machine_restart(unsigned int delay_millisecs)
{
    /*
     * TODO: mdelay(delay_millisecs)
     * TODO: Probe for #SRST support, where sbi_system_reset() has a
     *       shutdown/reboot parameter.
     */

    machine_halt();
}
