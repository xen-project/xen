/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/version.h>
#include <asm/boot.h>
#include <asm/early_printk.h>
#include <asm/mm.h>
#include <asm/processor.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE] __aligned(STACK_SIZE);

void __init noreturn start_xen(unsigned long r3, unsigned long r4,
                               unsigned long r5, unsigned long r6,
                               unsigned long r7)
{
    if ( r5 )
    {
        /* Unsupported OpenFirmware boot protocol */
        __builtin_trap();
    }
    else
    {
        /* kexec boot protocol */
        boot_opal_init((void *)r3);
    }

    setup_initial_pagetables();

    early_printk("Hello, ppc64le!\n");

    for ( ; ; )
        /* Set current hardware thread to very low priority */
        HMT_very_low();

    unreachable();
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    BUG_ON("unimplemented");
}
