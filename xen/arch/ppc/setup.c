/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/init.h>
#include <asm/boot.h>
#include <asm/early_printk.h>
#include <asm/processor.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE] __aligned(STACK_SIZE);

void __init noreturn start_xen(unsigned long r3, unsigned long r4,
                               unsigned long r5, unsigned long r6,
                               unsigned long r7)
{
    if ( r5 )
    {
        /* OpenFirmware boot protocol */
        boot_of_init(r5);
    }
    else
    {
        /* kexec boot: Unimplemented */
        __builtin_trap();
    }

    early_printk("Hello, ppc64le!\n");

    for ( ; ; )
        /* Set current hardware thread to very low priority */
        HMT_very_low();

    unreachable();
}
