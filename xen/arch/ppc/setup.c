/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/init.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE] __aligned(STACK_SIZE);

/* Macro to adjust thread priority for hardware multithreading */
#define HMT_very_low()  asm volatile ( "or %r31, %r31, %r31" )

void __init noreturn start_xen(unsigned long r3, unsigned long r4,
                               unsigned long r5, unsigned long r6,
                               unsigned long r7)
{
    for ( ; ; )
        /* Set current hardware thread to very low priority */
        HMT_very_low();

    unreachable();
}
