/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/mm.h>

#include <public/version.h>

#include <asm/early_printk.h>
#include <asm/traps.h>

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    BUG_ON("unimplemented");
}

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
    remove_identity_mapping();

    trap_init();

    printk("All set up\n");

    for ( ;; )
        asm volatile ("wfi");

    unreachable();
}
