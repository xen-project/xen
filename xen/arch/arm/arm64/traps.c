/*
 * xen/arch/arm/arm64/traps.c
 *
 * ARM AArch64 Specific Trap handlers
 *
 * Copyright (c) 2012 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/lib.h>

#include <asm/system.h>
#include <asm/processor.h>

#include <public/xen.h>

asmlinkage void do_trap_serror(struct cpu_user_regs *regs)
{
    panic("Unhandled serror trap");
}

static const char *handler[]= {
        "Synchronous Abort",
        "IRQ",
        "FIQ",
        "Error"
};

asmlinkage void do_bad_mode(struct cpu_user_regs *regs, int reason)
{
    uint64_t esr = READ_SYSREG64(ESR_EL2);
    printk("Bad mode in %s handler detected, code 0x%08"PRIx64"\n",
           handler[reason], esr);

    local_irq_disable();
    panic("bad mode");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
