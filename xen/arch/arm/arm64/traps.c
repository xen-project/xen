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

#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/hsr.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/traps.h>

#include <public/xen.h>

static const char *handler[]= {
        "Synchronous Abort",
        "IRQ",
        "FIQ",
        "Error"
};

void do_bad_mode(struct cpu_user_regs *regs, int reason)
{
    union hsr hsr = { .bits = regs->hsr };

    printk("Bad mode in %s handler detected\n", handler[reason]);
    printk("ESR=%#"PRIregister":  EC=%"PRIx32", IL=%"PRIx32", ISS=%"PRIx32"\n",
           hsr.bits, hsr.ec, hsr.len, hsr.iss);

    local_irq_disable();
    show_execution_state(regs);
    panic("bad mode\n");
}

void finalize_instr_emulation(const struct instr_details *instr)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    register_t val = 0;
    uint8_t psr_mode = (regs->cpsr & PSR_MODE_MASK);

    /* Currently, we handle only ldr/str post indexing instructions */
    if ( instr->state != INSTR_LDR_STR_POSTINDEXING )
        return;

    /*
     * Handle when rn = SP
     * Refer ArmV8 ARM DDI 0487G.b, Page - D1-2463 "Stack pointer register
     * selection"
     * t = SP_EL0
     * h = SP_ELx
     * and M[3:0] (Page - C5-474 "When exception taken from AArch64 state:")
     */
    if ( instr->rn == 31 )
    {
        switch ( psr_mode )
        {
        case PSR_MODE_EL1h:
            val = regs->sp_el1;
            break;
        case PSR_MODE_EL1t:
        case PSR_MODE_EL0t:
            val = regs->sp_el0;
            break;

        default:
            domain_crash(current->domain);
            return;
        }
    }
    else
        val = get_user_reg(regs, instr->rn);

    val += instr->imm9;

    if ( instr->rn == 31 )
    {
        if ( (regs->cpsr & PSR_MODE_MASK) == PSR_MODE_EL1h )
            regs->sp_el1 = val;
        else
            regs->sp_el0 = val;
    }
    else
        set_user_reg(regs, instr->rn, val);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
