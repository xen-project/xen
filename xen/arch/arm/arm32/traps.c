/*
 * xen/arch/arm/arm32/traps.c
 *
 * ARM AArch32 Specific Trap handlers
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
#include <xen/kernel.h>

#include <public/xen.h>

#include <asm/processor.h>

asmlinkage void do_trap_undefined_instruction(struct cpu_user_regs *regs)
{
    uint32_t pc = regs->pc;
    uint32_t instr;

    if ( !is_kernel_text(pc) &&
         (system_state >= SYS_STATE_active || !is_kernel_inittext(pc)) )
        goto die;

    /* PC should be always a multiple of 4, as Xen is using ARM instruction set */
    if ( regs->pc & 0x3 )
        goto die;

    instr = *((uint32_t *)pc);
    if ( instr != BUG_OPCODE )
        goto die;

    if ( do_bug_frame(regs, pc) )
        goto die;

    regs->pc += 4;
    return;

die:
    do_unexpected_trap("Undefined Instruction", regs);
}

asmlinkage void do_trap_supervisor_call(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Supervisor Call", regs);
}

asmlinkage void do_trap_prefetch_abort(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Prefetch Abort", regs);
}

asmlinkage void do_trap_data_abort(struct cpu_user_regs *regs)
{
    do_unexpected_trap("Data Abort", regs);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
