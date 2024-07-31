/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 Vates
 *
 * RISC-V Trap handlers
 */

#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/processor.h>
#include <asm/traps.h>

void do_trap(struct cpu_user_regs *cpu_regs)
{
    die();
}

void vcpu_show_execution_state(struct vcpu *v)
{
    BUG_ON("unimplemented");
}

void show_execution_state(const struct cpu_user_regs *regs)
{
    printk("implement show_execution_state(regs)\n");
}

void arch_hypercall_tasklet_result(struct vcpu *v, long res)
{
    BUG_ON("unimplemented");
}

enum mc_disposition arch_do_multicall_call(struct mc_state *state)
{
    BUG_ON("unimplemented");
    return mc_continue;
}
