/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Jimi Xenidis <jimix@watson.ibm.com>
 */

#include <xen/config.h>
#include <xen/softirq.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/gdbstub.h>
#include <asm/time.h>
#include <asm/processor.h>

#undef DEBUG

extern ulong ppc_do_softirq(ulong orig_msr);
extern void do_timer(struct cpu_user_regs *regs);
extern void do_dec(struct cpu_user_regs *regs);
extern void program_exception(struct cpu_user_regs *regs, unsigned long cookie);

int hdec_sample = 0;

void do_timer(struct cpu_user_regs *regs)
{
    /* Set HDEC high so it stops firing and can be reprogrammed by
     * set_preempt() */
    mthdec(INT_MAX);
    raise_softirq(TIMER_SOFTIRQ);
}

void do_dec(struct cpu_user_regs *regs)
{
    if (!(regs->msr & MSR_HV)) {
        panic("HV dec from domain\n");
    }
    printk("DEC_HV: pc: 0x%lx lr: 0x%lx \n", regs->pc, regs->lr);
    mtdec(INT_MAX);
}

void program_exception(struct cpu_user_regs *regs, unsigned long cookie)
{
#ifdef CRASH_DEBUG
    __trap_to_gdb(regs, cookie);
#else /* CRASH_DEBUG */
    int recover = 0;

    show_registers(regs);
    printk("dar 0x%016lx, dsisr 0x%08x\n", mfdar(), mfdsisr());
    printk("hid4 0x%016lx\n", regs->hid4);
    printk("---[ backtrace ]---\n");
    show_backtrace(regs->gprs[1], regs->lr, regs->pc);

    if (cookie == 0x200)
        recover = cpu_machinecheck(regs);

    if (!recover)
        panic("%s: 0x%lx\n", __func__, cookie);
#endif /* CRASH_DEBUG */
}
