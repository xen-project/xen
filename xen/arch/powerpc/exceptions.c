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
#include <xen/console.h>
#include <xen/shutdown.h>
#include <asm/time.h>
#include <asm/processor.h>
#include <asm/debugger.h>

#undef DEBUG

extern ulong ppc_do_softirq(ulong orig_msr);
extern void do_timer(struct cpu_user_regs *regs);
extern void do_dec(struct cpu_user_regs *regs);
extern void program_exception(struct cpu_user_regs *regs,
                              unsigned long cookie);
extern int reprogram_timer(s_time_t timeout); 

int hdec_sample = 0;

void do_timer(struct cpu_user_regs *regs)
{
    /* Set HDEC high so it stops firing and can be reprogrammed by
     * set_preempt() */
    /* FIXME! HACK ALERT!
     *
     * We have a bug in that if we switch domains in schedule() we
     * switch right away regardless of whatever else is pending.  This
     * means that if the timer goes off while in schedule(), the next
     * domain will be preempted by the interval defined below.  So
     * until we fix our cotnext_switch(), the follow workaround will
     * make sure that the domain we switch to does not run for to long
     * so we can continue to service the other timers in the timer
     * queue and that the value is long enough to escape this
     * particular timer event.
     */
    reprogram_timer(NOW() + MILLISECS(1));

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
    if (cookie == 0x200) {
        if (cpu_machinecheck(regs))
            return;

        printk("%s: machine check\n", __func__);
    } else {
#ifdef CRASH_DEBUG
        if (__trap_to_gdb(regs, cookie) == 0)
            return;
#endif /* CRASH_DEBUG */

        printk("%s: type: 0x%lx\n", __func__, cookie);
        show_backtrace_regs(regs);
    }
    machine_halt();
}
