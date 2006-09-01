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
 */

#include <xen/config.h>
#include <xen/softirq.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/gdbstub.h>
#include <public/xen.h>
#include <asm/time.h>

#undef DEBUG
#define HDEC_PREEMPT

extern ulong ppc_do_softirq(ulong orig_msr);
extern void do_timer(struct cpu_user_regs *regs);
extern void do_dec(struct cpu_user_regs *regs);
extern void program_exception(struct cpu_user_regs *regs, unsigned long cookie);

int hdec_sample = 0;

void do_timer(struct cpu_user_regs *regs)
{
    /* XXX this is just here to keep HDEC from firing until
     * reprogram_ac_timer() sets the proper next-tick time */
    mthdec(timebase_freq);

#ifdef HDEC_PREEMPT
    raise_softirq(TIMER_SOFTIRQ);
#endif
#ifdef DEBUG
    {
        int d;
        if (regs->msr & MSR_HV) {
            d = -1;
        } else {
            d = get_current()->domain->domain_id;
        }
        extern char serial_getc_nb(int handle);
        if (0 && serial_getc_nb(0) > 0) {
            printk("H: pc: 0x%lx lr: 0x%lx \n", regs->pc, regs->lr);
        }
        if (hdec_sample)  {
            printk("H: pc: 0x%lx lr: 0x%lx \n", regs->pc, regs->lr);
            hdec_sample = 0;
        }
    }
#endif
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
    show_registers(regs);
    printk("dar 0x%016lx, dsisr 0x%08x\n", mfdar(), mfdsisr());
    printk("hid4 0x%016lx\n", regs->hid4);
    printk("---[ backtrace ]---\n");
    show_backtrace(regs->gprs[1], regs->lr, regs->pc);
    panic("%s: 0x%lx\n", __func__, cookie);
#endif /* CRASH_DEBUG */
}
