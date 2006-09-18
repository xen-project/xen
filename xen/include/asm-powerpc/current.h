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

#ifndef _ASM_CURRENT_H_
#define _ASM_CURRENT_H_

#include <public/xen.h>
#include <asm/processor.h>
#include <asm/powerpc64/procarea.h>

struct vcpu;

extern volatile struct processor_area * volatile global_cpu_table[];
register volatile struct processor_area *parea asm("r13");
static inline struct vcpu *get_current(void)
{
    return parea->cur_vcpu;
}
#define current get_current()

static inline void set_current(struct vcpu *v)
{
    parea->cur_vcpu = v;
}

/* The *currently running* guest's register state has been saved at the top of
 * this processor's hypervisor stack. */
static inline struct cpu_user_regs *guest_cpu_user_regs(void)
{
    ulong stack_top = (ulong)parea->hyp_stack_base;

    return (struct cpu_user_regs *)(stack_top - STACK_VOLATILE_AREA
                                    - sizeof (struct cpu_user_regs));
}

/* XXX *#%(ing circular header dependencies force this to be a macro */
/* If the vcpu is running, its state is still on the stack, and the vcpu
 * structure's copy is obsolete. If the vcpu isn't running, the vcpu structure
 * holds the only copy. This routine always does the right thing. */
#define vcpu_regs(v) ({                 \
    struct cpu_user_regs *regs;         \
    if (v == current)                   \
        regs = guest_cpu_user_regs();   \
    else                                \
        regs = &v->arch.ctxt;           \
    regs;                               \
})


static inline void reset_stack_and_jump(void (*f)(void))
{
    void _reset_stack_and_jump(void (*)(void), struct cpu_user_regs *);
    struct cpu_user_regs *regs = guest_cpu_user_regs();

#ifdef TRACK_RESUME
    printk("PC: 0x%lx, MSR: 0x%lx\n", regs->pc, regs->msr);
#endif

    _reset_stack_and_jump(f, regs);
}

#endif
