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
 * Copyright IBM Corp. 2005, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ARCH_PPC_EXCEPTIONS_H_
#define _ARCH_PPC_EXCEPTIONS_H_

#include <xen/types.h>
#include <public/xen.h>
#include <xen/multiboot.h>

extern void do_hcall(struct cpu_user_regs *regs);
extern void do_IRQ(struct cpu_user_regs *regs);
extern void deliver_ee(struct cpu_user_regs *regs);
extern void do_external(struct cpu_user_regs *regs);
extern void init_IRQ(void);
extern void ack_APIC_irq(void);
extern int ioapic_guest_read(unsigned long physbase, unsigned int reg, u32 *pval);
extern int ioapic_guest_write(unsigned long physbase, unsigned int reg, u32 val);

extern void do_timer(struct cpu_user_regs *regs);
extern void do_dec(struct cpu_user_regs *regs);
extern void do_perfmon(struct cpu_user_regs *regs);
extern void program_exception(
    struct cpu_user_regs *regs, unsigned long cookie);

extern long xen_hvcall_jump(struct cpu_user_regs *regs, ulong address);

extern void sleep(void);
extern void idle_loop(void);

extern ulong *__hypercall_table[];

extern char exception_vectors[];
extern char exception_vectors_end[];
extern int spin_start[];
extern void secondary_cpu_init(int cpuid, unsigned long r4);
#endif
