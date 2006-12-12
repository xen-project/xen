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
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_SMP_H
#define _ASM_SMP_H

#include <xen/types.h>
#include <xen/cpumask.h>
#include <xen/init.h>
#include <asm/current.h>

/* crap to make x86 "common code" happy */
#define BAD_APICID 0xFFu
extern u8 x86_cpu_to_apicid[];


extern int smp_num_siblings;

/* revisit when we support SMP */
#define raw_smp_processor_id() (parea->whoami)
#define get_hard_smp_processor_id(i) (global_cpu_table[i]->hard_id)
#define hard_smp_processor_id() (parea->hard_id)
extern cpumask_t cpu_sibling_map[];
extern cpumask_t cpu_core_map[];
extern void __devinit smp_generic_take_timebase(void);
extern void __devinit smp_generic_give_timebase(void);

#define SA_INTERRUPT	0x20000000u
typedef int irqreturn_t;
extern int request_irq(unsigned int irq,
    irqreturn_t (*handler)(int, void *, struct cpu_user_regs *),
    unsigned long irqflags, const char * devname, void *dev_id);
void smp_message_recv(int msg, struct cpu_user_regs *regs);
void smp_call_function_interrupt(struct cpu_user_regs *regs);
void smp_event_check_interrupt(void);
void send_IPI_mask(cpumask_t mask, int vector);

#undef DEBUG_IPI
#ifdef DEBUG_IPI
void ipi_torture_test(void);
#endif

#endif
