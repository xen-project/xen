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
extern int smp_num_siblings;

/* revisit when we support SMP */
#define raw_smp_processor_id() (parea->whoami)
#define get_hard_smp_processor_id(i) (global_cpu_table[i]->hard_id)
#define hard_smp_processor_id() (parea->hard_id)
extern cpumask_t cpu_sibling_map[];
extern cpumask_t cpu_core_map[];
extern void __devinit smp_generic_take_timebase(void);
extern void __devinit smp_generic_give_timebase(void);
#endif
