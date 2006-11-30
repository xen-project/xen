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

#include <xen/cpumask.h>
#include <xen/smp.h>
#include <asm/flushtlb.h>
#include <asm/debugger.h>

int smp_num_siblings = 1;
int smp_num_cpus = 1;
int ht_per_core = 1;

void __flush_tlb_mask(cpumask_t mask, unsigned long addr)
{
    unimplemented();
}

void smp_send_event_check_mask(cpumask_t cpu_mask)
{
    unimplemented();
}

int smp_call_function(void (*func) (void *info), void *info, int unused,
        int wait)
{
    unimplemented();
    return 0;
}

void smp_send_stop(void)
{
    unimplemented();
}

int on_selected_cpus(
    cpumask_t selected,
    void (*func) (void *info),
    void *info,
    int retry,
    int wait)
{
    return 0;
}
