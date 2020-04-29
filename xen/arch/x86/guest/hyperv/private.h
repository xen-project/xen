/******************************************************************************
 * arch/x86/guest/hyperv/private.h
 *
 * Definitions / declarations only useful to Hyper-V code.
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2020 Microsoft.
 */

#ifndef __XEN_HYPERV_PRIVIATE_H__
#define __XEN_HYPERV_PRIVIATE_H__

#include <xen/cpumask.h>
#include <xen/percpu.h>

DECLARE_PER_CPU(void *, hv_input_page);
DECLARE_PER_CPU(void *, hv_vp_assist);
DECLARE_PER_CPU(unsigned int, hv_vp_index);
extern unsigned int hv_max_vp_index;

static inline unsigned int hv_vp_index(unsigned int cpu)
{
    return per_cpu(hv_vp_index, cpu);
}

int hyperv_flush_tlb(const cpumask_t *mask, const void *va,
                     unsigned int flags);

/* Returns number of banks, -ev if error */
int cpumask_to_vpset(struct hv_vpset *vpset, const cpumask_t *mask);

#endif /* __XEN_HYPERV_PRIVIATE_H__  */
