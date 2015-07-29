/******************************************************************************
 * preempt.c
 * 
 * Track atomic regions in the hypervisor which disallow sleeping.
 * 
 * Copyright (c) 2010, Keir Fraser <keir@xen.org>
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
 */

#include <xen/preempt.h>
#include <xen/irq.h>
#include <asm/system.h>

DEFINE_PER_CPU(unsigned int, __preempt_count);

bool_t in_atomic(void)
{
    return preempt_count() || in_irq() || !local_irq_is_enabled();
}

#ifndef NDEBUG
void ASSERT_NOT_IN_ATOMIC(void)
{
    ASSERT(!preempt_count());
    ASSERT(!in_irq());
    ASSERT(local_irq_is_enabled());
}
#endif
