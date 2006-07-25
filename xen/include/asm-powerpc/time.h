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

#ifndef _ASM_TIME_H_
#define _ASM_TIME_H_

#include <xen/types.h>

extern unsigned int timebase_freq;
#define CLOCK_TICK_RATE timebase_freq

#define watchdog_disable() ((void)0)
#define watchdog_enable()  ((void)0)

extern u64 get_timebase(void);

typedef u64 cycles_t;
static inline cycles_t get_cycles(void)
{
    cycles_t c;
    c = get_timebase();
    return c;
}

#endif
