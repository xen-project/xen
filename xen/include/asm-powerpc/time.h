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

#ifndef _ASM_TIME_H_
#define _ASM_TIME_H_

#include <xen/types.h>
#include <xen/time.h>
#include <xen/percpu.h>
#include <asm/processor.h>

extern s64 timebase_freq;
#define CLOCK_TICK_RATE timebase_freq

#define watchdog_disable() ((void)0)
#define watchdog_enable()  ((void)0)

static inline u64 get_timebase(void)
{
    u64 s;

#ifdef __PPC64__
    s = mftb();
#else
    do {
        unsigned up;
        unsigned lo;
        unsigned up2;

        up = mftbu();
        lo = mftbl();
        up2 = mftbu();
    } while (up1 != up2);
    s = ((ulong)up << 32) | lo;
#endif
    return s;
}

static inline void set_timebase(unsigned upper, unsigned lower)
{
    mttbl(0);
    mttbu(upper);
    mttbl(lower);
}

typedef u64 cycles_t;
static inline cycles_t get_cycles(void)
{
    cycles_t c;
    c = get_timebase();
    return c;
}

#define __nano(s) ((s) * 1000000000ULL)

static inline u64 ns_to_tb(u64 ns)
{
    return (ns * timebase_freq) / __nano(1);
}

static inline u64 tb_to_ns(u64 tb)
{
    return tb * (__nano(1) / timebase_freq);
}
#endif
