/******************************************************************************
 * flushtlb.c
 * based on x86 flushtlb.c
 * 
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/vcpu.h>
#include <asm/vhpt.h>
#include <asm/flushtlb.h>

/* Debug builds: Wrap frequently to stress-test the wrap logic. */
#ifdef NDEBUG
#define WRAP_MASK (0xFFFFFFFFU)
#else
#define WRAP_MASK (0x000003FFU)
#endif

volatile u32 tlbflush_clock = 1U; /* 1 greater than tlbflush_time. */
DEFINE_PER_CPU(volatile u32, tlbflush_time);

u32
tlbflush_clock_inc_and_return(void)
{
    u32 t, t1, t2;

    t = tlbflush_clock;
    do {
        t1 = t2 = t;
        /* Clock wrapped: someone else is leading a global TLB shootdown. */
        if (unlikely(t1 == 0))
            return t2;
        t2 = (t + 1) & WRAP_MASK;
        t = ia64_cmpxchg(acq, &tlbflush_clock, t1, t2, sizeof(tlbflush_clock));
    } while (unlikely(t != t1));

    /* Clock wrapped: we will lead a global TLB shootdown. */
    if (unlikely(t2 == 0))
        raise_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ);

    return t2;
}

static void
tlbflush_clock_local_flush(void *unused)
{
    local_vhpt_flush();
    local_flush_tlb_all();
}

void
new_tlbflush_clock_period(void)
{
    /* flush all vhpt of physical cpu and mTLB */
    on_each_cpu(tlbflush_clock_local_flush, NULL, 1, 1);

    /*
     * if global TLB shootdown is finished, increment tlbflush_time
     * atomic operation isn't necessary because we know that tlbflush_clock
     * stays 0.
     */
    tlbflush_clock++;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
