/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003, K A Fraser
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/flushtlb.h>

u32 tlbflush_clock;
u32 tlbflush_time[NR_CPUS];

void tlb_clocktick(void)
{
    u32 y, ny;

    /* Tick the clock. 'y' contains the current time after the tick. */
    ny = tlbflush_clock;
    do {
#ifdef CONFIG_SMP
        if ( unlikely(((y = ny+1) & TLBCLOCK_EPOCH_MASK) == 0) )
        {
            new_tlbflush_clock_period();
            y = tlbflush_clock;
            break;
        }
#else
        y = ny+1;
#endif
    }
    while ( unlikely((ny = cmpxchg(&tlbflush_clock, y-1, y)) != y-1) );

    /* Update this CPU's timestamp to new time. */
    tlbflush_time[smp_processor_id()] = y;
}
