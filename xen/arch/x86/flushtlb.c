/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2004, K A Fraser
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/flushtlb.h>

u32 tlbflush_clock;
u32 tlbflush_time[NR_CPUS];

void write_cr3(unsigned long cr3)
{
    u32 t, t1, t2;
    unsigned long flags;

    local_irq_save(flags);

    /*
     * Tick the clock, which is incremented by two each time. The L.S.B. is
     * used to decide who will control the epoch change, when one is required.
     */
    t = tlbflush_clock;
    do {
        t1 = t;      /* t1: Time before this clock tick. */
        t2 = t + 2;  /* t2: Time after this clock tick. */
        if ( unlikely(t2 & 1) )
        {
            /* Epoch change: someone else is leader. */
            t2 = t; /* no tick */
            goto skip_clocktick;
        }
        else if ( unlikely((t2 & TLBCLOCK_EPOCH_MASK) == 0) )
        {
            /* Epoch change: we may become leader. */
            t2--; /* half tick */
        }
    }
    while ( unlikely((t = cmpxchg(&tlbflush_clock, t1, t2)) != t1) );

    /* Epoch change: we are the leader. */
    if ( unlikely(t2 & 1) )
        raise_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ);

 skip_clocktick:
    __asm__ __volatile__ ( "mov"__OS" %0, %%cr3" : : "r" (cr3) : "memory" );

    /* Update this CPU's timestamp to new time. */
    tlbflush_time[smp_processor_id()] = t2;

    local_irq_restore(flags);
}
