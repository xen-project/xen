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

unsigned long tlbflush_epoch_changing;
u32 tlbflush_clock;
u32 tlbflush_time[NR_CPUS];

void tlb_clocktick(void)
{
    u32 y, ny;
    unsigned long flags;

    local_irq_save(flags);

    /* Tick the clock. 'y' contains the current time after the tick. */
    ny = tlbflush_clock;
    do {
#ifdef CONFIG_SMP
        if ( unlikely(((y = ny+1) & TLBCLOCK_EPOCH_MASK) == 0) )
        {
            /* Epoch is changing: the first to detect this is the leader. */
            if ( unlikely(!test_and_set_bit(0, &tlbflush_epoch_changing)) )
                raise_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ);
            /* The clock doesn't tick again until end of the epoch change. */
            y--;
            break;
        }
#else
        y = ny+1;
#endif
    }
    while ( unlikely((ny = cmpxchg(&tlbflush_clock, y-1, y)) != y-1) );

    /* Update this CPU's timestamp to new time. */
    tlbflush_time[smp_processor_id()] = y;

    local_irq_restore(flags);
}
