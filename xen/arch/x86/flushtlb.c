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

/* Debug builds: Wrap frequently to stress-test the wrap logic. */
#ifdef NDEBUG
#define WRAP_MASK (0xFFFFFFFFU)
#else
#define WRAP_MASK (0x000003FFU)
#endif

u32 tlbflush_clock = 1U;
u32 tlbflush_time[NR_CPUS];

void write_cr3(unsigned long cr3)
{
    u32 t, t1, t2;
    unsigned long flags;

    /* This non-reentrant function is sometimes called in interrupt context. */
    local_irq_save(flags);

    /*
     * STEP 1. Increment the virtual clock *before* flushing the TLB.
     *         If we do it after, we race other CPUs invalidating PTEs.
     *         (e.g., a page invalidated after the flush might get the old 
     *          timestamp, but this CPU can speculatively fetch the mapping
     *          into its TLB after the flush but before inc'ing the clock).
     */

    t = tlbflush_clock;
    do {
        t1 = t2 = t;
        /* Clock wrapped: someone else is leading a global TLB shootodiown. */
        if ( unlikely(t1 == 0) )
            goto skip_clocktick;
        t2 = (t + 1) & WRAP_MASK;
    }
    while ( unlikely((t = cmpxchg(&tlbflush_clock, t1, t2)) != t1) );

    /* Clock wrapped: we will lead a global TLB shootdown. */
    if ( unlikely(t2 == 0) )
        raise_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ);

    /*
     * STEP 2. Update %CR3, thereby flushing the TLB.
     */

 skip_clocktick:
    __asm__ __volatile__ ( "mov"__OS" %0, %%cr3" : : "r" (cr3) : "memory" );

    /*
     * STEP 3. Update this CPU's timestamp.
     */

    tlbflush_time[smp_processor_id()] = t2;

    local_irq_restore(flags);
}
