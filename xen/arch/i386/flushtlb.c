/******************************************************************************
 * flushtlb.c
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003, K A Fraser
 */

#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/flushtlb.h>

unsigned long tlbflush_mask;
unsigned long tlbflush_clock;
unsigned long tlbflush_time[NR_CPUS];

static inline void tlb_clocktick(unsigned int cpu)
{
    unsigned long x, nx, y, ny;
    
    clear_bit(cpu, &tlbflush_mask);

    /* Tick the clock. 'y' contains the current time after the tick. */
    ny = tlbflush_clock;
    do {
#ifdef CONFIG_SMP
        if ( unlikely(((y = ny+1) & (GLOBAL_FLUSH_PERIOD - 1)) == 0) )
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

    /* Update cpu's timestamp to current time, unless someone else beats us. */
    nx = tlbflush_time[cpu];
    do { 
        if ( unlikely((x = nx) >= y) )
            break;
    }
    while ( unlikely((nx = cmpxchg(&tlbflush_time[cpu], x, y)) != x) );
}

void write_cr3_counted(unsigned long pa)
{
    __asm__ __volatile__ ( 
        "movl %0, %%cr3"
        : : "r" (pa) : "memory" );
    tlb_clocktick(smp_processor_id());
}

void flush_tlb_counted(void)
{
    __asm__ __volatile__ ( 
        "movl %%cr3, %%eax; movl %%eax, %%cr3"
        : : : "memory", "eax" );
    tlb_clocktick(smp_processor_id());
}

