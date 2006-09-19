/******************************************************************************
 * flushtlb.h
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003-2004, K A Fraser
 */

#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <xen/config.h>
#include <xen/percpu.h>
#include <xen/smp.h>
#include <xen/types.h>

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
DECLARE_PER_CPU(u32, tlbflush_time);

#define tlbflush_current_time() tlbflush_clock

/*
 * @cpu_stamp is the timestamp at last TLB flush for the CPU we are testing.
 * @lastuse_stamp is a timestamp taken when the PFN we are testing was last 
 * used for a purpose that may have caused the CPU's TLB to become tainted.
 */
static inline int NEED_FLUSH(u32 cpu_stamp, u32 lastuse_stamp)
{
    u32 curr_time = tlbflush_current_time();
    /*
     * Two cases:
     *  1. During a wrap, the clock ticks over to 0 while CPUs catch up. For
     *     safety during this period, we force a flush if @curr_time == 0.
     *  2. Otherwise, we look to see if @cpu_stamp <= @lastuse_stamp.
     *     To detect false positives because @cpu_stamp has wrapped, we
     *     also check @curr_time. If less than @lastuse_stamp we definitely
     *     wrapped, so there's no need for a flush (one is forced every wrap).
     */
    return ((curr_time == 0) ||
            ((cpu_stamp <= lastuse_stamp) &&
             (lastuse_stamp <= curr_time)));
}

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
#define tlbflush_filter(mask, page_timestamp)                           \
do {                                                                    \
    unsigned int cpu;                                                   \
    for_each_cpu_mask ( cpu, mask )                                     \
        if ( !NEED_FLUSH(per_cpu(tlbflush_time, cpu), page_timestamp) ) \
            cpu_clear(cpu, mask);                                       \
} while ( 0 )

extern void new_tlbflush_clock_period(void);

/* Read pagetable base. */
static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    __asm__ __volatile__ (
        "mov %%cr3, %0" : "=r" (cr3) : );
    return cr3;
}

/* Write pagetable base and implicitly tick the tlbflush clock. */
extern void write_cr3(unsigned long cr3);

/* Flush guest mappings from the TLB and implicitly tick the tlbflush clock. */
extern void local_flush_tlb(void);

#define local_flush_tlb_pge()                                     \
    do {                                                          \
        __pge_off();                                              \
        local_flush_tlb();                                        \
        __pge_on();                                               \
    } while ( 0 )

#define local_flush_tlb_one(__addr) \
    __asm__ __volatile__("invlpg %0": :"m" (*(char *) (__addr)))

#define flush_tlb_all()     flush_tlb_mask(cpu_online_map)

#ifndef CONFIG_SMP
#define flush_tlb_all_pge()        local_flush_tlb_pge()
#define flush_tlb_mask(mask)       local_flush_tlb()
#define flush_tlb_one_mask(mask,v) local_flush_tlb_one(_v)
#else
#include <xen/smp.h>
#define FLUSHVA_ALL (~0UL)
extern void flush_tlb_all_pge(void);
extern void __flush_tlb_mask(cpumask_t mask, unsigned long va);
#define flush_tlb_mask(mask)       __flush_tlb_mask(mask,FLUSHVA_ALL)
#define flush_tlb_one_mask(mask,v) __flush_tlb_mask(mask,(unsigned long)(v))
#endif

#endif /* __FLUSHTLB_H__ */
