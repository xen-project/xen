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
#include <xen/smp.h>

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
extern u32 tlbflush_time[NR_CPUS];

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

extern void new_tlbflush_clock_period(void);

/* Read pagetable base. */
static inline unsigned long read_cr3(void)
{
    unsigned long cr3;
    __asm__ __volatile__ (
        "mov"__OS" %%cr3, %0" : "=r" (cr3) : );
    return cr3;
}

/* Write pagetable base and implicitly tick the tlbflush clock. */
extern void write_cr3(unsigned long cr3);

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_pgtables(mm, start, end) flushes a range of page tables
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#define __flush_tlb()                                             \
    do {                                                          \
        unsigned long cr3 = read_cr3();                           \
        write_cr3(cr3);                                           \
    } while ( 0 )

#ifndef CONFIG_SMP

#define flush_tlb()               __flush_tlb()
#define flush_tlb_all()           __flush_tlb()
#define flush_tlb_all_pge()       __flush_tlb_pge()
#define local_flush_tlb()         __flush_tlb()
#define flush_tlb_cpu(_cpu)       __flush_tlb()
#define flush_tlb_mask(_mask)     __flush_tlb()
#define try_flush_tlb_mask(_mask) __flush_tlb()

#else

#include <xen/smp.h>

extern int try_flush_tlb_mask(unsigned long mask);
extern void flush_tlb_mask(unsigned long mask);
extern void flush_tlb_all_pge(void);

#define flush_tlb()	    __flush_tlb()
#define flush_tlb_all()     flush_tlb_mask((1 << smp_num_cpus) - 1)
#define local_flush_tlb()   __flush_tlb()
#define flush_tlb_cpu(_cpu) flush_tlb_mask(1 << (_cpu))

#endif

#endif /* __FLUSHTLB_H__ */
