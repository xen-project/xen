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

/*
 * Every time the TLB clock passes an "epoch", every CPU's TLB is flushed.
 * Therefore, if the current TLB time and a previously-read timestamp differ
 * in their significant bits (i.e., ~TLBCLOCK_EPOCH_MASK), then the TLB clock
 * has wrapped at least once and every CPU's TLB is guaranteed to have been
 * flushed meanwhile.
 * This allows us to deal gracefully with a bounded (a.k.a. wrapping) clock.
 */
#define TLBCLOCK_EPOCH_MASK ((1U<<16)-1)

/*
 * 'cpu_stamp' is the current timestamp for the CPU we are testing.
 * 'lastuse_stamp' is a timestamp taken when the PFN we are testing was last 
 * used for a purpose that may have caused the CPU's TLB to become tainted.
 */
static inline int NEED_FLUSH(u32 cpu_stamp, u32 lastuse_stamp)
{
    /*
     * Worst case in which a flush really is required:
     *  CPU has not flushed since end of last epoch (cpu_stamp = 0x0000ffff).
     *  Clock has run to end of current epoch (clock = 0x0001ffff).
     *  Therefore maximum valid difference is 0x10000 (EPOCH_MASK + 1).
     * N.B. The clock cannot run further until the CPU has flushed once more
     * and updated its stamp to 0x1ffff, so this is as 'far out' as it can get.
     */
    return ((lastuse_stamp - cpu_stamp) <= (TLBCLOCK_EPOCH_MASK + 1));
}

extern unsigned long tlbflush_epoch_changing;
extern u32 tlbflush_clock;
extern u32 tlbflush_time[NR_CPUS];

extern void tlb_clocktick(void);
extern void new_tlbflush_clock_period(void);

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
