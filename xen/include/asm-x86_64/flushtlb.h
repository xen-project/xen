/******************************************************************************
 * flushtlb.h
 * 
 * TLB flushes are timestamped using a global virtual 'clock' which ticks
 * on any TLB flush on any processor.
 * 
 * Copyright (c) 2003, K A Fraser
 */

#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

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
     * Why does this work?
     *  1. XOR sets high-order bits determines if stamps from differing epochs.
     *  2. Subtraction sets high-order bits if 'cpu_stamp > lastuse_stamp'.
     * In either case a flush is unnecessary: we therefore OR the results from
     * (1) and (2), mask the high-order bits, and return the inverse.
     */
    return !(((lastuse_stamp^cpu_stamp)|(lastuse_stamp-cpu_stamp)) & 
             ~TLBCLOCK_EPOCH_MASK);
}

extern u32 tlbflush_clock;
extern u32 tlbflush_time[NR_CPUS];

extern void tlb_clocktick(void);
extern void new_tlbflush_clock_period(void);

#endif /* __FLUSHTLB_H__ */
