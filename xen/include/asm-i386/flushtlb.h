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
 * Every GLOBAL_FLUSH_PERIOD ticks of the tlbflush clock, every TLB in the
 * system is guaranteed to have been flushed.
 */
#define GLOBAL_FLUSH_PERIOD (1<<16)

/*
 * '_cpu_stamp' is the current timestamp for the CPU we are testing.
 * '_lastuse_stamp' is a timestamp taken when the PFN we are testing was last 
 * used for a purpose that may have caused the CPU's TLB to become tainted.
 */
#define NEED_FLUSH(_cpu_stamp, _lastuse_stamp) \
 (((_cpu_stamp) <= (_lastuse_stamp)) &&        \
  (((_lastuse_stamp) - (_cpu_stamp)) <= (2*GLOBAL_FLUSH_PERIOD)))

extern unsigned long tlbflush_mask;
extern unsigned long tlbflush_clock;
extern unsigned long tlbflush_time[NR_CPUS];

extern void new_tlbflush_clock_period(void);

extern void write_cr3_counted(unsigned long pa);
extern void flush_tlb_counted(void);

#endif /* __FLUSHTLB_H__ */
