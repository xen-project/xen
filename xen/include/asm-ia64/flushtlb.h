#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
extern u32 tlbflush_time[NR_CPUS];

#define tlbflush_current_time() tlbflush_clock
#define tlbflush_filter_cpuset(x,y) (0)
#define NEED_FLUSH(x, y) (0)

#endif
