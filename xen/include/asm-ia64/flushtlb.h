#ifndef __FLUSHTLB_H__
#define __FLUSHTLB_H__

#include <asm/tlbflush.h>

/* The current time as shown by the virtual TLB clock. */
extern u32 tlbflush_clock;

/* Time at which each CPU's TLB was last flushed. */
extern u32 tlbflush_time[NR_CPUS];

#define tlbflush_current_time() tlbflush_clock
#define tlbflush_filter(x,y) ((void)0)
#define NEED_FLUSH(x, y) (0)

#endif
