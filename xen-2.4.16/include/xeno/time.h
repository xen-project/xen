/******************************************************************************
 * time.h
 */

#ifndef __XENO_TIME_H__
#define __XENO_TIME_H__

#include <xeno/types.h>
#include <asm/ptrace.h>

struct timeval {
    long            tv_sec;         /* seconds */
    long            tv_usec;        /* microseconds */
};
  
struct timezone {
    int     tz_minuteswest; /* minutes west of Greenwich */
    int     tz_dsttime;     /* type of dst correction */
};

#ifdef __KERNEL__
extern void do_gettimeofday(struct timeval *tv);
extern void do_settimeofday(struct timeval *tv);
extern void get_fast_time(struct timeval *tv);
extern void (*do_get_fast_time)(struct timeval *);
#endif

extern void do_timer(struct pt_regs *regs);

#endif /* __XENO_TIME_H__ */
