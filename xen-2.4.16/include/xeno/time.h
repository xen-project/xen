/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: time.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: This file provides a one stop shop for all time related
 *              issues within the hypervisor. 
 * 
 *              The Hypervisor provides the following notions of time:
 *              Cycle Counter Time, System Time, Wall Clock Time, and 
 *              Domain Virtual Time.
 *
 ****************************************************************************
 * $Id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn Exp $
 ****************************************************************************
 */



#ifndef __XENO_TIME_H__
#define __XENO_TIME_H__

#include <asm/ptrace.h>  /* XXX Only used for do_timer which should be moved */
#include <asm/time.h>    /* pull in architecture specific time definition */
#include <xeno/types.h>

/*
 * Cycle Counter Time (defined in asm/time.h)
 */


/*
 * System Time
 * 64 bit value containing the nanoseconds elapsed since boot time.
 * This value is adjusted by frequency drift.
 * NOW() returns the current time.
 * The other macros are for convenience to approximate short intervals
 * of real time into system time 
 */
#define NOW()				((s_time_t)get_s_time())
#define SECONDS(_s)			(((s_time_t)(_s))  * 1000000000UL )
#define TENTHS(_ts)			(((s_time_t)(_ts)) * 100000000UL )
#define HUNDREDTHS(_hs)		(((s_time_t)(_hs)) * 10000000UL )
#define MILLISECS(_ms)		(((s_time_t)(_ms)) * 1000000UL )
#define MICROSECS(_us)		(((s_time_t)(_us)) * 1000UL )
#define Time_Max			((s_time_t) 0x7fffffffffffffffLL)
#define FOREVER				Time_Max

/*
 * Wall Clock Time
 */
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

/*
 * Domain Virtual Time (defined in asm/time.h) 
 */
/* XXX Interface for getting and setting still missing */


/* XXX move this  */
extern void do_timer(struct pt_regs *regs);

#endif /* __XENO_TIME_H__ */
