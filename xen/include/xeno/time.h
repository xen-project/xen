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
#include <hypervisor-ifs/hypervisor-if.h>

/*
 * Init time
 */
extern int init_xeno_time();


/*
 * System Time
 * 64 bit value containing the nanoseconds elapsed since boot time.
 * This value is adjusted by frequency drift.
 * NOW() returns the current time.
 * The other macros are for convenience to approximate short intervals
 * of real time into system time 
 */

s_time_t get_s_time(void);

#define NOW()				((s_time_t)get_s_time())
#define SECONDS(_s)			(((s_time_t)(_s))  * 1000000000ULL )
#define MILLISECS(_ms)		(((s_time_t)(_ms)) * 1000000ULL )
#define MICROSECS(_us)		(((s_time_t)(_us)) * 1000ULL )
#define Time_Max			((s_time_t) 0x7fffffffffffffffLL)
#define FOREVER				Time_Max

/* Wall Clock Time */
struct timeval {
    long            tv_sec;         /* seconds */
    long            tv_usec;        /* microseconds */
};
  
extern void update_dom_time(shared_info_t *si);
extern void do_settime(unsigned long secs, unsigned long usecs, 
                       u64 system_time_base);
extern void do_timer(struct pt_regs *regs);

#endif /* __XENO_TIME_H__ */
