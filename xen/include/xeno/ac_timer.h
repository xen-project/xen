/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: ac_timer.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: Accurate timer for the Hypervisor
 * 
 ****************************************************************************
 * $Id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn Exp $
 ****************************************************************************
 */

#ifndef _AC_TIMER_H_
#define _AC_TIMER_H_

#include <xeno/time.h> /* include notion of time */

/*
 * The Xen Hypervisor provides two types of timers:
 *
 * - Linux style, jiffy based timers for legacy code and coarse grain timeouts
 *   These are defined in ./include/xeno/timer.h and implemented in
 *   ./common/timer.c. Unlike in Linux they are executed not on a periodic
 *   timer interrupt but "occasionally" with somewhat lesser accuracy.
 *  
 * - accurate timers defined in this file and implemented in
 *   ./common/ac_timer.c. These are implemented using a programmable timer
 *   interrupt and are thus as accurate as the hardware allows. Where possible
 *   we use the local APIC for this purpose. However, this fact is hidden
 *   behind a architecture independent layer.
 *   accurate timers are programmed using system time.
 * 
 * The interface to accurate timers is very similar to Linux timers with the
 * exception that the expires value is not expressed in jiffies but in ns from
 * boot time.  Its implementation however, is entirely different.
 */

struct ac_timer {
    struct list_head timer_list;
    s_time_t         expires;   /* system time time out value */
    unsigned long    data;
    void             (*function)(unsigned long);
    int              cpu;
};

/* interface for "clients" */
extern void add_ac_timer(struct ac_timer *timer);
extern void rem_ac_timer(struct ac_timer *timer);
extern void mod_ac_timer(struct ac_timer *timer, s_time_t new_time);
static __inline__ void init_ac_timer(struct ac_timer *timer, int cpu)
{
    timer->cpu = cpu;
    timer->timer_list.next = NULL;
}
/* check if ac_timer is active, i.e., on the list */
static __inline__ int active_ac_timer(struct ac_timer *timer)
{
    return (timer->timer_list.next != NULL);
}

/* interface used by programmable timer, implemented hardware dependent */
extern int  reprogram_ac_timer(s_time_t timeout);
extern void do_ac_timer(void);

#endif /* _AC_TIMER_H_ */
