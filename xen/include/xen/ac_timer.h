/****************************************************************************
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

#include <xen/time.h>

struct ac_timer {
    /*
     * PUBLIC FIELDS
     */
    /* System time expiry value (nanoseconds since boot). */
    s_time_t         expires;
    /* CPU on which this timer will be installed and executed. */
    unsigned int     cpu;
    /* On expiry, '(*function)(data)' will be executed in softirq context. */
    unsigned long    data;
    void             (*function)(unsigned long);

    /*
     * PRIVATE FIELDS
     */
    unsigned int     heap_offset;
};

/*
 * This function can be called for any CPU from any CPU in any context.
 * It initialises the private fields of the ac_timer structure.
 */
static __inline__ void init_ac_timer(struct ac_timer *timer)
{
    timer->heap_offset = 0;
}

/*
 * This function can be called for any CPU from any CPU in any context.
 * It returns TRUE if the given timer is on a timer list.
 */
static __inline__ int active_ac_timer(struct ac_timer *timer)
{
    return (timer->heap_offset != 0);
}

/*
 * This function can be called for any CPU from any CPU in any context, BUT:
 *  -- The private fields must have been initialised (ac_timer_init).
 *  -- All public fields must be initialised.
 *  -- The timer must not currently be on a timer list.
 */
extern void add_ac_timer(struct ac_timer *timer);

/*
 * This function can be called for any CPU from any CPU in any context, BUT:
 *  -- The private fields must have been initialised (ac_timer_init).
 *  -- All public fields must be initialised.
 *  -- The timer must currently be on a timer list.
 */
extern void rem_ac_timer(struct ac_timer *timer);

/*
 * This function can be called for any CPU from any CPU in any context, BUT:
 *  -- The private fields must have been initialised (ac_timer_init).
 *  -- All public fields must be initialised.
 */
extern void mod_ac_timer(struct ac_timer *timer, s_time_t new_time);


/*
 * PRIVATE DEFINITIONS
 */

extern int reprogram_ac_timer(s_time_t timeout);

#endif /* _AC_TIMER_H_ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 */
