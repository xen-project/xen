/******************************************************************************
 * ac_timer.h
 * 
 * Copyright (c) 2002-2003 Rolf Neugebauer
 * Copyright (c) 2002-2005 K A Fraser
 */

#ifndef _AC_TIMER_H_
#define _AC_TIMER_H_

#include <xen/spinlock.h>
#include <xen/time.h>
#include <xen/string.h>

struct ac_timer {
    /* System time expiry value (nanoseconds since boot). */
    s_time_t      expires;
    /* CPU on which this timer will be installed and executed. */
    unsigned int  cpu;
    /* On expiry, '(*function)(data)' will be executed in softirq context. */
    void        (*function)(void *);
    void         *data;
    /* Timer-heap offset. */
    unsigned int  heap_offset;
};

/*
 * All functions below can be called for any CPU from any CPU in any context.
 */

/* Returns TRUE if the given timer is on a timer list. */
static __inline__ int active_ac_timer(struct ac_timer *timer)
{
    return (timer->heap_offset != 0);
}

/*
 * It initialises the static fields of the ac_timer structure.
 * It can be called multiple times to reinitialise a single (inactive) timer.
 */
static __inline__ void init_ac_timer(
    struct ac_timer *timer,
    void           (*function)(void *),
    void            *data,
    unsigned int     cpu)
{
    memset(timer, 0, sizeof(*timer));
    timer->function = function;
    timer->data     = data;
    timer->cpu      = cpu;
}

/*
 * Set the expiry time and activate a timer (which must previously have been
 * initialised by init_ac_timer).
 */
extern void set_ac_timer(struct ac_timer *timer, s_time_t expires);

/*
 * Deactivate a timer (which must previously have been initialised by
 * init_ac_timer). This function has no effect if the timer is not currently
 * active.
 */
extern void rem_ac_timer(struct ac_timer *timer);

/*
 * Initialisation. Must be called before any other ac_timer function.
 */
extern void ac_timer_init(void);

#endif /* _AC_TIMER_H_ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
