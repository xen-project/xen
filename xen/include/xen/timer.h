/******************************************************************************
 * timer.h
 * 
 * Copyright (c) 2002-2003 Rolf Neugebauer
 * Copyright (c) 2002-2005 K A Fraser
 */

#ifndef _TIMER_H_
#define _TIMER_H_

#include <xen/spinlock.h>
#include <xen/time.h>
#include <xen/string.h>
#include <xen/list.h>
#include <xen/percpu.h>

struct timer {
    /* System time expiry value (nanoseconds since boot). */
    s_time_t expires;

    /* Position in active-timer data structure. */
    union {
        /* Timer-heap offset (TIMER_STATUS_in_heap). */
        unsigned int heap_offset;
        /* Linked list (TIMER_STATUS_in_list). */
        struct timer *list_next;
        /* Linked list of inactive timers (TIMER_STATUS_inactive). */
        struct list_head inactive;
    };

    /* On expiry, '(*function)(data)' will be executed in softirq context. */
    void (*function)(void *);
    void *data;

    /* CPU on which this timer will be installed and executed. */
#define TIMER_CPU_status_killed 0xffffu /* Timer is TIMER_STATUS_killed */
    uint16_t cpu;

    /* Timer status. */
#define TIMER_STATUS_invalid  0 /* Should never see this.           */
#define TIMER_STATUS_inactive 1 /* Not in use; can be activated.    */
#define TIMER_STATUS_killed   2 /* Not in use; cannot be activated. */
#define TIMER_STATUS_in_heap  3 /* In use; on timer heap.           */
#define TIMER_STATUS_in_list  4 /* In use; on overflow linked list. */
    uint8_t status;
};

/*
 * All functions below can be called for any CPU from any CPU in any context.
 */

/*
 * Initialise a timer structure with an initial callback CPU, callback
 * function and callback data pointer. This function must only be called on
 * a brand new timer, or a killed timer. It must *never* execute concurrently
 * with any other operation on the same timer.
 */
void init_timer(
    struct timer *timer,
    void        (*function)(void *),
    void         *data,
    unsigned int  cpu);

/* Set the expiry time and activate a timer. */
void set_timer(struct timer *timer, s_time_t expires);

/*
 * Deactivate a timer This function has no effect if the timer is not currently
 * active.
 */
void stop_timer(struct timer *timer);

/* True if a timer is active, and its expiry time is earlier than t. */
bool timer_expires_before(struct timer *timer, s_time_t t);

#define timer_is_expired(t) timer_expires_before(t, NOW())

/* Migrate a timer to a different CPU. The timer may be currently active. */
void migrate_timer(struct timer *timer, unsigned int new_cpu);

/*
 * Deactivate a timer and prevent it from being re-set (future calls to
 * set_timer will silently fail). When this function returns it is guaranteed
 * that the timer callback handler is not running on any CPU.
 */
void kill_timer(struct timer *timer);

/* Bootstrap initialisation. Must be called before any other timer function. */
void timer_init(void);

/* Next timer deadline for each CPU. */
DECLARE_PER_CPU(s_time_t, timer_deadline);

/* Arch-defined function to reprogram timer hardware for new deadline. */
int reprogram_timer(s_time_t timeout);

/* Calculate the aligned first tick time for a given periodic timer. */
s_time_t align_timer(s_time_t firsttick, uint64_t period);

#endif /* _TIMER_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
