/******************************************************************************
 * event.c
 * 
 * A nice interface for passing per-domain asynchronous events. 
 * These events are handled in the hypervisor, prior to return
 * to the guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xeno/config.h>
#include <xeno/event.h>

typedef void (*hyp_event_callback_fn_t)(void);

extern void schedule(void);
extern void flush_rx_queue(void);

/* Ordering must match definitions of _HYP_EVENT_* in xeno/sched.h */
static hyp_event_callback_fn_t event_call_fn[] = 
{
    schedule,
    flush_rx_queue,
    kill_domain
};

/* Handle outstanding events for the currently-executing domain. */
void do_hyp_events(void)
{
    int nr;
    while ( (nr = ffs(current->hyp_events)) != 0 )
        (event_call_fn[nr-1])();
}
