/******************************************************************************
 * event.h
 * 
 * A nice interface for passing asynchronous events to guest OSes.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xeno/config.h>
#include <xeno/sched.h>
#include <asm/bitops.h>

#ifdef CONFIG_SMP

/*
 * mark_guest_event:
 *  @p:        Domain to which event should be passed
 *  @event:    Event number
 *  RETURNS:   "Bitmask" of CPU on which process is currently running
 * 
 * Idea is that caller may loop on task_list, looking for domains
 * to pass events to (using this function). The caller accumulates the
 * bits returned by this function (ORing them together) then calls
 * event_notify().
 * 
 * Guest_events are per-domain events passed directly to the guest OS
 * in ring 1. 
 */
static inline unsigned long mark_guest_event(struct task_struct *p, int event)
{
    if ( test_and_set_bit(event, &p->shared_info->events) )
        return 0;

    /*
     * No need for the runqueue_lock! The check below does not race
     * with the setting of has_cpu, because that is set with runqueue_lock
     * held. The lock must be released before hypervisor exit (and so
     * a write barrier executed). And, just before hypervisor exit, 
     * outstanding events are checked. So bit is certainly set early enough.
     */
    smp_mb();
    if ( p->state == TASK_INTERRUPTIBLE ) wake_up(p);
    reschedule(p);
    return p->has_cpu ? (1 << p->processor) : 0;
}

/* As above, but hyp_events are handled within the hypervisor. */
static inline unsigned long mark_hyp_event(struct task_struct *p, int event)
{
    if ( test_and_set_bit(event, &p->shared_info->events) )
        return 0;
    smp_mb();
    if ( p->state == TASK_INTERRUPTIBLE ) wake_up(p);
    reschedule(p);
    return p->has_cpu ? (1 << p->processor) : 0;
}

/* Notify the given set of CPUs that guest events may be outstanding. */
static inline void guest_event_notify(unsigned long cpu_mask)
{
    cpu_mask &= ~(1 << smp_processor_id());
    if ( cpu_mask != 0 ) smp_send_event_check_mask(cpu_mask);
}

#else

static inline unsigned long mark_guest_event(struct task_struct *p, int event)
{
    if ( !test_and_set_bit(event, &p->shared_info->events) )
    {
        if ( p->state == TASK_INTERRUPTIBLE ) wake_up(p);
        reschedule(p);
    }
    return 0;
}

static inline unsigned long mark_hyp_event(struct task_struct *p, int event)
{
    if ( !test_and_set_bit(event, &p->hyp_events) )
    {
        if ( p->state == TASK_INTERRUPTIBLE ) wake_up(p);
        reschedule(p);
    }
    return 0;
}

#define guest_event_notify(_mask) ((void)0)

#endif

/* Notify hypervisor events in thesame way as for guest OS events. */
#define hyp_event_notify(_mask) guest_event_notify(_mask)

/* Clear a guest-OS event from a per-domain mask. */
static inline void clear_guest_event(struct task_struct *p, int event)
{
    clear_bit(event, &p->shared_info->events);
}

/* Clear a hypervisor event from a per-domain mask. */
static inline void clear_hyp_event(struct task_struct *p, int event)
{
    clear_bit(event, &p->hyp_events);
}

/* Called on return from (architecture-dependent) entry.S. */
void do_hyp_events(void);
