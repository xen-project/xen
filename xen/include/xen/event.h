/******************************************************************************
 * event.h
 * 
 * A nice interface for passing asynchronous events to guest OSes.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __XEN_EVENT_H__
#define __XEN_EVENT_H__

#include <xen/config.h>
#include <xen/sched.h>
#include <asm/bitops.h>

/*
 * GENERIC SCHEDULING CALLBACK MECHANISMS
 */

/* Schedule an asynchronous callback for the specified domain. */
static inline void __guest_notify(struct task_struct *p)
{
#ifdef CONFIG_SMP
    unsigned long flags, cpu_mask;

    spin_lock_irqsave(&schedule_lock[p->processor], flags);
    if ( p->state == TASK_INTERRUPTIBLE )
        __wake_up(p);
    cpu_mask = __reschedule(p);
    if ( p->has_cpu )
        cpu_mask |= 1 << p->processor;
    spin_unlock_irqrestore(&schedule_lock[p->processor], flags);

    cpu_mask &= ~(1 << smp_processor_id());
    if ( cpu_mask != 0 )
        smp_send_event_check_mask(cpu_mask);
#else
    if ( p->state == TASK_INTERRUPTIBLE )
        wake_up(p);
    reschedule(p);
#endif
}

static inline void guest_notify(struct task_struct *p)
{
    /*
     * Upcall already pending or upcalls masked?
     * NB. Suitably synchronised on x86:
     *  We must set the pending bit before checking the mask, but this is
     *  guaranteed to occur because test_and_set_bit() is an ordering barrier.
     */
    if ( !test_and_set_bit(0, &p->shared_info->evtchn_upcall_pending) &&
         !test_bit(0, &p->shared_info->evtchn_upcall_mask) )
        __guest_notify(p);
}


/*
 * EVENT-CHANNEL NOTIFICATIONS
 * NB. As in guest_notify, evtchn_set_* is suitably synchronised on x86.
 */

static inline void evtchn_set_pending(struct task_struct *p, int port)
{
    shared_info_t *s = p->shared_info;
    if ( !test_and_set_bit(port,    &s->evtchn_pending[0]) &&
         !test_bit        (port,    &s->evtchn_mask[0])    &&
         !test_and_set_bit(port>>5, &s->evtchn_pending_sel) )
        guest_notify(p);
}

static inline void evtchn_set_exception(struct task_struct *p, int port)
{
    if ( !test_and_set_bit(port, &p->shared_info->evtchn_exception[0]) )
        evtchn_set_pending(p, port);
}

/*
 * send_guest_virq:
 *  @p:        Domain to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
static inline void send_guest_virq(struct task_struct *p, int virq)
{
    evtchn_set_pending(p, p->virq_to_evtchn[virq]);
}

/*
 * send_guest_pirq:
 *  @p:        Domain to which physical IRQ should be sent
 *  @pirq:     Physical IRQ number
 */
static inline void send_guest_pirq(struct task_struct *p, int pirq)
{
    evtchn_set_pending(p, p->pirq_to_evtchn[pirq]);
}


/*
 * HYPERVISOR-HANDLED EVENTS
 */

static inline void send_hyp_event(struct task_struct *p, int event)
{
    if ( !test_and_set_bit(event, &p->hyp_events) )
        __guest_notify(p);
}

/* Called on return from (architecture-dependent) entry.S. */
void do_hyp_events(void);

#endif /* __XEN_EVENT_H__ */
