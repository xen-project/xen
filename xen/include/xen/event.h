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
static inline void guest_async_callback(struct domain *p)
{
    if ( !domain_unblock(p) && p->has_cpu && (p != current) )
        smp_send_event_check_mask(1 << p->processor);
}

/*
 * EVENT-CHANNEL NOTIFICATIONS
 * NB. On x86, the atomic bit operations also act as memory barriers. There
 * is therefore sufficiently strict ordering for this architecture -- others
 * may require explicit memory barriers.
 */

static inline void evtchn_set_pending(struct domain *p, int port)
{
    shared_info_t *s = p->shared_info;
    if ( !test_and_set_bit(port,    &s->evtchn_pending[0]) &&
         !test_bit        (port,    &s->evtchn_mask[0])    &&
         !test_and_set_bit(port>>5, &s->evtchn_pending_sel) )
    {
        /* The VCPU pending flag must be set /after/ update to evtchn-pend. */
        s->vcpu_data[0].evtchn_upcall_pending = 1;
        guest_async_callback(p);
    }
}

static inline void evtchn_set_exception(struct domain *p, int port)
{
    if ( !test_and_set_bit(port, &p->shared_info->evtchn_exception[0]) )
        evtchn_set_pending(p, port);
}

/*
 * send_guest_virq:
 *  @p:        Domain to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
static inline void send_guest_virq(struct domain *p, int virq)
{
    evtchn_set_pending(p, p->virq_to_evtchn[virq]);
}

/*
 * send_guest_pirq:
 *  @p:        Domain to which physical IRQ should be sent
 *  @pirq:     Physical IRQ number
 */
static inline void send_guest_pirq(struct domain *p, int pirq)
{
    evtchn_set_pending(p, p->pirq_to_evtchn[pirq]);
}

#define event_pending(_d)                                     \
    ((_d)->shared_info->vcpu_data[0].evtchn_upcall_pending && \
     !(_d)->shared_info->vcpu_data[0].evtchn_upcall_mask)

#endif /* __XEN_EVENT_H__ */
