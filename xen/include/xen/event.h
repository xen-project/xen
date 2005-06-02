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
 * EVENT-CHANNEL NOTIFICATIONS
 * NB. On x86, the atomic bit operations also act as memory barriers. There
 * is therefore sufficiently strict ordering for this architecture -- others
 * may require explicit memory barriers.
 */

static inline void evtchn_set_pending(struct vcpu *v, int port)
{
    struct domain *d = v->domain;
    shared_info_t *s = d->shared_info;
    int            running;

    /* These three operations must happen in strict order. */
    if ( !test_and_set_bit(port,    &s->evtchn_pending[0]) &&
         !test_bit        (port,    &s->evtchn_mask[0])    &&
         !test_and_set_bit(port>>5, &v->vcpu_info->evtchn_pending_sel) )
    {
        /* The VCPU pending flag must be set /after/ update to evtchn-pend. */
        set_bit(0, &v->vcpu_info->evtchn_upcall_pending);

        /*
         * NB1. 'vcpu_flags' and 'processor' must be checked /after/ update of
         * pending flag. These values may fluctuate (after all, we hold no
         * locks) but the key insight is that each change will cause
         * evtchn_upcall_pending to be polled.
         * 
         * NB2. We save VCPUF_running across the unblock to avoid a needless
         * IPI for domains that we IPI'd to unblock.
         */
        running = test_bit(_VCPUF_running, &v->vcpu_flags);
        vcpu_unblock(v);
        if ( running )
            smp_send_event_check_cpu(v->processor);
    }
}

/*
 * send_guest_virq:
 *  @d:        Domain to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
static inline void send_guest_virq(struct vcpu *v, int virq)
{
    int port = v->virq_to_evtchn[virq];

    if ( likely(port != 0) )
        evtchn_set_pending(v, port);
}

/*
 * send_guest_pirq:
 *  @d:        Domain to which physical IRQ should be sent
 *  @pirq:     Physical IRQ number
 */
static inline void send_guest_pirq(struct vcpu *v, int pirq)
{
    evtchn_set_pending(v, v->domain->pirq_to_evtchn[pirq]);
}

#define event_pending(_d)                                     \
    ((_d)->vcpu_info->evtchn_upcall_pending && \
     !(_d)->vcpu_info->evtchn_upcall_mask)

#endif /* __XEN_EVENT_H__ */
