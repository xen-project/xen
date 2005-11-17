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
#include <xen/smp.h>
#include <asm/bitops.h>
#include <asm/event.h>

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

    /* These four operations must happen in strict order. */
    if ( !test_and_set_bit(port, &s->evtchn_pending[0]) &&
         !test_bit        (port, &s->evtchn_mask[0])    &&
         !test_and_set_bit(port / BITS_PER_LONG,
                           &v->vcpu_info->evtchn_pending_sel) &&
         !test_and_set_bit(0, &v->vcpu_info->evtchn_upcall_pending) )
    {
        evtchn_notify(v);
    }
}

/*
 * send_guest_virq:
 *  @v:        VCPU to which virtual IRQ should be sent
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
extern void send_guest_pirq(struct domain *d, int pirq);

/* Note: Bitwise operations result in fast code with no branches. */
#define event_pending(v)                        \
    (!!(v)->vcpu_info->evtchn_upcall_pending &  \
      !(v)->vcpu_info->evtchn_upcall_mask)

#endif /* __XEN_EVENT_H__ */
