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

static inline void evtchn_set_pending(struct exec_domain *ed, int port)
{
    struct domain *d = ed->domain;
    shared_info_t *s = d->shared_info;
    int            running;

    /* These three operations must happen in strict order. */
    if ( !test_and_set_bit(port,    &s->evtchn_pending[0]) &&
         !test_bit        (port,    &s->evtchn_mask[0])    &&
         !test_and_set_bit(port>>5, &s->evtchn_pending_sel) )
    {
        /* The VCPU pending flag must be set /after/ update to evtchn-pend. */
        set_bit(0, &ed->vcpu_info->evtchn_upcall_pending);

        /*
         * NB1. 'flags' and 'processor' must be checked /after/ update of
         * pending flag. These values may fluctuate (after all, we hold no
         * locks) but the key insight is that each change will cause
         * evtchn_upcall_pending to be polled.
         * 
         * NB2. We save DF_RUNNING across the unblock to avoid a needless
         * IPI for domains that we IPI'd to unblock.
         */
        running = test_bit(EDF_RUNNING, &ed->ed_flags);
        exec_domain_unblock(ed);
        if ( running )
            smp_send_event_check_cpu(ed->processor);
    }
}

/*
 * send_guest_virq:
 *  @d:        Domain to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
static inline void send_guest_virq(struct exec_domain *ed, int virq)
{
    evtchn_set_pending(ed, ed->domain->virq_to_evtchn[virq]);
}

/*
 * send_guest_pirq:
 *  @d:        Domain to which physical IRQ should be sent
 *  @pirq:     Physical IRQ number
 */
static inline void send_guest_pirq(struct exec_domain *ed, int pirq)
{
    evtchn_set_pending(ed, ed->domain->pirq_to_evtchn[pirq]);
}

#define event_pending(_d)                                     \
    ((_d)->vcpu_info->evtchn_upcall_pending && \
     !(_d)->vcpu_info->evtchn_upcall_mask)

#endif /* __XEN_EVENT_H__ */
