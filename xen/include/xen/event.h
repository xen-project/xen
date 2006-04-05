/******************************************************************************
 * event.h
 * 
 * A nice interface for passing asynchronous events to guest OSes.
 * 
 * Copyright (c) 2002-2006, K A Fraser
 */

#ifndef __XEN_EVENT_H__
#define __XEN_EVENT_H__

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <asm/bitops.h>
#include <asm/event.h>

extern void evtchn_set_pending(struct vcpu *v, int port);

/*
 * send_guest_vcpu_virq: Notify guest via a per-VCPU VIRQ.
 *  @v:        VCPU to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
extern void send_guest_vcpu_virq(struct vcpu *v, int virq);

/*
 * send_guest_global_virq: Notify guest via a global VIRQ.
 *  @d:        Domain to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
extern void send_guest_global_virq(struct domain *d, int virq);

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

#define evtchn_pending(d, p)                    \
    (test_bit((p), &(d)->shared_info->evtchn_pending[0]))

/* Send a notification from a local event-channel port. */
extern long evtchn_send(unsigned int lport);

/* Bind a local event-channel port to the specified VCPU. */
extern long evtchn_bind_vcpu(unsigned int port, unsigned int vcpu_id);

#endif /* __XEN_EVENT_H__ */
