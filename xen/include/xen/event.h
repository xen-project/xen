/******************************************************************************
 * event.h
 * 
 * A nice interface for passing asynchronous events to guest OSes.
 * 
 * Copyright (c) 2002-2006, K A Fraser
 */

#ifndef __XEN_EVENT_H__
#define __XEN_EVENT_H__

#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <asm/bitops.h>
#include <asm/event.h>

/*
 * send_guest_vcpu_virq: Notify guest via a per-VCPU VIRQ.
 *  @v:        VCPU to which virtual IRQ should be sent
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
void send_guest_vcpu_virq(struct vcpu *v, uint32_t virq);

/*
 * send_global_virq: Notify the domain handling a global VIRQ.
 *  @virq:     Virtual IRQ number (VIRQ_*)
 */
void send_global_virq(uint32_t virq);

/*
 * sent_global_virq_handler: Set a global VIRQ handler.
 *  @d:        New target domain for this VIRQ
 *  @virq:     Virtual IRQ number (VIRQ_*), must be global
 */
int set_global_virq_handler(struct domain *d, uint32_t virq);

/*
 * send_guest_pirq:
 *  @d:        Domain to which physical IRQ should be sent
 *  @pirq:     Physical IRQ number
 * Returns TRUE if the delivery port was already pending.
 */
int send_guest_pirq(struct domain *, const struct pirq *);

/* Send a notification from a given domain's event-channel port. */
int evtchn_send(struct domain *d, unsigned int lport);

/* Bind a local event-channel port to the specified VCPU. */
long evtchn_bind_vcpu(unsigned int port, unsigned int vcpu_id);

/* Unmask a local event-channel port. */
int evtchn_unmask(unsigned int port);

/* Move all PIRQs after a vCPU was moved to another pCPU. */
void evtchn_move_pirqs(struct vcpu *v);

/* Allocate/free a Xen-attached event channel port. */
typedef void (*xen_event_channel_notification_t)(
    struct vcpu *v, unsigned int port);
int alloc_unbound_xen_event_channel(
    struct vcpu *local_vcpu, domid_t remote_domid,
    xen_event_channel_notification_t notification_fn);
void free_xen_event_channel(
    struct vcpu *local_vcpu, int port);

/* Query if event channel is in use by the guest */
int guest_enabled_event(struct vcpu *v, uint32_t virq);

/* Notify remote end of a Xen-attached event channel.*/
void notify_via_xen_event_channel(struct domain *ld, int lport);

/* Wait on a Xen-attached event channel. */
#define wait_on_xen_event_channel(port, condition)                      \
    do {                                                                \
        if ( condition )                                                \
            break;                                                      \
        set_bit(_VPF_blocked_in_xen, &current->pause_flags);            \
        mb(); /* set blocked status /then/ re-evaluate condition */     \
        if ( condition )                                                \
        {                                                               \
            clear_bit(_VPF_blocked_in_xen, &current->pause_flags);      \
            break;                                                      \
        }                                                               \
        raise_softirq(SCHEDULE_SOFTIRQ);                                \
        do_softirq();                                                   \
    } while ( 0 )

#define prepare_wait_on_xen_event_channel(port)                         \
    do {                                                                \
        set_bit(_VPF_blocked_in_xen, &current->pause_flags);            \
        raise_softirq(SCHEDULE_SOFTIRQ);                                \
        mb(); /* set blocked status /then/ caller does his work */      \
    } while ( 0 )

#endif /* __XEN_EVENT_H__ */
