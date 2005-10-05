/******************************************************************************
 * event_channel.h
 * 
 * Event channels between domains.
 * 
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef __XEN_PUBLIC_EVENT_CHANNEL_H__
#define __XEN_PUBLIC_EVENT_CHANNEL_H__

/*
 * EVTCHNOP_alloc_unbound: Allocate a port in <dom> for later binding to
 * <remote_dom>. <port> may be wildcarded by setting to zero, in which case a
 * fresh port will be allocated, and the field filled in on return.
 * NOTES:
 *  1. If the caller is unprivileged then <dom> must be DOMID_SELF.
 */
#define EVTCHNOP_alloc_unbound    6
typedef struct evtchn_alloc_unbound {
    /* IN parameters */
    domid_t dom, remote_dom;
    /* IN/OUT parameters */
    u32     port;
} evtchn_alloc_unbound_t;

/*
 * EVTCHNOP_bind_interdomain: Construct an interdomain event channel between
 * <dom1> and <dom2>. Either <port1> or <port2> may be wildcarded by setting to
 * zero. On successful return both <port1> and <port2> are filled in and
 * <dom1,port1> is fully bound to <dom2,port2>.
 * 
 * NOTES:
 *  1. A wildcarded port is allocated from the relevant domain's free list
 *     (i.e., some port that was previously EVTCHNSTAT_closed). However, if the
 *     remote port pair is already fully bound then a port is not allocated,
 *     and instead the existing local port is returned to the caller.
 *  2. If the caller is unprivileged then <dom1> must be DOMID_SELF.
 *  3. If the caller is unprivileged and <dom2,port2> is EVTCHNSTAT_closed
 *     then <dom2> must be DOMID_SELF.
 *  4. If either port is already bound then it must be bound to the other
 *     specified domain and port (if not wildcarded).
 *  5. If either port is awaiting binding (EVTCHNSTAT_unbound) then it must
 *     be awaiting binding to the other domain, and the other port pair must
 *     be closed or unbound.
 */
#define EVTCHNOP_bind_interdomain 0
typedef struct evtchn_bind_interdomain {
    /* IN parameters. */
    domid_t dom1, dom2;
    /* IN/OUT parameters. */
    u32     port1, port2;
} evtchn_bind_interdomain_t;

/*
 * EVTCHNOP_bind_virq: Bind a local event channel to VIRQ <irq> on specified
 * vcpu.
 * NOTES:
 *  1. A virtual IRQ may be bound to at most one event channel per vcpu.
 *  2. The allocated event channel is bound to the specified vcpu. The binding
 *     may not be changed.
 */
#define EVTCHNOP_bind_virq        1
typedef struct evtchn_bind_virq {
    /* IN parameters. */
    u32 virq;
    u32 vcpu;
    /* OUT parameters. */
    u32 port;
} evtchn_bind_virq_t;

/*
 * EVTCHNOP_bind_pirq: Bind a local event channel to PIRQ <irq>.
 * NOTES:
 *  1. A physical IRQ may be bound to at most one event channel per domain.
 *  2. Only a sufficiently-privileged domain may bind to a physical IRQ.
 */
#define EVTCHNOP_bind_pirq        2
typedef struct evtchn_bind_pirq {
    /* IN parameters. */
    u32 pirq;
#define BIND_PIRQ__WILL_SHARE 1
    u32 flags; /* BIND_PIRQ__* */
    /* OUT parameters. */
    u32 port;
} evtchn_bind_pirq_t;

/*
 * EVTCHNOP_bind_ipi: Bind a local event channel to receive events.
 * NOTES:
 *  1. The allocated event channel is bound to the specified vcpu. The binding
 *     may not be changed.
 */
#define EVTCHNOP_bind_ipi         7
typedef struct evtchn_bind_ipi {
    u32 vcpu;
    /* OUT parameters. */
    u32 port;
} evtchn_bind_ipi_t;

/*
 * EVTCHNOP_close: Close the communication channel which has an endpoint at
 * <dom, port>. If the channel is interdomain then the remote end is placed in
 * the unbound state (EVTCHNSTAT_unbound), awaiting a new connection.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may close an event channel
 *     for which <dom> is not DOMID_SELF.
 */
#define EVTCHNOP_close            3
typedef struct evtchn_close {
    /* IN parameters. */
    domid_t dom;
    u32     port;
    /* No OUT parameters. */
} evtchn_close_t;

/*
 * EVTCHNOP_send: Send an event to the remote end of the channel whose local
 * endpoint is <DOMID_SELF, local_port>.
 */
#define EVTCHNOP_send             4
typedef struct evtchn_send {
    /* IN parameters. */
    u32     local_port;
    /* No OUT parameters. */
} evtchn_send_t;

/*
 * EVTCHNOP_status: Get the current status of the communication channel which
 * has an endpoint at <dom, port>.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may obtain the status of an event
 *     channel for which <dom> is not DOMID_SELF.
 */
#define EVTCHNOP_status           5
typedef struct evtchn_status {
    /* IN parameters */
    domid_t dom;
    u32     port;
    /* OUT parameters */
#define EVTCHNSTAT_closed       0  /* Channel is not in use.                 */
#define EVTCHNSTAT_unbound      1  /* Channel is waiting interdom connection.*/
#define EVTCHNSTAT_interdomain  2  /* Channel is connected to remote domain. */
#define EVTCHNSTAT_pirq         3  /* Channel is bound to a phys IRQ line.   */
#define EVTCHNSTAT_virq         4  /* Channel is bound to a virtual IRQ line */
#define EVTCHNSTAT_ipi          5  /* Channel is bound to a virtual IPI line */
    u32     status;
    u32     vcpu;                  /* VCPU to which this channel is bound.   */
    union {
        struct {
            domid_t dom;
        } unbound; /* EVTCHNSTAT_unbound */
        struct {
            domid_t dom;
            u32     port;
        } interdomain; /* EVTCHNSTAT_interdomain */
        u32 pirq;      /* EVTCHNSTAT_pirq        */
        u32 virq;      /* EVTCHNSTAT_virq        */
    } u;
} evtchn_status_t;

/*
 * EVTCHNOP_bind_vcpu: Specify which vcpu a channel should notify when an
 * event is pending.
 * NOTES:
 *  1. IPI- and VIRQ-bound channels always notify the vcpu that initialised
 *     the binding. This binding cannot be changed.
 *  2. All other channels notify vcpu0 by default. This default is set when
 *     the channel is allocated (a port that is freed and subsequently reused
 *     has its binding reset to vcpu0).
 */
#define EVTCHNOP_bind_vcpu        8
typedef struct evtchn_bind_vcpu {
    /* IN parameters. */
    u32 port;
    u32 vcpu;
} evtchn_bind_vcpu_t;

typedef struct evtchn_op {
    u32 cmd; /* EVTCHNOP_* */
    union {
        evtchn_alloc_unbound_t    alloc_unbound;
        evtchn_bind_interdomain_t bind_interdomain;
        evtchn_bind_virq_t        bind_virq;
        evtchn_bind_pirq_t        bind_pirq;
        evtchn_bind_ipi_t         bind_ipi;
        evtchn_close_t            close;
        evtchn_send_t             send;
        evtchn_status_t           status;
        evtchn_bind_vcpu_t        bind_vcpu;
    } u;
} evtchn_op_t;

#endif /* __XEN_PUBLIC_EVENT_CHANNEL_H__ */
