/******************************************************************************
 * event_channel.h
 * 
 * Event channels between domains.
 * 
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef __HYPERVISOR_IFS__EVENT_CHANNEL_H__
#define __HYPERVISOR_IFS__EVENT_CHANNEL_H__

/*
 * EVTCHNOP_bind_interdomain: Open an event channel between <dom1> and <dom2>.
 * NOTES:
 *  1. <dom1> and/or <dom2> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may create an event channel.
 *  3. <port1> and <port2> are only supplied if the op succeeds.
 */
#define EVTCHNOP_bind_interdomain 0
typedef struct evtchn_bind_interdomain
{
    /* IN parameters. */
    domid_t dom1, dom2;
    /* OUT parameters. */
    int     port1, port2;
} evtchn_bind_interdomain_t;

/*
 * EVTCHNOP_bind_virq: Bind a local event channel to IRQ <irq>.
 * NOTES:
 *  1. A virtual IRQ may be bound to at most one event channel per domain.
 */
#define EVTCHNOP_bind_virq    1
typedef struct evtchn_bind_virq
{
    /* IN parameters. */
    int virq;
    /* OUT parameters. */
    int port;
} evtchn_bind_virq_t;

/*
 * EVTCHNOP_close: Close the communication channel which has an endpoint at
 * <dom, port>.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may close an event channel
 *     for which <dom> is not DOMID_SELF.
 */
#define EVTCHNOP_close            2
typedef struct evtchn_close
{
    /* IN parameters. */
    domid_t dom;
    int     port;
    /* No OUT parameters. */
} evtchn_close_t;

/*
 * EVTCHNOP_send: Send an event to the remote end of the channel whose local
 * endpoint is <DOMID_SELF, local_port>.
 */
#define EVTCHNOP_send             3
typedef struct evtchn_send
{
    /* IN parameters. */
    int     local_port;
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
#define EVTCHNOP_status           4
typedef struct evtchn_status
{
    /* IN parameters */
    domid_t dom;
    int     port;
    /* OUT parameters */
#define EVTCHNSTAT_closed       0  /* Chennel is not in use.                 */
#define EVTCHNSTAT_unbound      1  /* Channel is not bound to a source.      */
#define EVTCHNSTAT_interdomain  2  /* Channel is connected to remote domain. */
#define EVTCHNSTAT_pirq     3      /* Channel is bound to a phys IRQ line.   */
#define EVTCHNSTAT_virq     4      /* Channel is bound to a virtual IRQ line */
    int     status;
    union {
        int __none;    /* EVTCHNSTAT_closed, EVTCHNSTAT_unbound */
        struct {
            domid_t dom;
            int     port;
        } interdomain; /* EVTCHNSTAT_interdomain */
        int pirq;      /* EVTCHNSTAT_pirq        */
        int virq;      /* EVTCHNSTAT_virq        */
    } u;
} evtchn_status_t;

typedef struct evtchn_op
{
    int cmd; /* EVTCHNOP_* */
    union {
        evtchn_bind_interdomain_t bind_interdomain;
        evtchn_bind_virq_t        bind_virq;
        evtchn_close_t            close;
        evtchn_send_t             send;
        evtchn_status_t           status;
    } u;
} evtchn_op_t;

#endif /* __HYPERVISOR_IFS__EVENT_CHANNEL_H__ */
