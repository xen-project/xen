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
typedef struct {
    /* IN parameters. */
    domid_t dom1, dom2;               /*  0,  8 */
    /* OUT parameters. */
    u32     port1, port2;             /* 16, 20 */
} PACKED evtchn_bind_interdomain_t; /* 24 bytes */

/*
 * EVTCHNOP_bind_virq: Bind a local event channel to IRQ <irq>.
 * NOTES:
 *  1. A virtual IRQ may be bound to at most one event channel per domain.
 */
#define EVTCHNOP_bind_virq        1
typedef struct {
    /* IN parameters. */
    u32 virq;                         /*  0 */
    /* OUT parameters. */
    u32 port;                         /*  4 */
} PACKED evtchn_bind_virq_t; /* 8 bytes */

/*
 * EVTCHNOP_bind_pirq: Bind a local event channel to IRQ <irq>.
 * NOTES:
 *  1. A physical IRQ may be bound to at most one event channel per domain.
 *  2. Only a sufficiently-privileged domain may bind to a physical IRQ.
 */
#define EVTCHNOP_bind_pirq        2
typedef struct {
    /* IN parameters. */
    u32 pirq;                         /*  0 */
#define BIND_PIRQ__WILL_SHARE 1
    u32 flags; /* BIND_PIRQ__* */     /*  4 */
    /* OUT parameters. */
    u32 port;                         /*  8 */
} PACKED evtchn_bind_pirq_t; /* 12 bytes */

/*
 * EVTCHNOP_close: Close the communication channel which has an endpoint at
 * <dom, port>.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may close an event channel
 *     for which <dom> is not DOMID_SELF.
 */
#define EVTCHNOP_close            3
typedef struct {
    /* IN parameters. */
    domid_t dom;                      /*  0 */
    u32     port;                     /*  8 */
    /* No OUT parameters. */
} PACKED evtchn_close_t; /* 12 bytes */

/*
 * EVTCHNOP_send: Send an event to the remote end of the channel whose local
 * endpoint is <DOMID_SELF, local_port>.
 */
#define EVTCHNOP_send             4
typedef struct {
    /* IN parameters. */
    u32     local_port;               /*  0 */
    /* No OUT parameters. */
} PACKED evtchn_send_t; /* 4 bytes */

/*
 * EVTCHNOP_status: Get the current status of the communication channel which
 * has an endpoint at <dom, port>.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may obtain the status of an event
 *     channel for which <dom> is not DOMID_SELF.
 */
#define EVTCHNOP_status           5
typedef struct {
    /* IN parameters */
    domid_t dom;                      /*  0 */
    u32     port;                     /*  8 */
    /* OUT parameters */
#define EVTCHNSTAT_closed       0  /* Chennel is not in use.                 */
#define EVTCHNSTAT_unbound      1  /* Channel is not bound to a source.      */
#define EVTCHNSTAT_interdomain  2  /* Channel is connected to remote domain. */
#define EVTCHNSTAT_pirq         3  /* Channel is bound to a phys IRQ line.   */
#define EVTCHNSTAT_virq         4  /* Channel is bound to a virtual IRQ line */
    u32     status;                   /* 12 */
    union {
        struct {
            domid_t dom;                              /* 16 */
            u32     port;                             /* 24 */
        } PACKED interdomain; /* EVTCHNSTAT_interdomain */
        u32 pirq;      /* EVTCHNSTAT_pirq        */   /* 16 */
        u32 virq;      /* EVTCHNSTAT_virq        */   /* 16 */
    } PACKED u;
} PACKED evtchn_status_t; /* 28 bytes */

typedef struct {
    u32 cmd; /* EVTCHNOP_* */         /*  0 */
    u32 __reserved;                   /*  4 */
    union {                           /*  8 */
        evtchn_bind_interdomain_t bind_interdomain;
        evtchn_bind_virq_t        bind_virq;
        evtchn_bind_pirq_t        bind_pirq;
        evtchn_close_t            close;
        evtchn_send_t             send;
        evtchn_status_t           status;
        u8                        __dummy[32];
    } PACKED u;
} PACKED evtchn_op_t; /* 40 bytes */

#endif /* __HYPERVISOR_IFS__EVENT_CHANNEL_H__ */
