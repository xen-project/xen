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
 * EVTCHNOP_open: Open a communication channel between <dom1> and <dom2>.
 * NOTES:
 *  1. <dom1> and/or <dom2> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may create an event channel.
 *  3. <port1> and <port2> are only supplied if the op succeeds.
 */
#define EVTCHNOP_open           0
typedef struct evtchn_open
{
    /* IN parameters. */
    domid_t dom1, dom2;
    /* OUT parameters. */
    int     port1, port2;
} evtchn_open_t;

/*
 * EVTCHNOP_close: Close the communication channel which has an endpoint at
 * <dom, port>.
 * NOTES:
 *  1. <dom> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may close an event channel
 *     for which <dom> is not DOMID_SELF.
 */
#define EVTCHNOP_close          1
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
#define EVTCHNOP_send           2
typedef struct evtchn_send
{
    /* IN parameters. */
    int     local_port;
    /* No OUT parameters. */
} evtchn_send_t;

/*
 * EVTCHNOP_status: Get the current status of the communication channel which
 * has an endpoint at <dom1, port1>.
 * NOTES:
 *  1. <dom1> may be specified as DOMID_SELF.
 *  2. Only a sufficiently-privileged domain may obtain the status of an event
 *     channel for which <dom1> is not DOMID_SELF.
 *  3. <dom2, port2> is only supplied if status is 'connected'.
 */
#define EVTCHNOP_status         3  /* Get status of <channel id>.         */
typedef struct evtchn_status
{
    /* IN parameters */
    domid_t dom1;
    int     port1;
    /* OUT parameters */
    domid_t dom2;
    int     port2;
#define EVTCHNSTAT_closed       0  /* Chennel is not in use.              */
#define EVTCHNSTAT_disconnected 1  /* Channel is not connected to remote. */
#define EVTCHNSTAT_connected    2  /* Channel is connected to remote.     */
    int     status;
} evtchn_status_t;

typedef struct evtchn_op
{
    int cmd; /* EVTCHNOP_* */
    union {
        evtchn_open_t   open;
        evtchn_close_t  close;
        evtchn_send_t   send;
        evtchn_status_t status;
    } u;
} evtchn_op_t;

#endif /* __HYPERVISOR_IFS__EVENT_CHANNEL_H__ */
