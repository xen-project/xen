/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2005 - Grzegorz Milos - Intel Reseach Cambridge
 ****************************************************************************
 *
 *        File: events.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: Grzegorz Milos (gm281@cam.ac.uk)
 *              
 *        Date: Jul 2003, changes Jun 2005
 * 
 * Environment: Xen Minimal OS
 * Description: Deals with events on the event channels
 *
 ****************************************************************************
 */

#ifndef _EVENTS_H_
#define _EVENTS_H_

#include<traps.h>
#include <xen/event_channel.h>

typedef void (*evtchn_handler_t)(evtchn_port_t, struct pt_regs *, void *);

/* prototypes */
int do_event(evtchn_port_t port, struct pt_regs *regs);
int bind_virq(uint32_t virq, evtchn_handler_t handler, void *data);
evtchn_port_t bind_evtchn(evtchn_port_t port, evtchn_handler_t handler,
						  void *data);
void unbind_evtchn(evtchn_port_t port);
void init_events(void);
evtchn_port_t evtchn_alloc_unbound(evtchn_handler_t handler,
								   void *data);

static inline int notify_remote_via_evtchn(evtchn_port_t port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.port = port;
    return HYPERVISOR_event_channel_op(&op);
}


#endif /* _EVENTS_H_ */
