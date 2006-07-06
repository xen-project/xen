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

/* prototypes */
int do_event(u32 port, struct pt_regs *regs);
int bind_virq( u32 virq, void (*handler)(int, struct pt_regs *, void *data),
			   void *data);
int bind_evtchn( u32 virq, void (*handler)(int, struct pt_regs *, void *data),
				 void *data );
void unbind_evtchn( u32 port );
void init_events(void);
void unbind_virq( u32 port );
int evtchn_alloc_unbound(void (*handler)(int, struct pt_regs *regs,
										 void *data),
						 void *data);

static inline int notify_remote_via_evtchn(int port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.port = port;
    return HYPERVISOR_event_channel_op(&op);
}


#endif /* _EVENTS_H_ */
