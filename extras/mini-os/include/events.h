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

#define NR_EVS 1024

/* ev handler status */
#define EVS_INPROGRESS	1	/* Event handler active - do not enter! */
#define EVS_DISABLED	2	/* Event disabled - do not enter! */
#define EVS_PENDING	    4	/* Event pending - replay on enable */
#define EVS_REPLAY	    8	/* Event has been replayed but not acked yet */

/* this represents a event handler. Chaining or sharing is not allowed */
typedef struct _ev_action_t {
	void (*handler)(int, struct pt_regs *);
    unsigned int status;		/* IRQ status */
    u32 count;
} ev_action_t;

/* prototypes */
int do_event(u32 port, struct pt_regs *regs);
int bind_virq( u32 virq, void (*handler)(int, struct pt_regs *) );
void bind_evtchn( u32 virq, void (*handler)(int, struct pt_regs *) );
void init_events(void);

static inline int notify_via_evtchn(int port)
{
    evtchn_op_t op;
    op.cmd = EVTCHNOP_send;
    op.u.send.port = port;
    return HYPERVISOR_event_channel_op(&op);
}


#endif /* _EVENTS_H_ */
