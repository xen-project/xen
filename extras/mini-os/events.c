/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 * (C) 2005 - Grzegorz Milos - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: events.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: Grzegorz Milos (gm281@cam.ac.uk)
 *              
 *        Date: Jul 2003, changes Jun 2005
 * 
 * Environment: Xen Minimal OS
 * Description: Deals with events recieved on event channels
 *
 ****************************************************************************
 */

#include <os.h>
#include <mm.h>
#include <hypervisor.h>
#include <events.h>
#include <lib.h>


static ev_action_t ev_actions[NR_EVS];
void default_handler(int port, struct pt_regs *regs);


/*
 * Demux events to different handlers.
 */
int do_event(u32 port, struct pt_regs *regs)
{
    ev_action_t  *action;
    if (port >= NR_EVS) {
        printk("Port number too large: %d\n", port);
        return 0;
    }

    action = &ev_actions[port];
    action->count++;

    if (!action->handler)
        goto out;
    
    if (action->status & EVS_DISABLED)
        goto out;
    
    /* call the handler */
    action->handler(port, regs);

	clear_evtchn(port);
    
 out:
    return 1;

}

int bind_evtchn( u32 port, void (*handler)(int, struct pt_regs *) )
{
 	if(ev_actions[port].handler != default_handler)
        printk("WARN: Handler for port %d already registered, replacing\n",
				port);

	ev_actions[port].handler = handler;
	ev_actions[port].status &= ~EVS_DISABLED;	  
 
	/* Finally unmask the port */
	unmask_evtchn(port);

	return port;
}

void unbind_evtchn( u32 port )
{
	if (ev_actions[port].handler)
		printk("WARN: No handler for port %d when unbinding\n", port);
	ev_actions[port].handler = NULL;
	ev_actions[port].status |= EVS_DISABLED;
}

int bind_virq( u32 virq, void (*handler)(int, struct pt_regs *) )
{
	evtchn_op_t op;
	int ret = 0;

	/* Try to bind the virq to a port */
	op.cmd = EVTCHNOP_bind_virq;
	op.u.bind_virq.virq = virq;
	op.u.bind_virq.vcpu = smp_processor_id();

	if ( HYPERVISOR_event_channel_op(&op) != 0 )
	{
		ret = 1;
		printk("Failed to bind virtual IRQ %d\n", virq);
		goto out;
    }
    bind_evtchn(op.u.bind_virq.port, handler);	
out:
	return ret;
}

void unbind_virq( u32 port )
{
	unbind_evtchn(port);
}


/*
 * Initially all events are without a handler and disabled
 */
void init_events(void)
{
    int i;

    /* inintialise event handler */
    for ( i = 0; i < NR_EVS; i++ )
    {
        ev_actions[i].status  = EVS_DISABLED;
        ev_actions[i].handler = default_handler;
    }
}

void default_handler(int port, struct pt_regs *regs) {
    printk("[Port %d] - event received\n", port);
}
