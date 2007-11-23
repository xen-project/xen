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

#define NR_EVS 1024

/* this represents a event handler. Chaining or sharing is not allowed */
typedef struct _ev_action_t {
	evtchn_handler_t handler;
	void *data;
    u32 count;
} ev_action_t;

static ev_action_t ev_actions[NR_EVS];
void default_handler(evtchn_port_t port, struct pt_regs *regs, void *data);

static unsigned long bound_ports[NR_EVS/(8*sizeof(unsigned long))];

void unbind_all_ports(void)
{
    int i;

    for (i = 0; i < NR_EVS; i++)
    {
        if (test_and_clear_bit(i, bound_ports))
        {
            struct evtchn_close close;
            mask_evtchn(i);
            close.port = i;
            HYPERVISOR_event_channel_op(EVTCHNOP_close, &close);
        }
    }
}
  
/*
 * Demux events to different handlers.
 */
int do_event(evtchn_port_t port, struct pt_regs *regs)
{
    ev_action_t  *action;
    if (port >= NR_EVS) {
        printk("Port number too large: %d\n", port);
		goto out;
    }

    action = &ev_actions[port];
    action->count++;

    /* call the handler */
	action->handler(port, regs, action->data);

 out:
	clear_evtchn(port);

    return 1;

}

evtchn_port_t bind_evtchn(evtchn_port_t port, evtchn_handler_t handler,
						  void *data)
{
 	if(ev_actions[port].handler != default_handler)
        printk("WARN: Handler for port %d already registered, replacing\n",
				port);

	ev_actions[port].data = data;
	wmb();
	ev_actions[port].handler = handler;

	/* Finally unmask the port */
	unmask_evtchn(port);

	return port;
}

void unbind_evtchn(evtchn_port_t port )
{
	if (ev_actions[port].handler == default_handler)
		printk("WARN: No handler for port %d when unbinding\n", port);
	ev_actions[port].handler = default_handler;
	wmb();
	ev_actions[port].data = NULL;
}

evtchn_port_t bind_virq(uint32_t virq, evtchn_handler_t handler, void *data)
{
	evtchn_bind_virq_t op;

	/* Try to bind the virq to a port */
	op.virq = virq;
	op.vcpu = smp_processor_id();

	if ( HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq, &op) != 0 )
	{
		printk("Failed to bind virtual IRQ %d\n", virq);
		return -1;
    }
    set_bit(op.port,bound_ports);
    bind_evtchn(op.port, handler, data);
	return op.port;
}

#if defined(__x86_64__)
/* Allocate 4 pages for the irqstack */
#define STACK_PAGES 4
char irqstack[1024 * 4 * STACK_PAGES];

static struct pda
{
    int irqcount;       /* offset 0 (used in x86_64.S) */
    char *irqstackptr;  /*        8 */
} cpu0_pda;
#endif

/*
 * Initially all events are without a handler and disabled
 */
void init_events(void)
{
    int i;
#if defined(__x86_64__)
    asm volatile("movl %0,%%fs ; movl %0,%%gs" :: "r" (0));
    wrmsrl(0xc0000101, &cpu0_pda); /* 0xc0000101 is MSR_GS_BASE */
    cpu0_pda.irqcount = -1;
    cpu0_pda.irqstackptr = irqstack + 1024 * 4 * STACK_PAGES;
#endif
    /* inintialise event handler */
    for ( i = 0; i < NR_EVS; i++ )
	{
        ev_actions[i].handler = default_handler;
        mask_evtchn(i);
    }
}

void default_handler(evtchn_port_t port, struct pt_regs *regs, void *ignore)
{
    printk("[Port %d] - event received\n", port);
}

/* Create a port available to the pal for exchanging notifications.
   Returns the result of the hypervisor call. */

/* Unfortunate confusion of terminology: the port is unbound as far
   as Xen is concerned, but we automatically bind a handler to it
   from inside mini-os. */

int evtchn_alloc_unbound(domid_t pal, evtchn_handler_t handler,
						 void *data, evtchn_port_t *port)
{
    evtchn_alloc_unbound_t op;
    op.dom = DOMID_SELF;
    op.remote_dom = pal;
    int err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
    if (err)
		return err;
    *port = bind_evtchn(op.port, handler, data);
    return err;
}

/* Connect to a port so as to allow the exchange of notifications with
   the pal. Returns the result of the hypervisor call. */

int evtchn_bind_interdomain(domid_t pal, evtchn_port_t remote_port,
			    evtchn_handler_t handler, void *data,
			    evtchn_port_t *local_port)
{
    evtchn_bind_interdomain_t op;
    op.remote_dom = pal;
    op.remote_port = remote_port;
    int err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &op);
    if (err)
		return err;
    set_bit(op.local_port,bound_ports);
	evtchn_port_t port = op.local_port;
    clear_evtchn(port);	      /* Without, handler gets invoked now! */
    *local_port = bind_evtchn(port, handler, data);
    return err;
}
