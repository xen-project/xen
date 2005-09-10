/*
 * Xen Virtual USB Frontend Driver 
 *
 * This file contains the first version of the Xen virtual USB hub
 * that I've managed not to delete by mistake (3rd time lucky!).
 *
 * Based on Linux's uhci.c, original copyright notices are displayed
 * below.  Portions also (c) 2004 Intel Research Cambridge
 * and (c) 2004, 2005 Mark Williamson
 *
 * Contact <mark.williamson@cl.cam.ac.uk> or
 * <xen-devel@lists.sourceforge.net> regarding this code.
 *
 * Still to be (maybe) implemented:
 * - migration / backend restart support?
 * - support for building / using as a module
 */

/*
 * Universal Host Controller Interface driver for USB.
 *
 * Maintainer: Johannes Erdfelt <johannes@erdfelt.com>
 *
 * (C) Copyright 1999 Linus Torvalds
 * (C) Copyright 1999-2002 Johannes Erdfelt, johannes@erdfelt.com
 * (C) Copyright 1999 Randy Dunlap
 * (C) Copyright 1999 Georg Acher, acher@in.tum.de
 * (C) Copyright 1999 Deti Fliegl, deti@fliegl.de
 * (C) Copyright 1999 Thomas Sailer, sailer@ife.ee.ethz.ch
 * (C) Copyright 1999 Roman Weissgaerber, weissg@vienna.at
 * (C) Copyright 2000 Yggdrasil Computing, Inc. (port of new PCI interface
 *               support from usb-ohci.c by Adam Richter, adam@yggdrasil.com).
 * (C) Copyright 1999 Gregory P. Smith (from usb-ohci.c)
 *
 * Intel documents this fairly well, and as far as I know there
 * are no royalties or anything like that, but even so there are
 * people who decided that they want to do the same thing in a
 * completely different way.
 *
 * WARNING! The USB documentation is downright evil. Most of it
 * is just crap, written by a committee. You're better off ignoring
 * most of it, the important stuff is:
 *  - the low-level protocol (fairly simple but lots of small details)
 *  - working around the horridness of the rest
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#ifdef CONFIG_USB_DEBUG
#define DEBUG
#else
#undef DEBUG
#endif
#include <linux/usb.h>

#include <asm/irq.h>
#include <asm/system.h>

#include "xhci.h"

#include "../../../../../drivers/usb/hcd.h"

#include <asm-xen/xen-public/io/usbif.h>
#include <asm/xen-public/io/domain_controller.h>

/*
 * Version Information
 */
#define DRIVER_VERSION "v1.0"
#define DRIVER_AUTHOR "Linus 'Frodo Rabbit' Torvalds, Johannes Erdfelt, " \
                      "Randy Dunlap, Georg Acher, Deti Fliegl, " \
                      "Thomas Sailer, Roman Weissgaerber, Mark Williamson"
#define DRIVER_DESC "Xen Virtual USB Host Controller Interface"

/*
 * debug = 0, no debugging messages
 * debug = 1, dump failed URB's except for stalls
 * debug = 2, dump all failed URB's (including stalls)
 */
#ifdef DEBUG
static int debug = 1;
#else
static int debug = 0;
#endif
MODULE_PARM(debug, "i");
MODULE_PARM_DESC(debug, "Debug level");
static char *errbuf;
#define ERRBUF_LEN    (PAGE_SIZE * 8)

static int rh_submit_urb(struct urb *urb);
static int rh_unlink_urb(struct urb *urb);
static int xhci_unlink_urb(struct urb *urb);
static void xhci_call_completion(struct urb *urb);
static void xhci_drain_ring(void);
static void xhci_transfer_result(struct xhci *xhci, struct urb *urb);
static void xhci_finish_completion(void);

#define MAX_URB_LOOP	2048		/* Maximum number of linked URB's */

static kmem_cache_t *xhci_up_cachep;	/* urb_priv cache */
static struct xhci *xhci;               /* XHCI structure for the interface */

/******************************************************************************
 * DEBUGGING
 */

#ifdef DEBUG

static void dump_urb(struct urb *urb)
{
    printk(KERN_DEBUG "dumping urb @ %p\n"
           "  hcpriv = %p\n"
           "  next = %p\n"
           "  dev = %p\n"
           "  pipe = 0x%lx\n"
           "  status = %d\n"
           "  transfer_flags = 0x%lx\n"
           "  transfer_buffer = %p\n"
           "  transfer_buffer_length = %d\n"
           "  actual_length = %d\n"
           "  bandwidth = %d\n"
           "  setup_packet = %p\n",
           urb, urb->hcpriv, urb->next, urb->dev, urb->pipe, urb->status,
           urb->transfer_flags, urb->transfer_buffer,
           urb->transfer_buffer_length, urb->actual_length, urb->bandwidth,
           urb->setup_packet);
    if ( urb->setup_packet != NULL )
        printk(KERN_DEBUG
               "setup = { 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x }\n",
               urb->setup_packet[0], urb->setup_packet[1],
               urb->setup_packet[2], urb->setup_packet[3],
               urb->setup_packet[4], urb->setup_packet[5],
               urb->setup_packet[6], urb->setup_packet[7]);
    printk(KERN_DEBUG "complete = %p\n"
           "interval = %d\n", urb->complete, urb->interval);
        
}

static void xhci_show_resp(usbif_response_t *r)
{
        printk(KERN_DEBUG "dumping response @ %p\n"
               "  id=0x%lx\n"
               "  op=0x%x\n"
               "  data=0x%x\n"
               "  status=0x%x\n"
               "  length=0x%lx\n",
               r->id, r->operation, r->data, r->status, r->length);
}

#define DPRINK(...) printk(KERN_DEBUG __VA_ARGS__)

#else /* DEBUG */

#define dump_urb(blah) ((void)0)
#define xhci_show_resp(blah) ((void)0)
#define DPRINTK(blah,...) ((void)0)

#endif /* DEBUG */

/******************************************************************************
 * RING REQUEST HANDLING
 */

#define RING_PLUGGED(_hc) ( RING_FULL(&_hc->usb_ring) || _hc->recovery )

/**
 * xhci_construct_isoc - add isochronous information to a request
 */
static int xhci_construct_isoc(usbif_request_t *req, struct urb *urb)
{
        usbif_iso_t *schedule;
        int i;
        struct urb_priv *urb_priv = urb->hcpriv;
        
        req->num_iso = urb->number_of_packets;
        schedule = (usbif_iso_t *)__get_free_page(GFP_KERNEL);

        if ( schedule == NULL )
            return -ENOMEM;

        for ( i = 0; i < req->num_iso; i++ )
        {
                schedule[i].buffer_offset = urb->iso_frame_desc[i].offset;
                schedule[i].length = urb->iso_frame_desc[i].length;
        }

        urb_priv->schedule = schedule;
	req->iso_schedule = virt_to_mfn(schedule) << PAGE_SHIFT;

        return 0;
}

/**
 * xhci_queue_req - construct and queue request for an URB
 */
static int xhci_queue_req(struct urb *urb)
{
        unsigned long flags;
        usbif_request_t *req;
        usbif_front_ring_t *usb_ring = &xhci->usb_ring;

#if DEBUG
        printk(KERN_DEBUG
               "usbif = %p, req_prod = %d (@ 0x%lx), resp_prod = %d, resp_cons = %d\n",
               usbif, usbif->req_prod, virt_to_mfn(&usbif->req_prod),
               usbif->resp_prod, xhci->usb_resp_cons);
#endif
        
        spin_lock_irqsave(&xhci->ring_lock, flags);

        if ( RING_PLUGGED(xhci) )
        {
                printk(KERN_WARNING
                       "xhci_queue_req(): USB ring plugged, not queuing request\n");
                spin_unlock_irqrestore(&xhci->ring_lock, flags);
                return -ENOBUFS;
        }

        /* Stick something in the shared communications ring. */
	req = RING_GET_REQUEST(usb_ring, usb_ring->req_prod_pvt);

        req->operation       = USBIF_OP_IO;
        req->port            = 0; /* We don't care what the port is. */
        req->id              = (unsigned long) urb->hcpriv;
        req->transfer_buffer = virt_to_mfn(urb->transfer_buffer) << PAGE_SHIFT;
	req->devnum          = usb_pipedevice(urb->pipe);
        req->direction       = usb_pipein(urb->pipe);
	req->speed           = usb_pipeslow(urb->pipe);
        req->pipe_type       = usb_pipetype(urb->pipe);
        req->length          = urb->transfer_buffer_length;
        req->transfer_flags  = urb->transfer_flags;
	req->endpoint        = usb_pipeendpoint(urb->pipe);
	req->speed           = usb_pipeslow(urb->pipe);
	req->timeout         = urb->timeout * (1000 / HZ);

        if ( usb_pipetype(urb->pipe) == 0 ) /* ISO */
        {
            int ret = xhci_construct_isoc(req, urb);
            if ( ret != 0 )
                return ret;
        }

	if(urb->setup_packet != NULL)
                memcpy(req->setup, urb->setup_packet, 8);
        else
                memset(req->setup, 0, 8);
        
        usb_ring->req_prod_pvt++;
        RING_PUSH_REQUESTS(usb_ring);

        spin_unlock_irqrestore(&xhci->ring_lock, flags);

	notify_via_evtchn(xhci->evtchn);

        DPRINTK("Queued request for an URB.\n");
        dump_urb(urb);

        return -EINPROGRESS;
}

/**
 * xhci_queue_probe - queue a probe request for a particular port
 */
static inline usbif_request_t *xhci_queue_probe(usbif_vdev_t port)
{
        usbif_request_t *req;
        usbif_front_ring_t *usb_ring = &xhci->usb_ring;

#if DEBUG
	printk(KERN_DEBUG
               "queuing probe: req_prod = %d (@ 0x%lx), resp_prod = %d, "
               "resp_cons = %d\n", usbif->req_prod,
               virt_to_mfn(&usbif->req_prod),
	       usbif->resp_prod, xhci->usb_resp_cons);
#endif
 
        /* This is always called from the timer interrupt. */
        spin_lock(&xhci->ring_lock);
       
        if ( RING_PLUGGED(xhci) )
        {
                printk(KERN_WARNING
                       "xhci_queue_probe(): ring full, not queuing request\n");
                spin_unlock(&xhci->ring_lock);
                return NULL;
        }

        /* Stick something in the shared communications ring. */
        req = RING_GET_REQUEST(usb_ring, usb_ring->req_prod_pvt);

        memset(req, 0, sizeof(*req));

        req->operation       = USBIF_OP_PROBE;
        req->port            = port;

        usb_ring->req_prod_pvt++;
        RING_PUSH_REQUESTS(usb_ring);

        spin_unlock(&xhci->ring_lock);

	notify_via_evtchn(xhci->evtchn);

        return req;
}

/**
 * xhci_port_reset - queue a reset request for a particular port
 */
static int xhci_port_reset(usbif_vdev_t port)
{
        usbif_request_t *req;
        usbif_front_ring_t *usb_ring = &xhci->usb_ring;

        /* Only ever happens from process context (hub thread). */
        spin_lock_irq(&xhci->ring_lock);

        if ( RING_PLUGGED(xhci) )
        {
                printk(KERN_WARNING
                       "xhci_port_reset(): ring plugged, not queuing request\n");
                spin_unlock_irq(&xhci->ring_lock);
                return -ENOBUFS;
        }

        /* We only reset one port at a time, so we only need one variable per
         * hub. */
        xhci->awaiting_reset = 1;
        
        /* Stick something in the shared communications ring. */
	req = RING_GET_REQUEST(usb_ring, usb_ring->req_prod_pvt);

        memset(req, 0, sizeof(*req));

        req->operation       = USBIF_OP_RESET;
        req->port            = port;
        
        usb_ring->req_prod_pvt++;
	RING_PUSH_REQUESTS(usb_ring);

        spin_unlock_irq(&xhci->ring_lock);

	notify_via_evtchn(xhci->evtchn);

        while ( xhci->awaiting_reset > 0 )
        {
                mdelay(1);
                xhci_drain_ring();
        }

	xhci->rh.ports[port].pe = 1;
	xhci->rh.ports[port].pe_chg = 1;

        return xhci->awaiting_reset;
}


/******************************************************************************
 * RING RESPONSE HANDLING
 */

static void receive_usb_reset(usbif_response_t *resp)
{
    xhci->awaiting_reset = resp->status;
    rmb();
    
}

static void receive_usb_probe(usbif_response_t *resp)
{
    spin_lock(&xhci->rh.port_state_lock);

    if ( resp->status >= 0 )
    {
        if ( resp->status == 1 )
        {
            /* If theres a device there and there wasn't one before there must
             * have been a connection status change. */
            if( xhci->rh.ports[resp->data].cs == 0 )
	    {
                xhci->rh.ports[resp->data].cs = 1;
                xhci->rh.ports[resp->data].cs_chg = 1;
	    }
        }
        else if ( resp->status == 0 )
        {
            if(xhci->rh.ports[resp->data].cs == 1 )
            {
                xhci->rh.ports[resp->data].cs  = 0;
                xhci->rh.ports[resp->data].cs_chg = 1;
		xhci->rh.ports[resp->data].pe = 0;
		/* According to USB Spec v2.0, 11.24.2.7.2.2, we don't need
		 * to set pe_chg since an error has not occurred. */
            }
        }
        else
            printk(KERN_WARNING "receive_usb_probe(): unexpected status %d "
                   "for port %d\n", resp->status, resp->data);
    }
    else if ( resp->status < 0)
        printk(KERN_WARNING "receive_usb_probe(): got error status %d\n",
               resp->status);

    spin_unlock(&xhci->rh.port_state_lock);
}

static void receive_usb_io(usbif_response_t *resp)
{
        struct urb_priv *urbp = (struct urb_priv *)resp->id;
        struct urb *urb = urbp->urb;

        urb->actual_length = resp->length;
        urbp->in_progress = 0;

        if( usb_pipetype(urb->pipe) == 0 ) /* ISO */
        {
                int i;
              
                /* Copy ISO schedule results back in. */
                for ( i = 0; i < urb->number_of_packets; i++ )
                {
                        urb->iso_frame_desc[i].status
                                = urbp->schedule[i].status;
                        urb->iso_frame_desc[i].actual_length
                                = urbp->schedule[i].length;
                }
                free_page((unsigned long)urbp->schedule);
        }

        /* Only set status if it's not been changed since submission.  It might
         * have been changed if the URB has been unlinked asynchronously, for
         * instance. */
	if ( urb->status == -EINPROGRESS )
                urbp->status = urb->status = resp->status;
}

/**
 * xhci_drain_ring - drain responses from the ring, calling handlers
 *
 * This may be called from interrupt context when an event is received from the
 * backend domain, or sometimes in process context whilst waiting for a port
 * reset or URB completion.
 */
static void xhci_drain_ring(void)
{
	struct list_head *tmp, *head;
	usbif_front_ring_t *usb_ring = &xhci->usb_ring;
	usbif_response_t *resp;
        RING_IDX i, rp;

        /* Walk the ring here to get responses, updating URBs to show what
         * completed. */
        
        rp = usb_ring->sring->rsp_prod;
        rmb(); /* Ensure we see queued requests up to 'rp'. */

        /* Take items off the comms ring, taking care not to overflow. */
        for ( i = usb_ring->rsp_cons; i != rp; i++ )
        {
            resp = RING_GET_RESPONSE(usb_ring, i);
            
            /* May need to deal with batching and with putting a ceiling on
               the number dispatched for performance and anti-dos reasons */

            xhci_show_resp(resp);

            switch ( resp->operation )
            {
            case USBIF_OP_PROBE:
                receive_usb_probe(resp);
                break;
                
            case USBIF_OP_IO:
                receive_usb_io(resp);
                break;

            case USBIF_OP_RESET:
                receive_usb_reset(resp);
                break;

            default:
                printk(KERN_WARNING
                       "error: unknown USB io operation response [%d]\n",
                       resp->operation);
                break;
            }
        }

        usb_ring->rsp_cons = i;

	/* Walk the list of pending URB's to see which ones completed and do
         * callbacks, etc. */
	spin_lock(&xhci->urb_list_lock);
	head = &xhci->urb_list;
	tmp = head->next;
	while (tmp != head) {
		struct urb *urb = list_entry(tmp, struct urb, urb_list);

		tmp = tmp->next;

		/* Checks the status and does all of the magic necessary */
		xhci_transfer_result(xhci, urb);
	}
	spin_unlock(&xhci->urb_list_lock);

	xhci_finish_completion();
}


static void xhci_interrupt(int irq, void *__xhci, struct pt_regs *regs)
{
        xhci_drain_ring();
}

/******************************************************************************
 * HOST CONTROLLER FUNCTIONALITY
 */

/**
 * no-op implementation of private device alloc / free routines
 */
static int xhci_do_nothing_dev(struct usb_device *dev)
{
	return 0;
}

static inline void xhci_add_complete(struct urb *urb)
{
	struct urb_priv *urbp = (struct urb_priv *)urb->hcpriv;
	unsigned long flags;

	spin_lock_irqsave(&xhci->complete_list_lock, flags);
	list_add_tail(&urbp->complete_list, &xhci->complete_list);
	spin_unlock_irqrestore(&xhci->complete_list_lock, flags);
}

/* When this returns, the owner of the URB may free its
 * storage.
 *
 * We spin and wait for the URB to complete before returning.
 *
 * Call with urb->lock acquired.
 */
static void xhci_delete_urb(struct urb *urb)
{
        struct urb_priv *urbp;

	urbp = urb->hcpriv;

        /* If there's no urb_priv structure for this URB then it can't have
         * been submitted at all. */
	if ( urbp == NULL )
		return;

	/* For now we just spin until the URB completes.  It shouldn't take too
         * long and we don't expect to have to do this very often. */
	while ( urb->status == -EINPROGRESS )
        {
            xhci_drain_ring();
            mdelay(1);
        }

	/* Now we know that further transfers to the buffer won't
	 * occur, so we can safely return. */
}

static struct urb_priv *xhci_alloc_urb_priv(struct urb *urb)
{
	struct urb_priv *urbp;

	urbp = kmem_cache_alloc(xhci_up_cachep, SLAB_ATOMIC);
	if (!urbp) {
		err("xhci_alloc_urb_priv: couldn't allocate memory for urb_priv\n");
		return NULL;
	}

	memset((void *)urbp, 0, sizeof(*urbp));

	urbp->inserttime = jiffies;
	urbp->urb = urb;
	urbp->dev = urb->dev;
	
	INIT_LIST_HEAD(&urbp->complete_list);

	urb->hcpriv = urbp;

	return urbp;
}

/*
 * MUST be called with urb->lock acquired
 */
/* When is this called?  Do we need to stop the transfer (as we
 * currently do)? */
static void xhci_destroy_urb_priv(struct urb *urb)
{
    struct urb_priv *urbp;
    
    urbp = (struct urb_priv *)urb->hcpriv;
    if (!urbp)
        return;

    if (!list_empty(&urb->urb_list))
        warn("xhci_destroy_urb_priv: urb %p still on xhci->urb_list", urb);
    
    if (!list_empty(&urbp->complete_list))
        warn("xhci_destroy_urb_priv: urb %p still on xhci->complete_list", urb);
    
    kmem_cache_free(xhci_up_cachep, urb->hcpriv);

    urb->hcpriv = NULL;
}

/**
 * Try to find URBs in progress on the same pipe to the same device.
 *
 * MUST be called with xhci->urb_list_lock acquired
 */
static struct urb *xhci_find_urb_ep(struct xhci *xhci, struct urb *urb)
{
	struct list_head *tmp, *head;

	/* We don't match Isoc transfers since they are special */
	if (usb_pipeisoc(urb->pipe))
		return NULL;

	head = &xhci->urb_list;
	tmp = head->next;
	while (tmp != head) {
		struct urb *u = list_entry(tmp, struct urb, urb_list);

		tmp = tmp->next;

		if (u->dev == urb->dev && u->pipe == urb->pipe &&
		    u->status == -EINPROGRESS)
			return u;
	}

	return NULL;
}

static int xhci_submit_urb(struct urb *urb)
{
	int ret = -EINVAL;
	unsigned long flags;
	struct urb *eurb;
	int bustime;

        DPRINTK("URB submitted to XHCI driver.\n");
        dump_urb(urb);

	if (!urb)
		return -EINVAL;

	if (!urb->dev || !urb->dev->bus || !urb->dev->bus->hcpriv) {
		warn("xhci_submit_urb: urb %p belongs to disconnected device or bus?", urb);
		return -ENODEV;
	}

        if ( urb->dev->devpath == NULL )
                BUG();

	usb_inc_dev_use(urb->dev);

	spin_lock_irqsave(&xhci->urb_list_lock, flags);
	spin_lock(&urb->lock);

	if (urb->status == -EINPROGRESS || urb->status == -ECONNRESET ||
	    urb->status == -ECONNABORTED) {
		dbg("xhci_submit_urb: urb not available to submit (status = %d)", urb->status);
		/* Since we can have problems on the out path */
		spin_unlock(&urb->lock);
		spin_unlock_irqrestore(&xhci->urb_list_lock, flags);
		usb_dec_dev_use(urb->dev);

		return ret;
	}

	INIT_LIST_HEAD(&urb->urb_list);
	if (!xhci_alloc_urb_priv(urb)) {
		ret = -ENOMEM;

		goto out;
	}

        ( (struct urb_priv *)urb->hcpriv )->in_progress = 1;

	eurb = xhci_find_urb_ep(xhci, urb);
	if (eurb && !(urb->transfer_flags & USB_QUEUE_BULK)) {
		ret = -ENXIO;

		goto out;
	}

	/* Short circuit the virtual root hub */
	if (urb->dev == xhci->rh.dev) {
		ret = rh_submit_urb(urb);

		goto out;
	}

	switch (usb_pipetype(urb->pipe)) {
	case PIPE_CONTROL:
	case PIPE_BULK:
		ret = xhci_queue_req(urb);
		break;

	case PIPE_INTERRUPT:
		if (urb->bandwidth == 0) {	/* not yet checked/allocated */
			bustime = usb_check_bandwidth(urb->dev, urb);
			if (bustime < 0)
				ret = bustime;
			else {
				ret = xhci_queue_req(urb);
				if (ret == -EINPROGRESS)
					usb_claim_bandwidth(urb->dev, urb,
                                                            bustime, 0);
			}
		} else		/* bandwidth is already set */
			ret = xhci_queue_req(urb);
		break;

	case PIPE_ISOCHRONOUS:
		if (urb->bandwidth == 0) {	/* not yet checked/allocated */
			if (urb->number_of_packets <= 0) {
				ret = -EINVAL;
				break;
			}
			bustime = usb_check_bandwidth(urb->dev, urb);
			if (bustime < 0) {
				ret = bustime;
				break;
			}

			ret = xhci_queue_req(urb);
			if (ret == -EINPROGRESS)
				usb_claim_bandwidth(urb->dev, urb, bustime, 1);
		} else		/* bandwidth is already set */
			ret = xhci_queue_req(urb);
		break;
	}
out:
	urb->status = ret;

	if (ret == -EINPROGRESS) {
		/* We use _tail to make find_urb_ep more efficient */
		list_add_tail(&urb->urb_list, &xhci->urb_list);

		spin_unlock(&urb->lock);
		spin_unlock_irqrestore(&xhci->urb_list_lock, flags);

		return 0;
	}

	xhci_delete_urb(urb);

	spin_unlock(&urb->lock);
	spin_unlock_irqrestore(&xhci->urb_list_lock, flags);

	/* Only call completion if it was successful */
	if (!ret)
		xhci_call_completion(urb);

	return ret;
}

/*
 * Return the result of a transfer
 *
 * MUST be called with urb_list_lock acquired
 */
static void xhci_transfer_result(struct xhci *xhci, struct urb *urb)
{
	int ret = 0;
	unsigned long flags;
	struct urb_priv *urbp;

	/* The root hub is special */
	if (urb->dev == xhci->rh.dev)
		return;

	spin_lock_irqsave(&urb->lock, flags);

	urbp = (struct urb_priv *)urb->hcpriv;

        if ( ( (struct urb_priv *)urb->hcpriv )->in_progress )
                ret = -EINPROGRESS;

        if (urb->actual_length < urb->transfer_buffer_length) {
                if (urb->transfer_flags & USB_DISABLE_SPD) {
                        ret = -EREMOTEIO;
                }
        }

	if (urb->status == -EPIPE)
        {
                ret = urb->status;
		/* endpoint has stalled - mark it halted */
		usb_endpoint_halt(urb->dev, usb_pipeendpoint(urb->pipe),
                                  usb_pipeout(urb->pipe));
        }

	if ((debug == 1 && ret != 0 && ret != -EPIPE) ||
            (ret != 0 && debug > 1)) {
		/* Some debugging code */
		dbg("xhci_result_interrupt/bulk() failed with status %x",
			status);
	}

	if (ret == -EINPROGRESS)
		goto out;

	switch (usb_pipetype(urb->pipe)) {
	case PIPE_CONTROL:
	case PIPE_BULK:
	case PIPE_ISOCHRONOUS:
		/* Release bandwidth for Interrupt or Isoc. transfers */
		/* Spinlock needed ? */
		if (urb->bandwidth)
			usb_release_bandwidth(urb->dev, urb, 1);
		xhci_delete_urb(urb);
		break;
	case PIPE_INTERRUPT:
		/* Interrupts are an exception */
		if (urb->interval)
			goto out_complete;

		/* Release bandwidth for Interrupt or Isoc. transfers */
		/* Spinlock needed ? */
		if (urb->bandwidth)
			usb_release_bandwidth(urb->dev, urb, 0);
		xhci_delete_urb(urb);
		break;
	default:
		info("xhci_transfer_result: unknown pipe type %d for urb %p\n",
                     usb_pipetype(urb->pipe), urb);
	}

	/* Remove it from xhci->urb_list */
	list_del_init(&urb->urb_list);

out_complete:
	xhci_add_complete(urb);

out:
	spin_unlock_irqrestore(&urb->lock, flags);
}

static int xhci_unlink_urb(struct urb *urb)
{
	unsigned long flags;
	struct urb_priv *urbp = urb->hcpriv;

	if (!urb)
		return -EINVAL;

	if (!urb->dev || !urb->dev->bus || !urb->dev->bus->hcpriv)
		return -ENODEV;

	spin_lock_irqsave(&xhci->urb_list_lock, flags);
	spin_lock(&urb->lock);

	/* Release bandwidth for Interrupt or Isoc. transfers */
	/* Spinlock needed ? */
	if (urb->bandwidth) {
		switch (usb_pipetype(urb->pipe)) {
		case PIPE_INTERRUPT:
			usb_release_bandwidth(urb->dev, urb, 0);
			break;
		case PIPE_ISOCHRONOUS:
			usb_release_bandwidth(urb->dev, urb, 1);
			break;
		default:
			break;
		}
	}

	if (urb->status != -EINPROGRESS) {
		spin_unlock(&urb->lock);
		spin_unlock_irqrestore(&xhci->urb_list_lock, flags);
		return 0;
	}

	list_del_init(&urb->urb_list);

	/* Short circuit the virtual root hub */
	if (urb->dev == xhci->rh.dev) {
		rh_unlink_urb(urb);

		spin_unlock(&urb->lock);
		spin_unlock_irqrestore(&xhci->urb_list_lock, flags);

		xhci_call_completion(urb);
	} else {
		if (urb->transfer_flags & USB_ASYNC_UNLINK) {
                        /* We currently don't currently attempt to cancel URBs
                         * that have been queued in the ring.  We handle async
                         * unlinked URBs when they complete. */
			urbp->status = urb->status = -ECONNABORTED;
			spin_unlock(&urb->lock);
			spin_unlock_irqrestore(&xhci->urb_list_lock, flags);
		} else {
			urb->status = -ENOENT;

			spin_unlock(&urb->lock);
			spin_unlock_irqrestore(&xhci->urb_list_lock, flags);

			if (in_interrupt()) {	/* wait at least 1 frame */
				static int errorcount = 10;

				if (errorcount--)
					dbg("xhci_unlink_urb called from interrupt for urb %p", urb);
				udelay(1000);
			} else
				schedule_timeout(1+1*HZ/1000); 

                        xhci_delete_urb(urb);

			xhci_call_completion(urb);
		}
	}

	return 0;
}

static void xhci_call_completion(struct urb *urb)
{
	struct urb_priv *urbp;
	struct usb_device *dev = urb->dev;
	int is_ring = 0, killed, resubmit_interrupt, status;
	struct urb *nurb;
	unsigned long flags;

	spin_lock_irqsave(&urb->lock, flags);

	urbp = (struct urb_priv *)urb->hcpriv;
	if (!urbp || !urb->dev) {
		spin_unlock_irqrestore(&urb->lock, flags);
		return;
	}

	killed = (urb->status == -ENOENT || urb->status == -ECONNABORTED ||
			urb->status == -ECONNRESET);
	resubmit_interrupt = (usb_pipetype(urb->pipe) == PIPE_INTERRUPT &&
			urb->interval);

	nurb = urb->next;
	if (nurb && !killed) {
		int count = 0;

		while (nurb && nurb != urb && count < MAX_URB_LOOP) {
			if (nurb->status == -ENOENT ||
			    nurb->status == -ECONNABORTED ||
			    nurb->status == -ECONNRESET) {
				killed = 1;
				break;
			}

			nurb = nurb->next;
			count++;
		}

		if (count == MAX_URB_LOOP)
			err("xhci_call_completion: too many linked URB's, loop? (first loop)");

		/* Check to see if chain is a ring */
		is_ring = (nurb == urb);
	}

	status = urbp->status;
	if (!resubmit_interrupt || killed)
		/* We don't need urb_priv anymore */
		xhci_destroy_urb_priv(urb);

	if (!killed)
		urb->status = status;

	spin_unlock_irqrestore(&urb->lock, flags);

	if (urb->complete)
		urb->complete(urb);

	if (resubmit_interrupt)
		/* Recheck the status. The completion handler may have */
		/*  unlinked the resubmitting interrupt URB */
		killed = (urb->status == -ENOENT ||
			  urb->status == -ECONNABORTED ||
			  urb->status == -ECONNRESET);

	if (resubmit_interrupt && !killed) {
                if ( urb->dev != xhci->rh.dev )
                        xhci_queue_req(urb); /* XXX What if this fails? */
                /* Don't need to resubmit URBs for the virtual root dev. */
	} else {
		if (is_ring && !killed) {
			urb->dev = dev;
			xhci_submit_urb(urb);
		} else {
			/* We decrement the usage count after we're done */
			/*  with everything */
			usb_dec_dev_use(dev);
		}
	}
}

static void xhci_finish_completion(void)
{
	struct list_head *tmp, *head;
	unsigned long flags;

	spin_lock_irqsave(&xhci->complete_list_lock, flags);
	head = &xhci->complete_list;
	tmp = head->next;
	while (tmp != head) {
		struct urb_priv *urbp = list_entry(tmp, struct urb_priv,
                                                   complete_list);
		struct urb *urb = urbp->urb;

		list_del_init(&urbp->complete_list);
		spin_unlock_irqrestore(&xhci->complete_list_lock, flags);

		xhci_call_completion(urb);

		spin_lock_irqsave(&xhci->complete_list_lock, flags);
		head = &xhci->complete_list;
		tmp = head->next;
	}
	spin_unlock_irqrestore(&xhci->complete_list_lock, flags);
}

static struct usb_operations xhci_device_operations = {
	.allocate = xhci_do_nothing_dev,
	.deallocate = xhci_do_nothing_dev,
        /* It doesn't look like any drivers actually care what the frame number
	 * is at the moment!  If necessary, we could approximate the current
	 * frame nubmer by passing it from the backend in response messages. */
	.get_frame_number = NULL,
	.submit_urb = xhci_submit_urb,
	.unlink_urb = xhci_unlink_urb
};

/******************************************************************************
 * VIRTUAL ROOT HUB EMULATION
 */

static __u8 root_hub_dev_des[] =
{
 	0x12,			/*  __u8  bLength; */
	0x01,			/*  __u8  bDescriptorType; Device */
	0x00,			/*  __u16 bcdUSB; v1.0 */
	0x01,
	0x09,			/*  __u8  bDeviceClass; HUB_CLASSCODE */
	0x00,			/*  __u8  bDeviceSubClass; */
	0x00,			/*  __u8  bDeviceProtocol; */
	0x08,			/*  __u8  bMaxPacketSize0; 8 Bytes */
	0x00,			/*  __u16 idVendor; */
	0x00,
	0x00,			/*  __u16 idProduct; */
	0x00,
	0x00,			/*  __u16 bcdDevice; */
	0x00,
	0x00,			/*  __u8  iManufacturer; */
	0x02,			/*  __u8  iProduct; */
	0x01,			/*  __u8  iSerialNumber; */
	0x01			/*  __u8  bNumConfigurations; */
};


/* Configuration descriptor */
static __u8 root_hub_config_des[] =
{
	0x09,			/*  __u8  bLength; */
	0x02,			/*  __u8  bDescriptorType; Configuration */
	0x19,			/*  __u16 wTotalLength; */
	0x00,
	0x01,			/*  __u8  bNumInterfaces; */
	0x01,			/*  __u8  bConfigurationValue; */
	0x00,			/*  __u8  iConfiguration; */
	0x40,			/*  __u8  bmAttributes;
					Bit 7: Bus-powered, 6: Self-powered,
					Bit 5 Remote-wakeup, 4..0: resvd */
	0x00,			/*  __u8  MaxPower; */

	/* interface */
	0x09,			/*  __u8  if_bLength; */
	0x04,			/*  __u8  if_bDescriptorType; Interface */
	0x00,			/*  __u8  if_bInterfaceNumber; */
	0x00,			/*  __u8  if_bAlternateSetting; */
	0x01,			/*  __u8  if_bNumEndpoints; */
	0x09,			/*  __u8  if_bInterfaceClass; HUB_CLASSCODE */
	0x00,			/*  __u8  if_bInterfaceSubClass; */
	0x00,			/*  __u8  if_bInterfaceProtocol; */
	0x00,			/*  __u8  if_iInterface; */

	/* endpoint */
	0x07,			/*  __u8  ep_bLength; */
	0x05,			/*  __u8  ep_bDescriptorType; Endpoint */
	0x81,			/*  __u8  ep_bEndpointAddress; IN Endpoint 1 */
	0x03,			/*  __u8  ep_bmAttributes; Interrupt */
	0x08,			/*  __u16 ep_wMaxPacketSize; 8 Bytes */
	0x00,
	0xff			/*  __u8  ep_bInterval; 255 ms */
};

static __u8 root_hub_hub_des[] =
{
	0x09,			/*  __u8  bLength; */
	0x29,			/*  __u8  bDescriptorType; Hub-descriptor */
	0x02,			/*  __u8  bNbrPorts; */
	0x00,			/* __u16  wHubCharacteristics; */
	0x00,
	0x01,			/*  __u8  bPwrOn2pwrGood; 2ms */
	0x00,			/*  __u8  bHubContrCurrent; 0 mA */
	0x00,			/*  __u8  DeviceRemovable; *** 7 Ports max *** */
	0xff			/*  __u8  PortPwrCtrlMask; *** 7 ports max *** */
};

/* prepare Interrupt pipe transaction data; HUB INTERRUPT ENDPOINT */
static int rh_send_irq(struct urb *urb)
{
	struct urb_priv *urbp = (struct urb_priv *)urb->hcpriv;
        xhci_port_t *ports = xhci->rh.ports;
	unsigned long flags;
	int i, len = 1;
	__u16 data = 0;

	spin_lock_irqsave(&urb->lock, flags);
	for (i = 0; i < xhci->rh.numports; i++) {
                /* Set a bit if anything at all has changed on the port, as per
		 * USB spec 11.12 */
		data |= (ports[i].cs_chg || ports[i].pe_chg )
                        ? (1 << (i + 1))
                        : 0;

		len = (i + 1) / 8 + 1;
	}

	*(__u16 *) urb->transfer_buffer = cpu_to_le16(data);
	urb->actual_length = len;
	urbp->status = 0;

	spin_unlock_irqrestore(&urb->lock, flags);

	if ((data > 0) && (xhci->rh.send != 0)) {
		dbg("root-hub INT complete: data: %x", data);
		xhci_call_completion(urb);
	}

	return 0;
}

/* Virtual Root Hub INTs are polled by this timer every "interval" ms */
static int rh_init_int_timer(struct urb *urb);

static void rh_int_timer_do(unsigned long ptr)
{
	struct urb *urb = (struct urb *)ptr;
	struct list_head list, *tmp, *head;
	unsigned long flags;
	int i;

	for ( i = 0; i < xhci->rh.numports; i++)
                xhci_queue_probe(i);

	if (xhci->rh.send)
		rh_send_irq(urb);

	INIT_LIST_HEAD(&list);

	spin_lock_irqsave(&xhci->urb_list_lock, flags);
	head = &xhci->urb_list;
	tmp = head->next;
	while (tmp != head) {
		struct urb *u = list_entry(tmp, struct urb, urb_list);
		struct urb_priv *up = (struct urb_priv *)u->hcpriv;

		tmp = tmp->next;

		spin_lock(&u->lock);

		/* Check if the URB timed out */
		if (u->timeout && time_after_eq(jiffies,
                                                up->inserttime + u->timeout)) {
			list_del(&u->urb_list);
			list_add_tail(&u->urb_list, &list);
		}

		spin_unlock(&u->lock);
	}
	spin_unlock_irqrestore(&xhci->urb_list_lock, flags);

	head = &list;
	tmp = head->next;
	while (tmp != head) {
		struct urb *u = list_entry(tmp, struct urb, urb_list);

		tmp = tmp->next;

		u->transfer_flags |= USB_ASYNC_UNLINK | USB_TIMEOUT_KILLED;
		xhci_unlink_urb(u);
	}

	rh_init_int_timer(urb);
}

/* Root Hub INTs are polled by this timer */
static int rh_init_int_timer(struct urb *urb)
{
	xhci->rh.interval = urb->interval;
	init_timer(&xhci->rh.rh_int_timer);
	xhci->rh.rh_int_timer.function = rh_int_timer_do;
	xhci->rh.rh_int_timer.data = (unsigned long)urb;
	xhci->rh.rh_int_timer.expires = jiffies
                + (HZ * (urb->interval < 30 ? 30 : urb->interval)) / 1000;
	add_timer(&xhci->rh.rh_int_timer);

	return 0;
}

#define OK(x)			len = (x); break

/* Root Hub Control Pipe */
static int rh_submit_urb(struct urb *urb)
{
	unsigned int pipe = urb->pipe;
	struct usb_ctrlrequest *cmd =
                (struct usb_ctrlrequest *)urb->setup_packet;
	void *data = urb->transfer_buffer;
	int leni = urb->transfer_buffer_length;
	int len = 0;
	xhci_port_t *status;
	int stat = 0;
	int i;
	int retstatus;
        unsigned long flags;
        
	__u16 cstatus;
	__u16 bmRType_bReq;
	__u16 wValue;
	__u16 wIndex;
	__u16 wLength;

	if (usb_pipetype(pipe) == PIPE_INTERRUPT) {
		xhci->rh.urb = urb;
		xhci->rh.send = 1;
		xhci->rh.interval = urb->interval;
		rh_init_int_timer(urb);

		return -EINPROGRESS;
	}

	bmRType_bReq = cmd->bRequestType | cmd->bRequest << 8;
	wValue = le16_to_cpu(cmd->wValue);
	wIndex = le16_to_cpu(cmd->wIndex);
	wLength = le16_to_cpu(cmd->wLength);

	for (i = 0; i < 8; i++)
		xhci->rh.c_p_r[i] = 0;

        status = &xhci->rh.ports[wIndex - 1];

        spin_lock_irqsave(&xhci->rh.port_state_lock, flags);

	switch (bmRType_bReq) {
		/* Request Destination:
		   without flags: Device,
		   RH_INTERFACE: interface,
		   RH_ENDPOINT: endpoint,
		   RH_CLASS means HUB here,
		   RH_OTHER | RH_CLASS  almost ever means HUB_PORT here
		*/

	case RH_GET_STATUS:
		*(__u16 *)data = cpu_to_le16(1);
		OK(2);
	case RH_GET_STATUS | RH_INTERFACE:
		*(__u16 *)data = cpu_to_le16(0);
		OK(2);
	case RH_GET_STATUS | RH_ENDPOINT:
		*(__u16 *)data = cpu_to_le16(0);
		OK(2);
	case RH_GET_STATUS | RH_CLASS:
		*(__u32 *)data = cpu_to_le32(0);
		OK(4);		/* hub power */
	case RH_GET_STATUS | RH_OTHER | RH_CLASS:
		cstatus = (status->cs_chg) |
			(status->pe_chg << 1) |
			(xhci->rh.c_p_r[wIndex - 1] << 4);
		retstatus = (status->cs) |
			(status->pe << 1) |
			(status->susp << 2) |
			(1 << 8) |      /* power on */
			(status->lsda << 9);
		*(__u16 *)data = cpu_to_le16(retstatus);
		*(__u16 *)(data + 2) = cpu_to_le16(cstatus);
		OK(4);
	case RH_CLEAR_FEATURE | RH_ENDPOINT:
		switch (wValue) {
		case RH_ENDPOINT_STALL:
			OK(0);
		}
		break;
	case RH_CLEAR_FEATURE | RH_CLASS:
		switch (wValue) {
		case RH_C_HUB_OVER_CURRENT:
			OK(0);	/* hub power over current */
		}
		break;
	case RH_CLEAR_FEATURE | RH_OTHER | RH_CLASS:
		switch (wValue) {
		case RH_PORT_ENABLE:
                        status->pe     = 0;
			OK(0);
		case RH_PORT_SUSPEND:
                        status->susp   = 0;
			OK(0);
		case RH_PORT_POWER:
			OK(0);	/* port power */
		case RH_C_PORT_CONNECTION:
                        status->cs_chg = 0;
			OK(0);
		case RH_C_PORT_ENABLE:
                        status->pe_chg = 0;
			OK(0);
		case RH_C_PORT_SUSPEND:
			/*** WR_RH_PORTSTAT(RH_PS_PSSC); */
			OK(0);
		case RH_C_PORT_OVER_CURRENT:
			OK(0);	/* port power over current */
		case RH_C_PORT_RESET:
			xhci->rh.c_p_r[wIndex - 1] = 0;
			OK(0);
		}
		break;
	case RH_SET_FEATURE | RH_OTHER | RH_CLASS:
		switch (wValue) {
		case RH_PORT_SUSPEND:
                        status->susp = 1;	
			OK(0);
		case RH_PORT_RESET:
                {
                        int ret;
                        xhci->rh.c_p_r[wIndex - 1] = 1;
                        status->pr = 0;
                        status->pe = 1;
                        ret = xhci_port_reset(wIndex - 1);
                        /* XXX MAW: should probably cancel queued transfers during reset... *\/ */
                        if ( ret == 0 ) { OK(0); }
                        else { return ret; }
                }
                break;
		case RH_PORT_POWER:
			OK(0); /* port power ** */
		case RH_PORT_ENABLE:
                        status->pe = 1;
			OK(0);
		}
		break;
	case RH_SET_ADDRESS:
		xhci->rh.devnum = wValue;
		OK(0);
	case RH_GET_DESCRIPTOR:
		switch ((wValue & 0xff00) >> 8) {
		case 0x01:	/* device descriptor */
			len = min_t(unsigned int, leni,
				  min_t(unsigned int,
				      sizeof(root_hub_dev_des), wLength));
			memcpy(data, root_hub_dev_des, len);
			OK(len);
		case 0x02:	/* configuration descriptor */
			len = min_t(unsigned int, leni,
				  min_t(unsigned int,
				      sizeof(root_hub_config_des), wLength));
			memcpy (data, root_hub_config_des, len);
			OK(len);
		case 0x03:	/* string descriptors */
			len = usb_root_hub_string (wValue & 0xff,
				0, "XHCI-alt",
				data, wLength);
			if (len > 0) {
				OK(min_t(int, leni, len));
			} else 
				stat = -EPIPE;
		}
		break;
	case RH_GET_DESCRIPTOR | RH_CLASS:
		root_hub_hub_des[2] = xhci->rh.numports;
		len = min_t(unsigned int, leni,
			  min_t(unsigned int, sizeof(root_hub_hub_des), wLength));
		memcpy(data, root_hub_hub_des, len);
		OK(len);
	case RH_GET_CONFIGURATION:
		*(__u8 *)data = 0x01;
		OK(1);
	case RH_SET_CONFIGURATION:
		OK(0);
	case RH_GET_INTERFACE | RH_INTERFACE:
		*(__u8 *)data = 0x00;
		OK(1);
	case RH_SET_INTERFACE | RH_INTERFACE:
		OK(0);
	default:
		stat = -EPIPE;
	}

        spin_unlock_irqrestore(&xhci->rh.port_state_lock, flags);

	urb->actual_length = len;

	return stat;
}

/*
 * MUST be called with urb->lock acquired
 */
static int rh_unlink_urb(struct urb *urb)
{
	if (xhci->rh.urb == urb) {
		urb->status = -ENOENT;
		xhci->rh.send = 0;
		xhci->rh.urb = NULL;
		del_timer(&xhci->rh.rh_int_timer);
	}
	return 0;
}

/******************************************************************************
 * CONTROL PLANE FUNCTIONALITY
 */

/**
 * alloc_xhci - initialise a new virtual root hub for a new USB device channel
 */
static int alloc_xhci(void)
{
	int retval;
	struct usb_bus *bus;

	retval = -EBUSY;

	xhci = kmalloc(sizeof(*xhci), GFP_KERNEL);
	if (!xhci) {
		err("couldn't allocate xhci structure");
		retval = -ENOMEM;
		goto err_alloc_xhci;
	}

	xhci->state = USBIF_STATE_CLOSED;

	spin_lock_init(&xhci->urb_list_lock);
	INIT_LIST_HEAD(&xhci->urb_list);

	spin_lock_init(&xhci->complete_list_lock);
	INIT_LIST_HEAD(&xhci->complete_list);

	spin_lock_init(&xhci->frame_list_lock);

	bus = usb_alloc_bus(&xhci_device_operations);

	if (!bus) {
		err("unable to allocate bus");
		goto err_alloc_bus;
	}

	xhci->bus = bus;
	bus->bus_name = "XHCI";
	bus->hcpriv = xhci;

	usb_register_bus(xhci->bus);

	/* Initialize the root hub */

	xhci->rh.numports = 0;

	xhci->bus->root_hub = xhci->rh.dev = usb_alloc_dev(NULL, xhci->bus);
	if (!xhci->rh.dev) {
		err("unable to allocate root hub");
		goto err_alloc_root_hub;
	}

	xhci->state = 0;

	return 0;

/*
 * error exits:
 */
err_alloc_root_hub:
        usb_deregister_bus(xhci->bus);
	usb_free_bus(xhci->bus);
	xhci->bus = NULL;

err_alloc_bus:
	kfree(xhci);

err_alloc_xhci:
	return retval;
}

/**
 * usbif_status_change - deal with an incoming USB_INTERFACE_STATUS_ message
 */
static void usbif_status_change(usbif_fe_interface_status_changed_t *status)
{
    ctrl_msg_t                   cmsg;
    usbif_fe_interface_connect_t up;
    long rc;
    usbif_sring_t *sring;

    switch ( status->status )
    {
    case USBIF_INTERFACE_STATUS_DESTROYED:
        printk(KERN_WARNING "Unexpected usbif-DESTROYED message in state %d\n",
               xhci->state);
        break;

    case USBIF_INTERFACE_STATUS_DISCONNECTED:
        if ( xhci->state != USBIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected usbif-DISCONNECTED message"
                   " in state %d\n", xhci->state);
            break;
            /* Not bothering to do recovery here for now.  Keep things
             * simple. */

            spin_lock_irq(&xhci->ring_lock);
            
            /* Clean up resources. */
            free_page((unsigned long)xhci->usb_ring.sring);
            unbind_evtchn_from_irqhandler(xhci->evtchn, xhci);

            /* Plug the ring. */
            xhci->recovery = 1;
            wmb();
            
            spin_unlock_irq(&xhci->ring_lock);
        }

        /* Move from CLOSED to DISCONNECTED state. */
        sring = (usbif_sring_t *)__get_free_page(GFP_KERNEL);
        SHARED_RING_INIT(sring);
        FRONT_RING_INIT(&xhci->usb_ring, sring, PAGE_SIZE);
        xhci->state  = USBIF_STATE_DISCONNECTED;

        /* Construct an interface-CONNECT message for the domain controller. */
        cmsg.type      = CMSG_USBIF_FE;
        cmsg.subtype   = CMSG_USBIF_FE_INTERFACE_CONNECT;
        cmsg.length    = sizeof(usbif_fe_interface_connect_t);
        up.shmem_frame = virt_to_mfn(sring);
        memcpy(cmsg.msg, &up, sizeof(up));
        
        /* Tell the controller to bring up the interface. */
        ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
        break;

    case USBIF_INTERFACE_STATUS_CONNECTED:
        if ( xhci->state == USBIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected usbif-CONNECTED message"
                   " in state %d\n", xhci->state);
            break;
        }

        xhci->evtchn = status->evtchn;
	xhci->bandwidth = status->bandwidth;
	xhci->rh.numports = status->num_ports;

        xhci->rh.ports = kmalloc (sizeof(xhci_port_t) * xhci->rh.numports, GFP_KERNEL);
	
	if ( xhci->rh.ports == NULL )
            goto alloc_ports_nomem;
	
        memset(xhci->rh.ports, 0, sizeof(xhci_port_t) * xhci->rh.numports);

	usb_connect(xhci->rh.dev);

	if (usb_new_device(xhci->rh.dev) != 0) {
		err("unable to start root hub");
	}

	/* Allocate the appropriate USB bandwidth here...  Need to
         * somehow know what the total available is thought to be so we
         * can calculate the reservation correctly. */
 	usb_claim_bandwidth(xhci->rh.dev, xhci->rh.urb,
 			    1000 - xhci->bandwidth, 0);

        if ( (rc = bind_evtchn_to_irqhandler(xhci->evtchn, xhci_interrupt, 
                               SA_SAMPLE_RANDOM, "usbif", xhci)) )
                printk(KERN_ALERT"usbfront request_irq failed (%ld)\n",rc);

	DPRINTK(KERN_INFO __FILE__
                ": USB XHCI: SHM at %p (0x%lx), EVTCHN %d\n",
                xhci->usb_ring.sring, virt_to_mfn(xhci->usbif),
                xhci->evtchn);

        xhci->state = USBIF_STATE_CONNECTED;

        break;

    default:
        printk(KERN_WARNING "Status change to unknown value %d\n", 
               status->status);
        break;
    }

    return;

 alloc_ports_nomem:
    printk(KERN_WARNING "Failed to allocate port memory, XHCI failed to connect.\n");
    return;
}

/**
 * usbif_ctrlif_rx - demux control messages by subtype
 */
static void usbif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED:
        usbif_status_change((usbif_fe_interface_status_changed_t *)
                            &msg->msg[0]);
        break;

        /* New interface...? */
    default:
        msg->length = 0;
        break;
    }

    ctrl_if_send_response(msg);
}

static void send_driver_up(void)
{
        control_msg_t cmsg;
        usbif_fe_interface_status_changed_t st;

        /* Send a driver-UP notification to the domain controller. */
        cmsg.type      = CMSG_USBIF_FE;
        cmsg.subtype   = CMSG_USBIF_FE_DRIVER_STATUS_CHANGED;
        cmsg.length    = sizeof(usbif_fe_driver_status_changed_t);
        st.status      = USBIF_DRIVER_STATUS_UP;
        memcpy(cmsg.msg, &st, sizeof(st));
        ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

void usbif_resume(void)
{
        int i;
        
        /* Fake disconnection on all virtual USB ports (suspending / migrating
         * will destroy hard state associated will the USB devices anyhow). */
        /* No need to lock here. */
        for ( i = 0; i < xhci->rh.numports; i++ )
        {
                xhci->rh.ports[i].cs = 0;
                xhci->rh.ports[i].cs_chg = 1;
		xhci->rh.ports[i].pe = 0;
        }
        
        send_driver_up();
}

static int __init xhci_hcd_init(void)
{
	int retval = -ENOMEM, i;

	if ( (xen_start_info->flags & SIF_INITDOMAIN) ||
	     (xen_start_info->flags & SIF_USB_BE_DOMAIN) )
                return 0;

	info(DRIVER_DESC " " DRIVER_VERSION);

	if (debug) {
		errbuf = kmalloc(ERRBUF_LEN, GFP_KERNEL);
		if (!errbuf)
			goto errbuf_failed;
	}

	xhci_up_cachep = kmem_cache_create("xhci_urb_priv",
		sizeof(struct urb_priv), 0, 0, NULL, NULL);
	if (!xhci_up_cachep)
		goto up_failed;

        /* Let the domain controller know we're here.  For now we wait until
         * connection, as for the block and net drivers.  This is only strictly
         * necessary if we're going to boot off a USB device. */
        printk(KERN_INFO "Initialising Xen virtual USB hub\n");
    
        (void)ctrl_if_register_receiver(CMSG_USBIF_FE, usbif_ctrlif_rx,
                                        CALLBACK_IN_BLOCKING_CONTEXT);
        
	alloc_xhci();

        send_driver_up();

        /*
         * We should read 'nr_interfaces' from response message and wait
         * for notifications before proceeding. For now we assume that we
         * will be notified of exactly one interface.
         */
        for ( i=0; (xhci->state != USBIF_STATE_CONNECTED) && (i < 10*HZ); i++ )
        {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(1);
        }
        
        if (xhci->state != USBIF_STATE_CONNECTED)
            printk(KERN_WARNING "Timeout connecting USB frontend driver!\n");
	
	return 0;

up_failed:
	if (errbuf)
		kfree(errbuf);

errbuf_failed:
	return retval;
}

module_init(xhci_hcd_init);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

