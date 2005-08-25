/******************************************************************************
 * xhci.h
 *
 * Private definitions for the Xen Virtual USB Controller.  Based on
 * drivers/usb/host/uhci.h from Linux.  Copyright for the imported content is
 * retained by the original authors.
 *
 * Modifications are:
 * Copyright (C) 2004 Intel Research Cambridge
 * Copyright (C) 2004, 2005 Mark Williamson
 */

#ifndef __LINUX_XHCI_H
#define __LINUX_XHCI_H

#include <linux/list.h>
#include <linux/usb.h>
#include <asm-xen/xen-public/io/usbif.h>
#include <linux/spinlock.h>

/* xhci_port_t - current known state of a virtual hub ports */
typedef struct {
        unsigned int cs     :1; /* Connection status.         */
        unsigned int cs_chg :1; /* Connection status change.  */
        unsigned int pe     :1; /* Port enable.               */
        unsigned int pe_chg :1; /* Port enable change.        */
        unsigned int susp   :1; /* Suspended.                 */
        unsigned int lsda   :1; /* Low speed device attached. */
        unsigned int pr     :1; /* Port reset.                */
} xhci_port_t;

/* struct virt_root_hub - state related to the virtual root hub */
struct virt_root_hub {
	struct usb_device *dev;
	int devnum;		/* Address of Root Hub endpoint */
	struct urb *urb;
	void *int_addr;
	int send;
	int interval;
	int numports;
	int c_p_r[8];
	struct timer_list rh_int_timer;
        spinlock_t port_state_lock;
        xhci_port_t *ports;
};

/* struct xhci - contains the state associated with a single USB interface */
struct xhci {

#ifdef CONFIG_PROC_FS
	/* procfs */
	int num;
	struct proc_dir_entry *proc_entry;
#endif

        int evtchn;                        /* Interdom channel to backend */
        enum { 
                USBIF_STATE_CONNECTED    = 2,
                USBIF_STATE_DISCONNECTED = 1,
                USBIF_STATE_CLOSED       = 0
        } state; /* State of this USB interface */
        unsigned long recovery; /* boolean recovery in progress flag */
        
        unsigned long bandwidth;

	struct usb_bus *bus;

	/* Main list of URB's currently controlled by this HC */
	spinlock_t urb_list_lock;
	struct list_head urb_list;		/* P: xhci->urb_list_lock */

	/* List of URB's awaiting completion callback */
	spinlock_t complete_list_lock;
	struct list_head complete_list;		/* P: xhci->complete_list_lock */

	struct virt_root_hub rh;	/* private data of the virtual root hub */

        spinlock_t ring_lock;
        usbif_front_ring_t usb_ring;

        int awaiting_reset;
};

/* per-URB private data structure for the host controller */
struct urb_priv {
	struct urb *urb;
        usbif_iso_t *schedule;
	struct usb_device *dev;

        int in_progress : 1;	        /* QH was queued (not linked in) */
	int short_control_packet : 1;	/* If we get a short packet during */
					/*  a control transfer, retrigger */
					/*  the status phase */

	int status;			/* Final status */

	unsigned long inserttime;	/* In jiffies */

	struct list_head complete_list;	/* P: xhci->complete_list_lock */
};

/*
 * Locking in xhci.c
 *
 * spinlocks are used extensively to protect the many lists and data
 * structures we have. It's not that pretty, but it's necessary. We
 * need to be done with all of the locks (except complete_list_lock) when
 * we call urb->complete. I've tried to make it simple enough so I don't
 * have to spend hours racking my brain trying to figure out if the
 * locking is safe.
 *
 * Here's the safe locking order to prevent deadlocks:
 *
 * #1 xhci->urb_list_lock
 * #2 urb->lock
 * #3 xhci->urb_remove_list_lock
 * #4 xhci->complete_list_lock
 *
 * If you're going to grab 2 or more locks at once, ALWAYS grab the lock
 * at the lowest level FIRST and NEVER grab locks at the same level at the
 * same time.
 * 
 * So, if you need xhci->urb_list_lock, grab it before you grab urb->lock
 */

/* -------------------------------------------------------------------------
   Virtual Root HUB
   ------------------------------------------------------------------------- */
/* destination of request */
#define RH_DEVICE		0x00
#define RH_INTERFACE		0x01
#define RH_ENDPOINT		0x02
#define RH_OTHER		0x03

#define RH_CLASS		0x20
#define RH_VENDOR		0x40

/* Requests: bRequest << 8 | bmRequestType */
#define RH_GET_STATUS		0x0080
#define RH_CLEAR_FEATURE	0x0100
#define RH_SET_FEATURE		0x0300
#define RH_SET_ADDRESS		0x0500
#define RH_GET_DESCRIPTOR	0x0680
#define RH_SET_DESCRIPTOR	0x0700
#define RH_GET_CONFIGURATION	0x0880
#define RH_SET_CONFIGURATION	0x0900
#define RH_GET_STATE		0x0280
#define RH_GET_INTERFACE	0x0A80
#define RH_SET_INTERFACE	0x0B00
#define RH_SYNC_FRAME		0x0C80
/* Our Vendor Specific Request */
#define RH_SET_EP		0x2000

/* Hub port features */
#define RH_PORT_CONNECTION	0x00
#define RH_PORT_ENABLE		0x01
#define RH_PORT_SUSPEND		0x02
#define RH_PORT_OVER_CURRENT	0x03
#define RH_PORT_RESET		0x04
#define RH_PORT_POWER		0x08
#define RH_PORT_LOW_SPEED	0x09
#define RH_C_PORT_CONNECTION	0x10
#define RH_C_PORT_ENABLE	0x11
#define RH_C_PORT_SUSPEND	0x12
#define RH_C_PORT_OVER_CURRENT	0x13
#define RH_C_PORT_RESET		0x14

/* Hub features */
#define RH_C_HUB_LOCAL_POWER	0x00
#define RH_C_HUB_OVER_CURRENT	0x01
#define RH_DEVICE_REMOTE_WAKEUP	0x00
#define RH_ENDPOINT_STALL	0x01

/* Our Vendor Specific feature */
#define RH_REMOVE_EP		0x00

#define RH_ACK			0x01
#define RH_REQ_ERR		-1
#define RH_NACK			0x00

#endif

