#ifndef __LINUX_XHCI_H
#define __LINUX_XHCI_H

#include <linux/list.h>
#include <linux/usb.h>
#include "../usbif.h"
#include <linux/spinlock.h>

#define XHCI_NUMFRAMES		1024	/* in the frame list [array] */
#define XHCI_MAX_SOF_NUMBER	2047	/* in an SOF packet */
#define CAN_SCHEDULE_FRAMES	1000	/* how far future frames can be scheduled */

/* In the absence of actual hardware state, we maintain the current known state
 * of the virtual hub ports in this data structure.
 */
typedef struct
{
        unsigned int cs     :1;     /* Connection status.  do we really need this /and/ ccs? */
        unsigned int cs_chg :1; /* Connection status change.  */
        unsigned int pe     :1;     /* Port enable.               */
        unsigned int pe_chg :1; /* Port enable change.        */
        unsigned int ccs    :1;    /* Current connect status.    */
        unsigned int susp   :1;   /* Suspended.                 */
        unsigned int lsda   :1;   /* Low speed device attached. */
        unsigned int pr     :1;     /* Port reset.                */
        
    /* Device info? */
} xhci_port_t;

struct xhci_frame_list {
	__u32 frame[XHCI_NUMFRAMES];

	void *frame_cpu[XHCI_NUMFRAMES];
};

struct urb_priv;

#define xhci_status_bits(ctrl_sts)	(ctrl_sts & 0xFE0000)
#define xhci_actual_length(ctrl_sts)	((ctrl_sts + 1) & TD_CTRL_ACTLEN_MASK) /* 1-based */

#define xhci_maxlen(token)	((token) >> 21)
#define xhci_expected_length(info) (((info >> 21) + 1) & TD_TOKEN_EXPLEN_MASK) /* 1-based */
#define xhci_toggle(token)	(((token) >> TD_TOKEN_TOGGLE_SHIFT) & 1)
#define xhci_endpoint(token)	(((token) >> 15) & 0xf)
#define xhci_devaddr(token)	(((token) >> 8) & 0x7f)
#define xhci_devep(token)	(((token) >> 8) & 0x7ff)
#define xhci_packetid(token)	((token) & TD_TOKEN_PID_MASK)
#define xhci_packetout(token)	(xhci_packetid(token) != USB_PID_IN)
#define xhci_packetin(token)	(xhci_packetid(token) == USB_PID_IN)

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
        xhci_port_t *ports;       /*  */
};

/*
 * This describes the full xhci information.
 *
 * Note how the "proper" USB information is just
 * a subset of what the full implementation needs.
 */
struct xhci {

#ifdef CONFIG_PROC_FS
	/* procfs */
	int num;
	struct proc_dir_entry *proc_entry;
#endif

        int evtchn;                        /* Interdom channel to backend */
        int irq;                           /* Bound to evtchn */
        int state;                         /* State of this USB interface */
        unsigned long bandwidth;
        int handle;

	struct usb_bus *bus;

	spinlock_t frame_list_lock;
	struct xhci_frame_list *fl;		/* P: xhci->frame_list_lock */
	int is_suspended;

	/* Main list of URB's currently controlled by this HC */
	spinlock_t urb_list_lock;
	struct list_head urb_list;		/* P: xhci->urb_list_lock */

	/* List of asynchronously unlinked URB's */
	spinlock_t urb_remove_list_lock;
	struct list_head urb_remove_list;	/* P: xhci->urb_remove_list_lock */

	/* List of URB's awaiting completion callback */
	spinlock_t complete_list_lock;
	struct list_head complete_list;		/* P: xhci->complete_list_lock */

	struct virt_root_hub rh;	/* private data of the virtual root hub */

        spinlock_t response_lock;

        usbif_t *usbif;
        int usb_resp_cons;
};

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

	struct list_head queue_list;	/* P: xhci->frame_list_lock */
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
 * #3 xhci->urb_remove_list_lock, xhci->frame_list_lock, 
 *   xhci->qh_remove_list_lock
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

