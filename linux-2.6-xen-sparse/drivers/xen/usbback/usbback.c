/******************************************************************************
 * arch/xen/drivers/usbif/backend/main.c
 * 
 * Backend for the Xen virtual USB driver - provides an abstraction of a
 * USB host controller to the corresponding frontend driver.
 *
 * by Mark Williamson
 * Copyright (c) 2004 Intel Research Cambridge
 * Copyright (c) 2004, 2005 Mark Williamson
 *
 * Based on arch/xen/drivers/blkif/backend/main.c
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 */

#include "common.h"


#include <linux/list.h>
#include <linux/usb.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/tqueue.h>

/*
 * This is rather arbitrary.
 */
#define MAX_PENDING_REQS 4
#define BATCH_PER_DOMAIN 1

static unsigned long mmap_vstart;

/* Needs to be sufficiently large that we can map the (large) buffers
 * the USB mass storage driver wants. */
#define MMAP_PAGES_PER_REQUEST \
    (128)
#define MMAP_PAGES             \
    (MAX_PENDING_REQS * MMAP_PAGES_PER_REQUEST)

#define MMAP_VADDR(_req,_seg)                        \
    (mmap_vstart +                                   \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * PAGE_SIZE))


static spinlock_t owned_ports_lock;
LIST_HEAD(owned_ports);

/* A list of these structures is used to track ownership of physical USB
 * ports. */
typedef struct 
{
    usbif_priv_t     *usbif_priv;
    char             path[16];
    int               guest_port;
    int enabled;
    struct list_head  list;
    unsigned long guest_address; /* The USB device address that has been
                                  * assigned by the guest. */
    int               dev_present; /* Is there a device present? */
    struct usb_device * dev;
    unsigned long ifaces;  /* What interfaces are present on this device? */
} owned_port_t;


/*
 * Each outstanding request that we've passed to the lower device layers has a
 * 'pending_req' allocated to it.  The request is complete, the specified
 * domain has a response queued for it, with the saved 'id' passed back.
 */
typedef struct {
    usbif_priv_t       *usbif_priv;
    unsigned long      id;
    int                nr_pages;
    unsigned short     operation;
    int                status;
} pending_req_t;

/*
 * We can't allocate pending_req's in order, since they may complete out of 
 * order. We therefore maintain an allocation ring. This ring also indicates 
 * when enough work has been passed down -- at that point the allocation ring 
 * will be empty.
 */
static pending_req_t pending_reqs[MAX_PENDING_REQS];
static unsigned char pending_ring[MAX_PENDING_REQS];
static spinlock_t pend_prod_lock;

/* NB. We use a different index type to differentiate from shared usb rings. */
typedef unsigned int PEND_RING_IDX;
#define MASK_PEND_IDX(_i) ((_i)&(MAX_PENDING_REQS-1))
static PEND_RING_IDX pending_prod, pending_cons;
#define NR_PENDING_REQS (MAX_PENDING_REQS - pending_prod + pending_cons)

static int do_usb_io_op(usbif_priv_t *usbif, int max_to_do);
static void make_response(usbif_priv_t *usbif, unsigned long id, 
                          unsigned short op, int st, int inband,
			  unsigned long actual_length);
static void dispatch_usb_probe(usbif_priv_t *up, unsigned long id, unsigned long port);
static void dispatch_usb_io(usbif_priv_t *up, usbif_request_t *req);    
static void dispatch_usb_reset(usbif_priv_t *up, unsigned long portid);
static owned_port_t *usbif_find_port(char *);

/******************************************************************
 * PRIVATE DEBUG FUNCTIONS
 */

#undef DEBUG
#ifdef DEBUG

static void dump_port(owned_port_t *p)
{
    printk(KERN_DEBUG "owned_port_t @ %p\n"
	   "  usbif_priv @ %p\n"
	   "  path: %s\n"
	   "  guest_port: %d\n"
	   "  guest_address: %ld\n"
	   "  dev_present: %d\n"
	   "  dev @ %p\n"
	   "  ifaces: 0x%lx\n",
	   p, p->usbif_priv, p->path, p->guest_port, p->guest_address,
	   p->dev_present, p->dev, p->ifaces);
}


static void dump_request(usbif_request_t *req)
{    
    printk(KERN_DEBUG "id = 0x%lx\n"
	   "devnum %d\n"
	   "endpoint 0x%x\n"
	   "direction %d\n"
	   "speed %d\n"
	   "pipe_type 0x%x\n"
	   "transfer_buffer 0x%lx\n"
	   "length 0x%lx\n"
	   "transfer_flags 0x%lx\n"
	   "setup = { 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x }\n"
	   "iso_schedule = 0x%lx\n"
	   "num_iso %ld\n",
	   req->id, req->devnum, req->endpoint, req->direction, req->speed,
	   req->pipe_type, req->transfer_buffer, req->length,
	   req->transfer_flags, req->setup[0], req->setup[1], req->setup[2],
	   req->setup[3], req->setup[4], req->setup[5], req->setup[6],
	   req->setup[7], req->iso_schedule, req->num_iso);
}

static void dump_urb(struct urb *urb)
{
    printk(KERN_DEBUG "dumping urb @ %p\n", urb);

#define DUMP_URB_FIELD(name, format) \
    printk(KERN_DEBUG "  " # name " " format "\n", urb-> name)
    
    DUMP_URB_FIELD(pipe, "0x%x");
    DUMP_URB_FIELD(status, "%d");
    DUMP_URB_FIELD(transfer_flags, "0x%x");    
    DUMP_URB_FIELD(transfer_buffer, "%p");
    DUMP_URB_FIELD(transfer_buffer_length, "%d");
    DUMP_URB_FIELD(actual_length, "%d");
}

static void dump_response(usbif_response_t *resp)
{
    printk(KERN_DEBUG "usbback: Sending response:\n"
	   "         id = 0x%x\n"
	   "         op = %d\n"
	   "         status = %d\n"
	   "         data = %d\n"
	   "         length = %d\n",
	   resp->id, resp->op, resp->status, resp->data, resp->length);
}

#else /* DEBUG */

#define dump_port(blah)     ((void)0)
#define dump_request(blah)   ((void)0)
#define dump_urb(blah)      ((void)0)
#define dump_response(blah) ((void)0)

#endif /* DEBUG */

/******************************************************************
 * MEMORY MANAGEMENT
 */

static void fast_flush_area(int idx, int nr_pages)
{
    multicall_entry_t mcl[MMAP_PAGES_PER_REQUEST];
    int               i;

    for ( i = 0; i < nr_pages; i++ )
    {
	MULTI_update_va_mapping(mcl+i, MMAP_VADDR(idx, i),
				__pte(0), 0);
    }

    mcl[nr_pages-1].args[MULTI_UVMFLAGS_INDEX] = UVMF_TLB_FLUSH|UVMF_ALL;
    if ( unlikely(HYPERVISOR_multicall(mcl, nr_pages) != 0) )
        BUG();
}


/******************************************************************
 * USB INTERFACE SCHEDULER LIST MAINTENANCE
 */

static struct list_head usbio_schedule_list;
static spinlock_t usbio_schedule_list_lock;

static int __on_usbif_list(usbif_priv_t *up)
{
    return up->usbif_list.next != NULL;
}

void remove_from_usbif_list(usbif_priv_t *up)
{
    unsigned long flags;
    if ( !__on_usbif_list(up) ) return;
    spin_lock_irqsave(&usbio_schedule_list_lock, flags);
    if ( __on_usbif_list(up) )
    {
        list_del(&up->usbif_list);
        up->usbif_list.next = NULL;
        usbif_put(up);
    }
    spin_unlock_irqrestore(&usbio_schedule_list_lock, flags);
}

static void add_to_usbif_list_tail(usbif_priv_t *up)
{
    unsigned long flags;
    if ( __on_usbif_list(up) ) return;
    spin_lock_irqsave(&usbio_schedule_list_lock, flags);
    if ( !__on_usbif_list(up) && (up->status == CONNECTED) )
    {
        list_add_tail(&up->usbif_list, &usbio_schedule_list);
        usbif_get(up);
    }
    spin_unlock_irqrestore(&usbio_schedule_list_lock, flags);
}

void free_pending(int pending_idx)
{
    unsigned long flags;

    /* Free the pending request. */
    spin_lock_irqsave(&pend_prod_lock, flags);
    pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
    spin_unlock_irqrestore(&pend_prod_lock, flags);
}

/******************************************************************
 * COMPLETION CALLBACK -- Called as urb->complete()
 */

static void maybe_trigger_usbio_schedule(void);

static void __end_usb_io_op(struct urb *purb)
{
    pending_req_t *pending_req;
    int pending_idx;

    pending_req = purb->context;

    pending_idx = pending_req - pending_reqs;

    ASSERT(purb->actual_length <= purb->transfer_buffer_length);
    ASSERT(purb->actual_length <= pending_req->nr_pages * PAGE_SIZE);
    
    /* An error fails the entire request. */
    if ( purb->status )
    {
        printk(KERN_WARNING "URB @ %p failed. Status %d\n", purb, purb->status);
    }

    if ( usb_pipetype(purb->pipe) == 0 )
    {
        int i;
        usbif_iso_t *sched = (usbif_iso_t *)MMAP_VADDR(pending_idx, pending_req->nr_pages - 1);

        /* If we're dealing with an iso pipe, we need to copy back the schedule. */
        for ( i = 0; i < purb->number_of_packets; i++ )
        {
            sched[i].length = purb->iso_frame_desc[i].actual_length;
            ASSERT(sched[i].buffer_offset ==
                   purb->iso_frame_desc[i].offset);
            sched[i].status = purb->iso_frame_desc[i].status;
        }
    }
    
    fast_flush_area(pending_req - pending_reqs, pending_req->nr_pages);

    kfree(purb->setup_packet);

    make_response(pending_req->usbif_priv, pending_req->id,
		  pending_req->operation, pending_req->status, 0, purb->actual_length);
    usbif_put(pending_req->usbif_priv);

    usb_free_urb(purb);

    free_pending(pending_idx);
    
    rmb();

    /* Check for anything still waiting in the rings, having freed a request... */
    maybe_trigger_usbio_schedule();
}

/******************************************************************
 * SCHEDULER FUNCTIONS
 */

static DECLARE_WAIT_QUEUE_HEAD(usbio_schedule_wait);

static int usbio_schedule(void *arg)
{
    DECLARE_WAITQUEUE(wq, current);

    usbif_priv_t          *up;
    struct list_head *ent;

    daemonize();

    for ( ; ; )
    {
        /* Wait for work to do. */
        add_wait_queue(&usbio_schedule_wait, &wq);
        set_current_state(TASK_INTERRUPTIBLE);
        if ( (NR_PENDING_REQS == MAX_PENDING_REQS) || 
             list_empty(&usbio_schedule_list) )
            schedule();
        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&usbio_schedule_wait, &wq);

        /* Queue up a batch of requests. */
        while ( (NR_PENDING_REQS < MAX_PENDING_REQS) &&
                !list_empty(&usbio_schedule_list) )
        {
            ent = usbio_schedule_list.next;
            up = list_entry(ent, usbif_priv_t, usbif_list);
            usbif_get(up);
            remove_from_usbif_list(up);
            if ( do_usb_io_op(up, BATCH_PER_DOMAIN) )
                add_to_usbif_list_tail(up);
            usbif_put(up);
        }
    }
}

static void maybe_trigger_usbio_schedule(void)
{
    /*
     * Needed so that two processes, who together make the following predicate
     * true, don't both read stale values and evaluate the predicate
     * incorrectly. Incredibly unlikely to stall the scheduler on x86, but...
     */
    smp_mb();

    if ( !list_empty(&usbio_schedule_list) )
        wake_up(&usbio_schedule_wait);
}


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

irqreturn_t usbif_be_int(int irq, void *dev_id, struct pt_regs *regs)
{
    usbif_priv_t *up = dev_id;

    smp_mb();

    add_to_usbif_list_tail(up); 

    /* Will in fact /always/ trigger an io schedule in this case. */
    maybe_trigger_usbio_schedule();

    return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the usb-device layer proper.
 */

static int do_usb_io_op(usbif_priv_t *up, int max_to_do)
{
    usbif_back_ring_t *usb_ring = &up->usb_ring;
    usbif_request_t *req;
    RING_IDX i, rp;
    int more_to_do = 0;

    rp = usb_ring->sring->req_prod;
    rmb(); /* Ensure we see queued requests up to 'rp'. */
    
    /* Take items off the comms ring, taking care not to overflow. */
    for ( i = usb_ring->req_cons; 
          (i != rp) && !RING_REQUEST_CONS_OVERFLOW(usb_ring, i);
          i++ )
    {
        if ( (max_to_do-- == 0) || (NR_PENDING_REQS == MAX_PENDING_REQS) )
        {
            more_to_do = 1;
            break;
        }

        req = RING_GET_REQUEST(usb_ring, i);
        
        switch ( req->operation )
        {
        case USBIF_OP_PROBE:
            dispatch_usb_probe(up, req->id, req->port);
            break;

        case USBIF_OP_IO:
	  /* Assemble an appropriate URB. */
	  dispatch_usb_io(up, req);
          break;

	case USBIF_OP_RESET:
	  dispatch_usb_reset(up, req->port);
          break;

        default:
            DPRINTK("error: unknown USB io operation [%d]\n",
                    req->operation);
            make_response(up, req->id, req->operation, -EINVAL, 0, 0);
            break;
        }
    }

    usb_ring->req_cons = i;

    return more_to_do;
}

static owned_port_t *find_guest_port(usbif_priv_t *up, int port)
{
    unsigned long flags;
    struct list_head *l;

    spin_lock_irqsave(&owned_ports_lock, flags);
    list_for_each(l, &owned_ports)
    {
        owned_port_t *p = list_entry(l, owned_port_t, list);
        if(p->usbif_priv == up && p->guest_port == port)
        {
            spin_unlock_irqrestore(&owned_ports_lock, flags);
            return p;
        }
    }
    spin_unlock_irqrestore(&owned_ports_lock, flags);

    return NULL;
}

static void dispatch_usb_reset(usbif_priv_t *up, unsigned long portid)
{
    owned_port_t *port = find_guest_port(up, portid);
    int ret = 0;


    /* Allowing the guest to actually reset the device causes more problems
     * than it's worth.  We just fake it out in software but we will do a real
     * reset when the interface is destroyed. */

    dump_port(port);

    port->guest_address = 0;
    /* If there's an attached device then the port is now enabled. */
    if ( port->dev_present )
        port->enabled = 1;
    else
        port->enabled = 0;

    make_response(up, 0, USBIF_OP_RESET, ret, 0, 0);
}

static void dispatch_usb_probe(usbif_priv_t *up, unsigned long id, unsigned long portid)
{
    owned_port_t *port = find_guest_port(up, portid);
    int ret;
 
    if ( port != NULL )
        ret = port->dev_present;
    else
    {
        ret = -EINVAL;
        printk(KERN_INFO "dispatch_usb_probe(): invalid port probe request "
	       "(port %ld)\n", portid);
    }

    /* Probe result is sent back in-band.  Probes don't have an associated id
     * right now... */
    make_response(up, id, USBIF_OP_PROBE, ret, portid, 0);
}

/**
 * check_iso_schedule - safety check the isochronous schedule for an URB
 * @purb : the URB in question
 */
static int check_iso_schedule(struct urb *purb)
{
    int i;
    unsigned long total_length = 0;
    
    for ( i = 0; i < purb->number_of_packets; i++ )
    {
        struct usb_iso_packet_descriptor *desc = &purb->iso_frame_desc[i];
        
        if ( desc->offset >= purb->transfer_buffer_length
            || ( desc->offset + desc->length) > purb->transfer_buffer_length )
            return -EINVAL;

        total_length += desc->length;

        if ( total_length > purb->transfer_buffer_length )
            return -EINVAL;
    }
    
    return 0;
}

owned_port_t *find_port_for_request(usbif_priv_t *up, usbif_request_t *req);

static void dispatch_usb_io(usbif_priv_t *up, usbif_request_t *req)
{
    unsigned long buffer_mach;
    int i = 0, offset = 0,
        pending_idx = pending_ring[MASK_PEND_IDX(pending_cons)];
    pending_req_t *pending_req;
    unsigned long  remap_prot;
    multicall_entry_t mcl[MMAP_PAGES_PER_REQUEST];
    struct urb *purb = NULL;
    owned_port_t *port;
    unsigned char *setup;    

    dump_request(req);

    if ( NR_PENDING_REQS == MAX_PENDING_REQS )
    {
        printk(KERN_WARNING "usbback: Max requests already queued. "
	       "Giving up!\n");
        
        return;
    }

    port = find_port_for_request(up, req);

    if ( port == NULL )
    {
	printk(KERN_WARNING "No such device! (%d)\n", req->devnum);
	dump_request(req);

        make_response(up, req->id, req->operation, -ENODEV, 0, 0);
	return;
    }
    else if ( !port->dev_present )
    {
        /* In normal operation, we'll only get here if a device is unplugged
         * and the frontend hasn't noticed yet. */
        make_response(up, req->id, req->operation, -ENODEV, 0, 0);
	return;
    }
        

    setup = kmalloc(8, GFP_KERNEL);

    if ( setup == NULL )
        goto no_mem;
   
    /* Copy request out for safety. */
    memcpy(setup, req->setup, 8);

    if( setup[0] == 0x0 && setup[1] == 0x5)
    {
        /* To virtualise the USB address space, we need to intercept
         * set_address messages and emulate.  From the USB specification:
         * bmRequestType = 0x0;
         * Brequest = SET_ADDRESS (i.e. 0x5)
         * wValue = device address
         * wIndex = 0
         * wLength = 0
         * data = None
         */
        /* Store into the guest transfer buffer using cpu_to_le16 */
        port->guest_address = le16_to_cpu(*(u16 *)(setup + 2));
        /* Make a successful response.  That was easy! */

        make_response(up, req->id, req->operation, 0, 0, 0);

	kfree(setup);
        return;
    }
    else if ( setup[0] == 0x0 && setup[1] == 0x9 )
    {
        /* The host kernel needs to know what device configuration is in use
         * because various error checks get confused otherwise.  We just do
         * configuration settings here, under controlled conditions.
         */

      /* Ignore configuration setting and hope that the host kernel
	 did it right. */
        /* usb_set_configuration(port->dev, setup[2]); */

        make_response(up, req->id, req->operation, 0, 0, 0);

        kfree(setup);
        return;
    }
    else if ( setup[0] == 0x1 && setup[1] == 0xB )
    {
        /* The host kernel needs to know what device interface is in use
         * because various error checks get confused otherwise.  We just do
         * configuration settings here, under controlled conditions.
         */
        usb_set_interface(port->dev, (setup[4] | setup[5] << 8),
                          (setup[2] | setup[3] << 8) );

        make_response(up, req->id, req->operation, 0, 0, 0);

        kfree(setup);
        return;
    }

    if ( ( req->transfer_buffer - (req->transfer_buffer & PAGE_MASK)
	   + req->length )
	 > MMAP_PAGES_PER_REQUEST * PAGE_SIZE )
    {
        printk(KERN_WARNING "usbback: request of %lu bytes too large\n",
	       req->length);
        make_response(up, req->id, req->operation, -EINVAL, 0, 0);
        kfree(setup);
        return;
    }
    
    buffer_mach = req->transfer_buffer;

    if( buffer_mach == 0 )
	goto no_remap;

    ASSERT((req->length >> PAGE_SHIFT) <= MMAP_PAGES_PER_REQUEST);
    ASSERT(buffer_mach);

    /* Always map writeable for now. */
    remap_prot = _KERNPG_TABLE;

    for ( i = 0, offset = 0; offset < req->length;
          i++, offset += PAGE_SIZE )
    {
	MULTI_update_va_mapping_otherdomain(
	    mcl+i, MMAP_VADDR(pending_idx, i),
	    pfn_pte_ma((buffer_mach + offset) >> PAGE_SHIFT, remap_prot),
	    0, up->domid);
        
        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx, i))>>PAGE_SHIFT] =
            FOREIGN_FRAME((buffer_mach + offset) >> PAGE_SHIFT);

        ASSERT(virt_to_mfn(MMAP_VADDR(pending_idx, i))
               == ((buffer_mach >> PAGE_SHIFT) + i));
    }

    if ( req->pipe_type == 0 && req->num_iso > 0 ) /* Maybe schedule ISO... */
    {
        /* Map in ISO schedule, if necessary. */
	MULTI_update_va_mapping_otherdomain(
	    mcl+i, MMAP_VADDR(pending_idx, i),
	    pfn_pte_ma(req->iso_schedule >> PAGE_SHIFT, remap_prot),
	    0, up->domid);

        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx, i))>>PAGE_SHIFT] =
            FOREIGN_FRAME(req->iso_schedule >> PAGE_SHIFT);
    
        i++;
    }

    if ( unlikely(HYPERVISOR_multicall(mcl, i) != 0) )
        BUG();
    
    {
        int j;
        for ( j = 0; j < i; j++ )
        {
            if ( unlikely(mcl[j].result != 0) )
            {
                printk(KERN_WARNING
		       "invalid buffer %d -- could not remap it\n", j);
                fast_flush_area(pending_idx, i);
                goto bad_descriptor;
            }
	}
    }
    
 no_remap:

    ASSERT(i <= MMAP_PAGES_PER_REQUEST);
    ASSERT(i * PAGE_SIZE >= req->length);

    /* We have to do this because some things might complete out of order. */
    pending_req = &pending_reqs[pending_idx];
    pending_req->usbif_priv= up;
    pending_req->id        = req->id;
    pending_req->operation = req->operation;
    pending_req->nr_pages  = i;

    pending_cons++;

    usbif_get(up);
    
    /* Fill out an actual request for the USB layer. */
    purb = usb_alloc_urb(req->num_iso);

    if ( purb == NULL )
    {
        usbif_put(up);
        free_pending(pending_idx);
        goto no_mem;
    }

    purb->dev = port->dev;
    purb->context = pending_req;
    purb->transfer_buffer =
        (void *)(MMAP_VADDR(pending_idx, 0) + (buffer_mach & ~PAGE_MASK));
    if(buffer_mach == 0)
      purb->transfer_buffer = NULL;
    purb->complete = __end_usb_io_op;
    purb->transfer_buffer_length = req->length;
    purb->transfer_flags = req->transfer_flags;

    purb->pipe = 0;
    purb->pipe |= req->direction << 7;
    purb->pipe |= port->dev->devnum << 8;
    purb->pipe |= req->speed << 26;
    purb->pipe |= req->pipe_type << 30;
    purb->pipe |= req->endpoint << 15;

    purb->number_of_packets = req->num_iso;

    if ( purb->number_of_packets * sizeof(usbif_iso_t) > PAGE_SIZE )
        goto urb_error;

    /* Make sure there's always some kind of timeout. */
    purb->timeout = ( req->timeout > 0 ) ? (req->timeout * HZ) / 1000
                    :  1000;

    purb->setup_packet = setup;

    if ( req->pipe_type == 0 ) /* ISO */
    {
        int j;
        usbif_iso_t *iso_sched = (usbif_iso_t *)MMAP_VADDR(pending_idx, i - 1);

        /* If we're dealing with an iso pipe, we need to copy in a schedule. */
        for ( j = 0; j < purb->number_of_packets; j++ )
        {
            purb->iso_frame_desc[j].length = iso_sched[j].length;
            purb->iso_frame_desc[j].offset = iso_sched[j].buffer_offset;
            iso_sched[j].status = 0;
        }
    }

    if ( check_iso_schedule(purb) != 0 )
        goto urb_error;

    if ( usb_submit_urb(purb) != 0 )
        goto urb_error;

    return;

 urb_error:
    dump_urb(purb);    
    usbif_put(up);
    free_pending(pending_idx);

 bad_descriptor:
    kfree ( setup );
    if ( purb != NULL )
        usb_free_urb(purb);
    make_response(up, req->id, req->operation, -EINVAL, 0, 0);
    return;
    
 no_mem:
    if ( setup != NULL )
        kfree(setup);
    make_response(up, req->id, req->operation, -ENOMEM, 0, 0);
    return;
} 



/******************************************************************
 * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
 */


static void make_response(usbif_priv_t *up, unsigned long id,
                          unsigned short op, int st, int inband,
			  unsigned long length)
{
    usbif_response_t *resp;
    unsigned long     flags;
    usbif_back_ring_t *usb_ring = &up->usb_ring;

    /* Place on the response ring for the relevant domain. */ 
    spin_lock_irqsave(&up->usb_ring_lock, flags);
    resp = RING_GET_RESPONSE(usb_ring, usb_ring->rsp_prod_pvt);
    resp->id        = id;
    resp->operation = op;
    resp->status    = st;
    resp->data      = inband;
    resp->length = length;
    wmb(); /* Ensure other side can see the response fields. */

    dump_response(resp);

    usb_ring->rsp_prod_pvt++;
    RING_PUSH_RESPONSES(usb_ring);
    spin_unlock_irqrestore(&up->usb_ring_lock, flags);

    /* Kick the relevant domain. */
    notify_via_evtchn(up->evtchn);
}

/**
 * usbif_claim_port - claim devices on a port on behalf of guest
 *
 * Once completed, this will ensure that any device attached to that
 * port is claimed by this driver for use by the guest.
 */
int usbif_claim_port(usbif_be_claim_port_t *msg)
{
    owned_port_t *o_p;
    
    /* Sanity... */
    if ( usbif_find_port(msg->path) != NULL )
    {
        printk(KERN_WARNING "usbback: Attempted to claim USB port "
               "we already own!\n");
        return -EINVAL;
    }

    /* No need for a slab cache - this should be infrequent. */
    o_p = kmalloc(sizeof(owned_port_t), GFP_KERNEL);

    if ( o_p == NULL )
        return -ENOMEM;

    o_p->enabled = 0;
    o_p->usbif_priv = usbif_find(msg->domid);
    o_p->guest_port = msg->usbif_port;
    o_p->dev_present = 0;
    o_p->guest_address = 0; /* Default address. */

    strcpy(o_p->path, msg->path);

    spin_lock_irq(&owned_ports_lock);
    
    list_add(&o_p->list, &owned_ports);

    spin_unlock_irq(&owned_ports_lock);

    printk(KERN_INFO "usbback: Claimed USB port (%s) for %d.%d\n", o_p->path,
	   msg->domid, msg->usbif_port);

    /* Force a reprobe for unclaimed devices. */
    usb_scan_devices();

    return 0;
}

owned_port_t *find_port_for_request(usbif_priv_t *up, usbif_request_t *req)
{
    unsigned long flags;
    struct list_head *port;

    /* I'm assuming this is not called from IRQ context - correct?  I think
     * it's probably only called in response to control messages or plug events
     * in the USB hub kernel thread, so should be OK. */
    spin_lock_irqsave(&owned_ports_lock, flags);
    list_for_each(port, &owned_ports)
    {
        owned_port_t *p = list_entry(port, owned_port_t, list);
        if(p->usbif_priv == up && p->guest_address == req->devnum && p->enabled )
	  {
              dump_port(p);

	      spin_unlock_irqrestore(&owned_ports_lock, flags);
              return p;
	  }
    }
    spin_unlock_irqrestore(&owned_ports_lock, flags);

    return NULL;    
}

owned_port_t *__usbif_find_port(char *path)
{
    struct list_head *port;

    list_for_each(port, &owned_ports)
    {
        owned_port_t *p = list_entry(port, owned_port_t, list);
        if(!strcmp(path, p->path))
        {
            return p;
        }
    }

    return NULL;
}

owned_port_t *usbif_find_port(char *path)
{
    owned_port_t *ret;
    unsigned long flags;

    spin_lock_irqsave(&owned_ports_lock, flags);
    ret = __usbif_find_port(path);    
    spin_unlock_irqrestore(&owned_ports_lock, flags);

    return ret;
}


static void *probe(struct usb_device *dev, unsigned iface,
                   const struct usb_device_id *id)
{
    owned_port_t *p;

    /* We don't care what the device is - if we own the port, we want it.  We
     * don't deal with device-specifics in this driver, so we don't care what
     * the device actually is ;-) */
    if ( ( p = usbif_find_port(dev->devpath) ) != NULL )
    {
        printk(KERN_INFO "usbback: claimed device attached to owned port\n");

        p->dev_present = 1;
        p->dev = dev;
        set_bit(iface, &p->ifaces);
        
        return p->usbif_priv;
    }
    else
        printk(KERN_INFO "usbback: hotplug for non-owned port (%s), ignoring\n",
	       dev->devpath);
   

    return NULL;
}

static void disconnect(struct usb_device *dev, void *usbif)
{
    /* Note the device is removed so we can tell the guest when it probes. */
    owned_port_t *port = usbif_find_port(dev->devpath);
    port->dev_present = 0;
    port->dev = NULL;
    port->ifaces = 0;
}


struct usb_driver driver =
{
    .owner      = THIS_MODULE,
    .name       = "Xen USB Backend",
    .probe      = probe,
    .disconnect = disconnect,
    .id_table   = NULL,
};

/* __usbif_release_port - internal mechanics for releasing a port */
void __usbif_release_port(owned_port_t *p)
{
    int i;

    for ( i = 0; p->ifaces != 0; i++)
        if ( p->ifaces & 1 << i )
        {
            usb_driver_release_interface(&driver, usb_ifnum_to_if(p->dev, i));
            clear_bit(i, &p->ifaces);
        }
    list_del(&p->list);

    /* Reset the real device.  We don't simulate disconnect / probe for other
     * drivers in this kernel because we assume the device is completely under
     * the control of ourselves (i.e. the guest!).  This should ensure that the
     * device is in a sane state for the next customer ;-) */

    /* MAW NB: we're not resetting the real device here.  This looks perfectly
     * valid to me but it causes memory corruption.  We seem to get away with not
     * resetting for now, although it'd be nice to have this tracked down. */
/*     if ( p->dev != NULL) */
/*         usb_reset_device(p->dev); */

    kfree(p);
}


/**
 * usbif_release_port - stop claiming devices on a port on behalf of guest
 */
void usbif_release_port(usbif_be_release_port_t *msg)
{
    owned_port_t *p;

    spin_lock_irq(&owned_ports_lock);
    p = __usbif_find_port(msg->path);
    __usbif_release_port(p);
    spin_unlock_irq(&owned_ports_lock);
}

void usbif_release_ports(usbif_priv_t *up)
{
    struct list_head *port, *tmp;
    unsigned long flags;
    
    spin_lock_irqsave(&owned_ports_lock, flags);
    list_for_each_safe(port, tmp, &owned_ports)
    {
        owned_port_t *p = list_entry(port, owned_port_t, list);
        if ( p->usbif_priv == up )
            __usbif_release_port(p);
    }
    spin_unlock_irqrestore(&owned_ports_lock, flags);
}

static int __init usbif_init(void)
{
    int i;
    struct page *page;

    if ( !(xen_start_info->flags & SIF_INITDOMAIN) &&
         !(xen_start_info->flags & SIF_USB_BE_DOMAIN) )
        return 0;

    page = balloon_alloc_empty_page_range(MMAP_PAGES);
    BUG_ON(page == NULL);
    mmap_vstart = (unsigned long)pfn_to_kaddr(page_to_pfn(page));

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    memset(pending_reqs, 0, sizeof(pending_reqs));
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;

    spin_lock_init(&pend_prod_lock);

    spin_lock_init(&owned_ports_lock);
    INIT_LIST_HEAD(&owned_ports);

    spin_lock_init(&usbio_schedule_list_lock);
    INIT_LIST_HEAD(&usbio_schedule_list);

    if ( kernel_thread(usbio_schedule, 0, CLONE_FS | CLONE_FILES) < 0 )
        BUG();
    
    usbif_interface_init();

    usbif_ctrlif_init();

    usb_register(&driver);

    printk(KERN_INFO "Xen USB Backend Initialised");

    return 0;
}

__initcall(usbif_init);
