/******************************************************************************
 * arch/xen/drivers/usbif/backend/main.c
 * 
 * Backend for the Xen virtual USB driver - provides an abstraction of a
 * USB host controller to the corresponding frontend driver.
 *
 * by Mark Williamson, Copyright (c) 2004 Intel Research Cambridge
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

#define MIN(x,y) ( ( x < y ) ? x : y )

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
    usbif_iso_t        *iso_sched;
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
static spinlock_t pend_prod_lock = SPIN_LOCK_UNLOCKED;

/* NB. We use a different index type to differentiate from shared blk rings. */
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


void dump_port(owned_port_t *p)
{
    printk("owned_port_t @ %p\n", p);
    printk("  usbif_priv @ %p\n", p->usbif_priv);
    printk("  path: %s\n", p->path);
    printk("  guest_port: %d\n", p->guest_port);
    printk("  guest_address: %ld\n", p->guest_address);
    printk("  dev_present: %d\n", p->dev_present);
    printk("  dev @ %p\n", p->dev);
    printk("  ifaces: 0x%lx\n", p->ifaces);
}



static void fast_flush_area(int idx, int nr_pages)
{
    multicall_entry_t mcl[MMAP_PAGES_PER_REQUEST];
    int               i;

    for ( i = 0; i < nr_pages; i++ )
    {
        mcl[i].op = __HYPERVISOR_update_va_mapping;
        mcl[i].args[0] = MMAP_VADDR(idx, i) >> PAGE_SHIFT;
        mcl[i].args[1] = 0;
        mcl[i].args[2] = 0;
    }

    mcl[nr_pages-1].args[2] = UVMF_FLUSH_TLB;
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


/******************************************************************
 * COMPLETION CALLBACK -- Called as urb->complete()
 */

static void maybe_trigger_usbio_schedule(void);

static void __end_usb_io_op(struct urb *purb)
{
    unsigned long flags;
    pending_req_t *pending_req;
    int pending_idx;

    pending_req = purb->context;

/*     printk("Completed for id = %p to 0x%lx - 0x%lx\n", pending_req->id, */
/*            virt_to_machine(purb->transfer_buffer), */
/*            virt_to_machine(purb->transfer_buffer) */
/*            + pending_req->nr_pages * PAGE_SIZE); */

    pending_idx = pending_req - pending_reqs;

    ASSERT(purb->actual_length <= purb->transfer_buffer_length);
    ASSERT(purb->actual_length <= pending_req->nr_pages * PAGE_SIZE);
    
    /* An error fails the entire request. */
    if ( purb->status )
    {
        printk("URB @ %p failed. Status %d\n", purb, purb->status);
    }

    if ( usb_pipetype(purb->pipe) == 0 )
    {
        int i;
        usbif_iso_t *sched = (usbif_iso_t *)MMAP_VADDR(pending_idx, pending_req->nr_pages - 1);

        ASSERT(sched == pending_req->sched);

	//	printk("writing back schedule at %p\n", sched);

        /* If we're dealing with an iso pipe, we need to copy back the schedule. */
        for ( i = 0; i < purb->number_of_packets; i++ )
        {
            sched[i].length = purb->iso_frame_desc[i].actual_length;
            ASSERT(sched[i].buffer_offset ==
                   purb->iso_frame_desc[i].offset);
            sched[i].status = purb->iso_frame_desc[i].status;
        }
    }
    
    //    printk("Flushing %d pages\n", pending_req->nr_pages);
    fast_flush_area(pending_req - pending_reqs, pending_req->nr_pages);

    kfree(purb->setup_packet);

    spin_lock_irqsave(&pending_req->usbif_priv->usb_ring_lock, flags);
    make_response(pending_req->usbif_priv, pending_req->id,
		  pending_req->operation, pending_req->status, 0, purb->actual_length);
    spin_unlock_irqrestore(&pending_req->usbif_priv->usb_ring_lock, flags);
    usbif_put(pending_req->usbif_priv);

    usb_free_urb(purb);

    /* Free the pending request. */
    spin_lock_irqsave(&pend_prod_lock, flags);
    pending_ring[MASK_PEND_IDX(pending_prod++)] = pending_idx;
    spin_unlock_irqrestore(&pend_prod_lock, flags);

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
    usbif_t *usb_ring = up->usb_ring_base;
    usbif_request_t *req;
    USBIF_RING_IDX i, rp;
    int more_to_do = 0;
    unsigned long flags;

    spin_lock_irqsave(&up->usb_ring_lock, flags);

    rp = usb_ring->req_prod;
    rmb(); /* Ensure we see queued requests up to 'rp'. */
    
    /* Take items off the comms ring, taking care not to overflow. */
    for ( i = up->usb_req_cons; 
          (i != rp) && ((i-up->usb_resp_prod) != USBIF_RING_SIZE);
          i++ )
    {
        if ( (max_to_do-- == 0) || (NR_PENDING_REQS == MAX_PENDING_REQS) )
        {
            more_to_do = 1;
            break;
        }

        req = &usb_ring->ring[MASK_USBIF_IDX(i)].req;
        
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

    up->usb_req_cons = i;

    spin_unlock_irqrestore(&up->usb_ring_lock, flags);

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

#if 0
    printk("Reset port %d\n", portid);

    dump_port(port);
#endif

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
        printk("dispatch_usb_probe(): invalid port probe request (port %ld)\n",
	       portid);
    }

    /* Probe result is sent back in-band.  Probes don't have an associated id
     * right now... */
    make_response(up, id, USBIF_OP_PROBE, ret, portid, 0);
}

owned_port_t *find_port_for_request(usbif_priv_t *up, usbif_request_t *req);

static void dump_request(usbif_request_t *req)
{    
    printk("id = 0x%lx\n", req->id);
    
	printk("devnum %d\n", req->devnum);
	printk("endpoint 0x%x\n", req->endpoint);
	printk("direction %d\n", req->direction);
	printk("speed %d\n", req->speed);
        printk("pipe_type 0x%x\n", req->pipe_type);
        printk("transfer_buffer 0x%lx\n", req->transfer_buffer);
        printk("length 0x%lx\n", req->length);
        printk("transfer_flags 0x%lx\n", req->transfer_flags);
        printk("setup = { 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
               req->setup[0], req->setup[1], req->setup[2], req->setup[3],
               req->setup[4], req->setup[5], req->setup[6], req->setup[7]);
        printk("iso_schedule = 0x%lx\n", req->iso_schedule);
        printk("num_iso %ld\n", req->num_iso);
}

void dump_urb(struct urb *urb)
{
    printk("dumping urb @ %p\n", urb);

#define DUMP_URB_FIELD(name, format) printk("  " # name " " format "\n", urb-> name)
    
    DUMP_URB_FIELD(pipe, "0x%x");
    DUMP_URB_FIELD(status, "%d");
    DUMP_URB_FIELD(transfer_flags, "0x%x");    
    DUMP_URB_FIELD(transfer_buffer, "%p");
    DUMP_URB_FIELD(transfer_buffer_length, "%d");
    DUMP_URB_FIELD(actual_length, "%d");
}


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

//    dump_request(req);

    if ( NR_PENDING_REQS == MAX_PENDING_REQS )
    {
        printk("usbback: Max requests already queued.  Now giving up!\n");
        
        return;
    }

    port = find_port_for_request(up, req);

    if(port == NULL)
    {
	printk("No such device! (%d)\n", req->devnum);
	dump_request(req);

        make_response(up, req->id, req->operation, -ENODEV, 0, 0);
	return;
    }

    setup = kmalloc(8, GFP_ATOMIC | GFP_NOIO);

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
        usb_set_configuration(port->dev, setup[2]);

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
        printk("usbback: request of %d bytes too large, failing it\n", req->length);
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
    remap_prot = _PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW;

    for ( i = 0, offset = 0; offset < req->length;
          i++, offset += PAGE_SIZE )
    {
      //        printk("length = %d, offset = %d, looping!\n", req->length, offset);
        
	mcl[i].op = __HYPERVISOR_update_va_mapping_otherdomain;
	mcl[i].args[0] = MMAP_VADDR(pending_idx, i) >> PAGE_SHIFT;
        mcl[i].args[1] = ((buffer_mach & PAGE_MASK) + offset) | remap_prot;
        mcl[i].args[2] = 0;
        mcl[i].args[3] = up->domid;
        
        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx, i))>>PAGE_SHIFT] =
            FOREIGN_FRAME((buffer_mach + offset) >> PAGE_SHIFT);
	//	printk("i = %d\n", i);

        ASSERT(virt_to_machine(MMAP_VADDR(pending_idx, i))
               == buffer_mach + i << PAGE_SHIFT);
    }

    if ( req->pipe_type == 0 && req->num_iso > 0 ) /* Maybe schedule ISO... */
    {
      //      printk("for iso, i = %d\n", i);
        /* Map in ISO schedule, if necessary. */
        mcl[i].op = __HYPERVISOR_update_va_mapping_otherdomain;
        mcl[i].args[0] = MMAP_VADDR(pending_idx, i) >> PAGE_SHIFT;
        mcl[i].args[1] = (req->iso_schedule & PAGE_MASK) | remap_prot;
        mcl[i].args[2] = 0;
        mcl[i].args[3] = up->domid;

        phys_to_machine_mapping[__pa(MMAP_VADDR(pending_idx, i))>>PAGE_SHIFT] =
            FOREIGN_FRAME(req->iso_schedule >> PAGE_SHIFT);
    
        //    printk("Mapped iso at %p\n", MMAP_VADDR(pending_idx, i));
        i++;
    }

    //    printk("Well we got this far!\n");

    if ( unlikely(HYPERVISOR_multicall(mcl, i) != 0) )
        BUG();
    
    {
        int j;
        for ( j = 0; j < i; j++ )
        {
            if ( unlikely(mcl[j].args[5] != 0) )
            {
                printk("invalid buffer %d -- could not remap it\n", j);
                fast_flush_area(pending_idx, i);
		printk("sending invalid descriptor\n");
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
        goto no_mem;

    purb->dev = port->dev;
    purb->context = pending_req;
    purb->transfer_buffer = (void *)MMAP_VADDR(pending_idx, 0) + (buffer_mach & ~PAGE_MASK);
    if(buffer_mach == 0)
      purb->transfer_buffer = NULL;
    purb->complete = __end_usb_io_op;
    purb->transfer_buffer_length = req->length;
    purb->transfer_flags = req->transfer_flags;

/*     if ( req->transfer_flags != 0 ) */
/*       dump_request(req); */

    purb->pipe = 0;
    purb->pipe |= req->direction << 7;
    purb->pipe |= port->dev->devnum << 8;
    purb->pipe |= req->speed << 26;
    purb->pipe |= req->pipe_type << 30;
    purb->pipe |= req->endpoint << 15;

    purb->number_of_packets = req->num_iso;

    /* Make sure there's always some kind of timeout. */
    purb->timeout = ( req->timeout > 0 ) ?  (req->timeout * HZ) / 1000
                    :  1000;

    purb->setup_packet = setup;

    if ( req->pipe_type == 0 ) /* ISO */
    {
        int j;
        usbif_iso_t *iso_sched = (usbif_iso_t *)MMAP_VADDR(pending_idx, i - 1);

	//	printk("Reading iso sched at %p\n", iso_sched);

        /* If we're dealing with an iso pipe, we need to copy in a schedule. */
        for ( j = 0; j < req->num_iso; j++ )
        {
            purb->iso_frame_desc[j].length = iso_sched[j].length;
            purb->iso_frame_desc[j].offset = iso_sched[j].buffer_offset;
            iso_sched[j].status = 0;
        }
        pending_req->iso_sched = iso_sched;
    }

    {
      int ret;
      ret = usb_submit_urb(purb);

      //      dump_urb(purb);

      if ( ret != 0 )
          goto bad_descriptor; /* XXX free pending here! */
    }
    
    return;

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

#if 0
    printk("usbback: Sending response:\n");
    printk("         id = 0x%x\n", id);
    printk("         op = %d\n", op);
    printk("         status = %d\n", st);
    printk("         data = %d\n", inband);
    printk("         length = %d\n", length);
#endif

    /* Place on the response ring for the relevant domain. */ 
    spin_lock_irqsave(&up->usb_ring_lock, flags);
    resp = &up->usb_ring_base->
        ring[MASK_USBIF_IDX(up->usb_resp_prod)].resp;
    resp->id        = id;
    resp->operation = op;
    resp->status    = st;
    resp->data      = inband;
    resp->length = length;
    wmb(); /* Ensure other side can see the response fields. */
    up->usb_ring_base->resp_prod = ++up->usb_resp_prod;
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
        printk("usbback: Attempted to claim USB port "
               "we already own!\n");
        return -EINVAL;
    }

    spin_lock_irq(&owned_ports_lock);
    
    /* No need for a slab cache - this should be infrequent. */
    o_p = kmalloc(sizeof(owned_port_t), GFP_KERNEL);

    o_p->enabled = 0;
    o_p->usbif_priv = usbif_find(msg->domid);
    o_p->guest_port = msg->usbif_port;
    o_p->dev_present = 0;
    o_p->guest_address = 0; /* Default address. */

    strcpy(o_p->path, msg->path);

    list_add(&o_p->list, &owned_ports);

    printk("usbback: Claimed USB port (%s) for %d.%d\n", o_p->path,
	   msg->domid, msg->usbif_port);

    spin_unlock_irq(&owned_ports_lock);

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
#if 0
              printk("Found port for devnum %d\n", req->devnum);

              dump_port(p);
#endif
              return p;
	  }
    }
    spin_unlock_irqrestore(&owned_ports_lock, flags);

    return NULL;    
}

owned_port_t *usbif_find_port(char *path)
{
    struct list_head *port;
    unsigned long flags;

    spin_lock_irqsave(&owned_ports_lock, flags);
    list_for_each(port, &owned_ports)
    {
        owned_port_t *p = list_entry(port, owned_port_t, list);
        if(!strcmp(path, p->path))
        {
            spin_unlock_irqrestore(&owned_ports_lock, flags);
            return p;
        }
    }
    spin_unlock_irqrestore(&owned_ports_lock, flags);

    return NULL;
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
        printk("usbback: claimed device attached to owned port\n");

        p->dev_present = 1;
        p->dev = dev;
        set_bit(iface, &p->ifaces);
        
        return p->usbif_priv;
    }
    else
        printk("usbback: hotplug for non-owned port (%s), ignoring\n", dev->devpath);
   

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
    p = usbif_find_port(msg->path);
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

    if ( !(xen_start_info.flags & SIF_INITDOMAIN) &&
         !(xen_start_info.flags & SIF_USB_BE_DOMAIN) )
        return 0;
    
    INIT_LIST_HEAD(&owned_ports);

    usb_register(&driver);

    usbif_interface_init();

    if ( (mmap_vstart = allocate_empty_lowmem_region(MMAP_PAGES)) == 0 )
        BUG();

    pending_cons = 0;
    pending_prod = MAX_PENDING_REQS;
    memset(pending_reqs, 0, sizeof(pending_reqs));
    for ( i = 0; i < MAX_PENDING_REQS; i++ )
        pending_ring[i] = i;

    spin_lock_init(&usbio_schedule_list_lock);
    INIT_LIST_HEAD(&usbio_schedule_list);

    if ( kernel_thread(usbio_schedule, 0, CLONE_FS | CLONE_FILES) < 0 )
        BUG();
    
    usbif_ctrlif_init();

    spin_lock_init(&owned_ports_lock);

    printk("Xen USB Backend Initialised");

    return 0;
}

__initcall(usbif_init);
