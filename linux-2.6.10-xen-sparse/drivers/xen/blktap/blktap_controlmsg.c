/******************************************************************************
 * blktap_controlmsg.c
 * 
 * XenLinux virtual block-device tap.
 * Control interfaces to the frontend and backend drivers.
 * 
 * Copyright (c) 2004, Andrew Warfield
 *
 */
 
#include "blktap.h"

#define BLKIF_STATE_CLOSED       0
#define BLKIF_STATE_DISCONNECTED 1
#define BLKIF_STATE_CONNECTED    2

static char *blkif_state_name[] = {
    [BLKIF_STATE_CLOSED]       = "closed",
    [BLKIF_STATE_DISCONNECTED] = "disconnected",
    [BLKIF_STATE_CONNECTED]    = "connected",
};

static char * blkif_status_name[] = {
    [BLKIF_INTERFACE_STATUS_CLOSED]       = "closed",
    [BLKIF_INTERFACE_STATUS_DISCONNECTED] = "disconnected",
    [BLKIF_INTERFACE_STATUS_CONNECTED]    = "connected",
    [BLKIF_INTERFACE_STATUS_CHANGED]      = "changed",
};
static unsigned int blkif_pt_state = BLKIF_STATE_CLOSED;
static unsigned blkif_ptbe_irq;
unsigned int blkif_ptbe_evtchn;

/*-----[ Control Messages to/from Frontend VMs ]--------------------------*/


void blkif_ptfe_create(blkif_be_create_t *create)
{
    blkif_t      *blkif;
    domid_t       domid  = create->domid;
    unsigned int  handle = create->blkif_handle;


    /* May want to store info on the connecting domain here. */

    DPRINTK("PT got BE_CREATE\n");
    blkif = &ptfe_blkif; /* for convenience if the hash is readded later. */

    /* blkif struct init code from blkback.c */
    memset(blkif, 0, sizeof(*blkif));
    blkif->domid  = domid;
    blkif->handle = handle;
    blkif->status = DISCONNECTED;    
    spin_lock_init(&blkif->blk_ring_lock);
    atomic_set(&blkif->refcnt, 0);

    create->status = BLKIF_BE_STATUS_OKAY;
}


void blkif_ptfe_destroy(blkif_be_destroy_t *destroy)
{
    /* Clear anything that we initialized above. */

    DPRINTK("PT got BE_DESTROY\n");
    destroy->status = BLKIF_BE_STATUS_OKAY;
}

void blkif_ptfe_connect(blkif_be_connect_t *connect)
{
    domid_t       domid  = connect->domid;
    /*unsigned int  handle = connect->blkif_handle;*/
    unsigned int  evtchn = connect->evtchn;
    unsigned long shmem_frame = connect->shmem_frame;
    struct vm_struct *vma;
    pgprot_t      prot;
    int           error;
    blkif_t      *blkif;

    DPRINTK("PT got BE_CONNECT\n");

    blkif = &ptfe_blkif; /* for convenience if the hash is readded later. */

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
    {
        connect->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    prot = __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED);
    error = direct_remap_area_pages(&init_mm, VMALLOC_VMADDR(vma->addr),
                                    shmem_frame<<PAGE_SHIFT, PAGE_SIZE,
                                    prot, domid);
    if ( error != 0 )
    {
        WPRINTK("BE_CONNECT: error! (%d)\n", error);
        if ( error == -ENOMEM ) 
            connect->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        else if ( error == -EFAULT ) {
            connect->status = BLKIF_BE_STATUS_MAPPING_ERROR;
            WPRINTK("BE_CONNECT: MAPPING error!\n");
        }
        else
            connect->status = BLKIF_BE_STATUS_ERROR;
        vfree(vma->addr);
        return;
    }

    if ( blkif->status != DISCONNECTED )
    {
        connect->status = BLKIF_BE_STATUS_INTERFACE_CONNECTED;
        vfree(vma->addr);
        return;
    }

    blkif->evtchn        = evtchn;
    blkif->irq           = bind_evtchn_to_irq(evtchn);
    blkif->shmem_frame   = shmem_frame;
    blkif->blk_ring_base = (blkif_ring_t *)vma->addr;
    blkif->status        = CONNECTED;
    /*blkif_get(blkif);*/

    request_irq(blkif->irq, blkif_ptfe_int, 0, "blkif-pt-backend", blkif);

    connect->status = BLKIF_BE_STATUS_OKAY;
}

void blkif_ptfe_disconnect(blkif_be_disconnect_t *disconnect)
{
    /*
     * don't actually set the passthrough to disconnected.
     * We just act as a pipe, and defer to the real ends to handle things like
     * recovery.
     */

    DPRINTK("PT got BE_DISCONNECT\n");

    disconnect->status = BLKIF_BE_STATUS_OKAY;
    return;
}

/*-----[ Control Messages to/from Backend VM ]----------------------------*/

/* Tell the controller to bring up the interface. */
static void blkif_ptbe_send_interface_connect(void)
{
    ctrl_msg_t cmsg = {
        .type    = CMSG_BLKIF_FE,
        .subtype = CMSG_BLKIF_FE_INTERFACE_CONNECT,
        .length  = sizeof(blkif_fe_interface_connect_t),
    };
    blkif_fe_interface_connect_t *msg = (void*)cmsg.msg;
    msg->handle      = 0;
    msg->shmem_frame = virt_to_machine(blk_ptbe_ring) >> PAGE_SHIFT;
    
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

static void blkif_ptbe_close(void)
{
}

/* Move from CLOSED to DISCONNECTED state. */
static void blkif_ptbe_disconnect(void)
{
    blk_ptbe_ring = (blkif_ring_t *)__get_free_page(GFP_KERNEL);
    blk_ptbe_ring->req_prod = blk_ptbe_ring->resp_prod 
                            = ptbe_resp_cons = ptbe_req_prod = 0;
    blkif_pt_state  = BLKIF_STATE_DISCONNECTED;
    DPRINTK("Blkif-Passthrough-BE is now DISCONNECTED.\n");
    blkif_ptbe_send_interface_connect();
}

static void blkif_ptbe_connect(blkif_fe_interface_status_t *status)
{
    int err = 0;
    
    blkif_ptbe_evtchn = status->evtchn;
    blkif_ptbe_irq    = bind_evtchn_to_irq(blkif_ptbe_evtchn);

    err = request_irq(blkif_ptbe_irq, blkif_ptbe_int, 
                      SA_SAMPLE_RANDOM, "blkif", NULL);
    if ( err ) {
	WPRINTK("blkfront request_irq failed (%d)\n", err);
        return;
    } else {
	/* transtion to connected in case we need to do a 
           a partion probe on a whole disk */
        blkif_pt_state = BLKIF_STATE_CONNECTED;
    }
}

static void unexpected(blkif_fe_interface_status_t *status)
{
    WPRINTK(" TAP: Unexpected blkif status %s in state %s\n", 
           blkif_status_name[status->status],
           blkif_state_name[blkif_pt_state]);
}

static void blkif_ptbe_status(
    blkif_fe_interface_status_t *status)
{
    if ( status->handle != 0 )
    {
        DPRINTK("Status change on unsupported blkif %d\n",
               status->handle);
        return;
    }

    DPRINTK("ptbe_status: got %s\n", blkif_status_name[status->status]);
    
    switch ( status->status )
    {
    case BLKIF_INTERFACE_STATUS_CLOSED:
        switch ( blkif_pt_state )
        {
        case BLKIF_STATE_CLOSED:
            unexpected(status);
            break;
        case BLKIF_STATE_DISCONNECTED:
        case BLKIF_STATE_CONNECTED:
            unexpected(status);
            blkif_ptbe_close();
            break;
        }
        break;
        
    case BLKIF_INTERFACE_STATUS_DISCONNECTED:
        switch ( blkif_pt_state )
        {
        case BLKIF_STATE_CLOSED:
            blkif_ptbe_disconnect();
            break;
        case BLKIF_STATE_DISCONNECTED:
        case BLKIF_STATE_CONNECTED:
            printk(KERN_ALERT "*** add recovery code to the tap driver. ***\n");
            unexpected(status);
            break;
        }
        break;
        
    case BLKIF_INTERFACE_STATUS_CONNECTED:
        switch ( blkif_pt_state )
        {
        case BLKIF_STATE_CLOSED:
            unexpected(status);
            blkif_ptbe_disconnect();
            blkif_ptbe_connect(status);
            break;
        case BLKIF_STATE_DISCONNECTED:
            blkif_ptbe_connect(status);
            break;
        case BLKIF_STATE_CONNECTED:
            unexpected(status);
            blkif_ptbe_connect(status);
            break;
        }
        break;

   case BLKIF_INTERFACE_STATUS_CHANGED:
        switch ( blkif_pt_state )
        {
        case BLKIF_STATE_CLOSED:
        case BLKIF_STATE_DISCONNECTED:
            unexpected(status);
            break;
        case BLKIF_STATE_CONNECTED:
            /* vbd_update(); */
            /* tap doesn't really get state changes... */
            unexpected(status);
            break;
        }
       break;
       
    default:
        DPRINTK("Status change to unknown value %d\n", status->status);
        break;
    }
}

/*-----[ All control messages enter here: ]-------------------------------*/

void blkif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->type )
    {
    case CMSG_BLKIF_FE:

        switch ( msg->subtype )
        {
        case CMSG_BLKIF_FE_INTERFACE_STATUS:
            if ( msg->length != sizeof(blkif_fe_interface_status_t) )
                goto parse_error;
            blkif_ptbe_status((blkif_fe_interface_status_t *) &msg->msg[0]);
            break;        

        default:
            goto parse_error;
        }

    case CMSG_BLKIF_BE:
        
        switch ( msg->subtype )
        {
        case CMSG_BLKIF_BE_CREATE:
            if ( msg->length != sizeof(blkif_be_create_t) )
                goto parse_error;
            blkif_ptfe_create((blkif_be_create_t *)&msg->msg[0]);
            break; 
        case CMSG_BLKIF_BE_DESTROY:
            if ( msg->length != sizeof(blkif_be_destroy_t) )
                goto parse_error;
            blkif_ptfe_destroy((blkif_be_destroy_t *)&msg->msg[0]);
            break;        
        case CMSG_BLKIF_BE_CONNECT:
            if ( msg->length != sizeof(blkif_be_connect_t) )
                goto parse_error;
            blkif_ptfe_connect((blkif_be_connect_t *)&msg->msg[0]);
            break;        
        case CMSG_BLKIF_BE_DISCONNECT:
            if ( msg->length != sizeof(blkif_be_disconnect_t) )
                goto parse_error;
            blkif_ptfe_disconnect((blkif_be_disconnect_t *)&msg->msg[0]);
            break;        

        /* We just ignore anything to do with vbds for now. */
        
        case CMSG_BLKIF_BE_VBD_CREATE:
            DPRINTK("PT got VBD_CREATE\n");
            ((blkif_be_vbd_create_t *)&msg->msg[0])->status 
                = BLKIF_BE_STATUS_OKAY;
            break;
        case CMSG_BLKIF_BE_VBD_DESTROY:
            DPRINTK("PT got VBD_DESTROY\n");
            ((blkif_be_vbd_destroy_t *)&msg->msg[0])->status
                = BLKIF_BE_STATUS_OKAY;
            break;
        case CMSG_BLKIF_BE_VBD_GROW:
            DPRINTK("PT got VBD_GROW\n");
            ((blkif_be_vbd_grow_t *)&msg->msg[0])->status
                = BLKIF_BE_STATUS_OKAY;
            break;
        case CMSG_BLKIF_BE_VBD_SHRINK:
            DPRINTK("PT got VBD_SHRINK\n");
            ((blkif_be_vbd_shrink_t *)&msg->msg[0])->status
                = BLKIF_BE_STATUS_OKAY;
            break;
        default:
            goto parse_error;
        }
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}
