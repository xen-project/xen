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
#include <asm-xen/evtchn.h>

static char *blkif_state_name[] = {
    [BLKIF_STATE_CLOSED]       = "closed",
    [BLKIF_STATE_DISCONNECTED] = "disconnected",
    [BLKIF_STATE_CONNECTED]    = "connected",
};

static char *blkif_status_name[] = {
    [BLKIF_INTERFACE_STATUS_CLOSED]       = "closed",
    [BLKIF_INTERFACE_STATUS_DISCONNECTED] = "disconnected",
    [BLKIF_INTERFACE_STATUS_CONNECTED]    = "connected",
    [BLKIF_INTERFACE_STATUS_CHANGED]      = "changed",
};

unsigned int blktap_be_state = BLKIF_STATE_CLOSED;
unsigned int blktap_be_evtchn;

/*-----[ Control Messages to/from Frontend VMs ]--------------------------*/

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d,_h) (((int)(_d)^(int)(_h))&(BLKIF_HASHSZ-1))

static kmem_cache_t *blkif_cachep;
static blkif_t      *blkif_hash[BLKIF_HASHSZ];

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle)
{
    blkif_t *blkif = blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif != NULL) && 
            ((blkif->domid != domid) || (blkif->handle != handle)) )
        blkif = blkif->hash_next;
    return blkif;
}

static void __blkif_disconnect_complete(void *arg)
{
    blkif_t              *blkif = (blkif_t *)arg;
    ctrl_msg_t            cmsg;
    blkif_be_disconnect_t disc;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    struct gnttab_unmap_grant_ref op;
#endif

    /*
     * These can't be done in blkif_disconnect() because at that point there
     * may be outstanding requests at the disc whose asynchronous responses
     * must still be notified to the remote driver.
     */
#ifdef CONFIG_XEN_BLKDEV_GRANT
    op.host_addr = blkif->shmem_vaddr;
    op.handle         = blkif->shmem_handle;
    op.dev_bus_addr   = 0;
    BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1));
#endif
    vfree(blkif->blk_ring.sring);

    /* Construct the deferred response message. */
    cmsg.type         = CMSG_BLKIF_BE;
    cmsg.subtype      = CMSG_BLKIF_BE_DISCONNECT;
    cmsg.id           = blkif->disconnect_rspid;
    cmsg.length       = sizeof(blkif_be_disconnect_t);
    disc.domid        = blkif->domid;
    disc.blkif_handle = blkif->handle;
    disc.status       = BLKIF_BE_STATUS_OKAY;
    memcpy(cmsg.msg, &disc, sizeof(disc));

    /*
     * Make sure message is constructed /before/ status change, because
     * after the status change the 'blkif' structure could be deallocated at
     * any time. Also make sure we send the response /after/ status change,
     * as otherwise a subsequent CONNECT request could spuriously fail if
     * another CPU doesn't see the status change yet.
     */
    mb();
    if ( blkif->status != DISCONNECTING )
        BUG();
    blkif->status = DISCONNECTED;
    mb();

    /* Send the successful response. */
    ctrl_if_send_response(&cmsg);
}

void blkif_disconnect_complete(blkif_t *blkif)
{
    INIT_WORK(&blkif->work, __blkif_disconnect_complete, (void *)blkif);
    schedule_work(&blkif->work);
}

void blkif_ptfe_create(blkif_be_create_t *create)
{
    blkif_t      *blkif, **pblkif;
    domid_t       domid  = create->domid;
    unsigned int  handle = create->blkif_handle;


    /* May want to store info on the connecting domain here. */

    DPRINTK("PT got BE_CREATE\n");

    if ( (blkif = kmem_cache_alloc(blkif_cachep, GFP_KERNEL)) == NULL )
    {
        WPRINTK("Could not create blkif: out of memory\n");
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    /* blkif struct init code from blkback.c */
    memset(blkif, 0, sizeof(*blkif));
    blkif->domid  = domid;
    blkif->handle = handle;
    blkif->status = DISCONNECTED;  
    spin_lock_init(&blkif->blk_ring_lock);
    atomic_set(&blkif->refcnt, 0);

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif != NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
        {
            WPRINTK("Could not create blkif: already exists\n");
            create->status = BLKIF_BE_STATUS_INTERFACE_EXISTS;
            kmem_cache_free(blkif_cachep, blkif);
            return;
        }
        pblkif = &(*pblkif)->hash_next;
    }

    blkif->hash_next = *pblkif;
    *pblkif = blkif;

    create->status = BLKIF_BE_STATUS_OKAY;
}


void blkif_ptfe_destroy(blkif_be_destroy_t *destroy)
{
    /* Clear anything that we initialized above. */

    domid_t       domid  = destroy->domid;
    unsigned int  handle = destroy->blkif_handle;
    blkif_t     **pblkif, *blkif;

    DPRINTK("PT got BE_DESTROY\n");
    
    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif = *pblkif) != NULL )
    {
        if ( (blkif->domid == domid) && (blkif->handle == handle) )
        {
            if ( blkif->status != DISCONNECTED )
                goto still_connected;
            goto destroy;
        }
        pblkif = &blkif->hash_next;
    }

    destroy->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
    return;

 still_connected:
    destroy->status = BLKIF_BE_STATUS_INTERFACE_CONNECTED;
    return;

 destroy:
    *pblkif = blkif->hash_next;
    kmem_cache_free(blkif_cachep, blkif);
    destroy->status = BLKIF_BE_STATUS_OKAY;
}

void blkif_ptfe_connect(blkif_be_connect_t *connect)
{
    domid_t        domid  = connect->domid;
    unsigned int   handle = connect->blkif_handle;
    unsigned int   evtchn = connect->evtchn;
    unsigned long  shmem_frame = connect->shmem_frame;
    struct vm_struct *vma;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    int ref = connect->shmem_ref;
#else
    pgprot_t       prot;
    int            error;
#endif
    blkif_t       *blkif;
    blkif_sring_t *sring;

    DPRINTK("PT got BE_CONNECT\n");

    blkif = blkif_find_by_handle(domid, handle);
    if ( unlikely(blkif == NULL) )
    {
        WPRINTK("blkif_connect attempted for non-existent blkif (%u,%u)\n", 
                connect->domid, connect->blkif_handle); 
        connect->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
    {
        connect->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

#ifndef CONFIG_XEN_BLKDEV_GRANT
    prot = __pgprot(_KERNPG_TABLE);
    error = direct_remap_area_pages(&init_mm, VMALLOC_VMADDR(vma->addr),
                                    shmem_frame<<PAGE_SHIFT, PAGE_SIZE,
                                    prot, domid);
    if ( error != 0 )
    {
        if ( error == -ENOMEM ) 
            connect->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        else if ( error == -EFAULT )
            connect->status = BLKIF_BE_STATUS_MAPPING_ERROR;
        else
            connect->status = BLKIF_BE_STATUS_ERROR;
        vfree(vma->addr);
        return;
    }
#else
    { /* Map: Use the Grant table reference */
        struct gnttab_map_grant_ref op;
        op.host_addr = VMALLOC_VMADDR(vma->addr);
        op.flags            = GNTMAP_host_map;
        op.ref              = ref;
        op.dom              = domid;
       
        BUG_ON( HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1) );
       
        handle = op.handle;
       
        if (op.handle < 0) {
            DPRINTK(" Grant table operation failure !\n");
            connect->status = BLKIF_BE_STATUS_MAPPING_ERROR;
            vfree(vma->addr);
            return;
        }

        blkif->shmem_ref = ref;
        blkif->shmem_handle = handle;
        blkif->shmem_vaddr = VMALLOC_VMADDR(vma->addr);
    }
#endif

    if ( blkif->status != DISCONNECTED )
    {
        connect->status = BLKIF_BE_STATUS_INTERFACE_CONNECTED;
        vfree(vma->addr);
        return;
    }

    sring = (blkif_sring_t *)vma->addr;
    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&blkif->blk_ring, sring, PAGE_SIZE);
    
    blkif->evtchn        = evtchn;
    blkif->shmem_frame   = shmem_frame;
    blkif->status        = CONNECTED;
    blkif_get(blkif);

    bind_evtchn_to_irqhandler(
        evtchn, blkif_ptfe_int, 0, "blkif-pt-backend", blkif);

    connect->status = BLKIF_BE_STATUS_OKAY;
}

int blkif_ptfe_disconnect(blkif_be_disconnect_t *disconnect, u8 rsp_id)
{
    domid_t       domid  = disconnect->domid;
    unsigned int  handle = disconnect->blkif_handle;
    blkif_t      *blkif;

    DPRINTK("PT got BE_DISCONNECT\n");
    
    blkif = blkif_find_by_handle(domid, handle);
    if ( unlikely(blkif == NULL) )
    {
        WPRINTK("blkif_disconnect attempted for non-existent blkif"
                " (%u,%u)\n", disconnect->domid, disconnect->blkif_handle); 
        disconnect->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return 1; /* Caller will send response error message. */
    }

    if ( blkif->status == CONNECTED )
    {
        blkif->status = DISCONNECTING;
        blkif->disconnect_rspid = rsp_id;
        wmb(); /* Let other CPUs see the status change. */
        unbind_evtchn_from_irqhandler(blkif->evtchn, blkif);
        blkif_deschedule(blkif);
        blkif_put(blkif);
        return 0; /* Caller should not send response message. */
    }

    disconnect->status = BLKIF_BE_STATUS_OKAY;
    return 1;
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
    msg->shmem_frame = virt_to_mfn(blktap_be_ring.sring);
    
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

static void blkif_ptbe_close(void)
{
}

/* Move from CLOSED to DISCONNECTED state. */
static void blkif_ptbe_disconnect(void)
{
    blkif_sring_t *sring;
    
    sring = (blkif_sring_t *)__get_free_page(GFP_KERNEL);
    SHARED_RING_INIT(sring);
    FRONT_RING_INIT(&blktap_be_ring, sring, PAGE_SIZE);
    blktap_be_state  = BLKIF_STATE_DISCONNECTED;
    DPRINTK("Blkif-Passthrough-BE is now DISCONNECTED.\n");
    blkif_ptbe_send_interface_connect();
}

static void blkif_ptbe_connect(blkif_fe_interface_status_t *status)
{
    int err = 0;
    
    blktap_be_evtchn = status->evtchn;

    err = bind_evtchn_to_irqhandler(
        blktap_be_evtchn, blkif_ptbe_int, SA_SAMPLE_RANDOM, "blkif", NULL);
    if ( err ) {
	WPRINTK("blkfront bind_evtchn_to_irqhandler failed (%d)\n", err);
        return;
    } else {
	/* transtion to connected in case we need to do a 
           a partion probe on a whole disk */
        blktap_be_state = BLKIF_STATE_CONNECTED;
    }
}

static void unexpected(blkif_fe_interface_status_t *status)
{
    WPRINTK(" TAP: Unexpected blkif status %s in state %s\n", 
           blkif_status_name[status->status],
           blkif_state_name[blktap_be_state]);
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
        switch ( blktap_be_state )
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
        switch ( blktap_be_state )
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
        switch ( blktap_be_state )
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
        switch ( blktap_be_state )
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
            blkif_ptbe_status((blkif_fe_interface_status_t *) &msg->msg[0]);
            break;

        default:
            goto parse_error;
        }

        break;

    case CMSG_BLKIF_BE:
        
        /* send a copy of the message to user if wanted */
        
        if ( (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) ||
             (blktap_mode & BLKTAP_MODE_COPY_FE) ) {
            
            blktap_write_ctrl_ring(msg);
            blktap_kick_user();
        }
        
        switch ( msg->subtype )
        {
        case CMSG_BLKIF_BE_CREATE:
            blkif_ptfe_create((blkif_be_create_t *)&msg->msg[0]);
            break; 
        case CMSG_BLKIF_BE_DESTROY:
            blkif_ptfe_destroy((blkif_be_destroy_t *)&msg->msg[0]);
            break;        
        case CMSG_BLKIF_BE_CONNECT:
            blkif_ptfe_connect((blkif_be_connect_t *)&msg->msg[0]);
            break;        
        case CMSG_BLKIF_BE_DISCONNECT:
            if ( !blkif_ptfe_disconnect((blkif_be_disconnect_t *)&msg->msg[0],
                    msg->id) )
                return;
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
        default:
            goto parse_error;
        }

        break;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}

/*-----[ Initialization ]-------------------------------------------------*/

void __init blkif_interface_init(void)
{
    blkif_cachep = kmem_cache_create("blkif_cache", sizeof(blkif_t), 
                                     0, 0, NULL, NULL);
    memset(blkif_hash, 0, sizeof(blkif_hash));
    
    blktap_be_ring.sring = NULL;
}



/* Debug : print the current ring indices. */

void print_fe_ring_idxs(void)
{
    int i;
    blkif_t *blkif;
            
    WPRINTK("FE Rings: \n---------\n");
    for ( i = 0; i < BLKIF_HASHSZ; i++) { 
        blkif = blkif_hash[i];
        while (blkif != NULL) {
            if (blkif->status == DISCONNECTED) {
                WPRINTK("(%2d,%2d) DISCONNECTED\n", 
                   blkif->domid, blkif->handle);
            } else if (blkif->status == DISCONNECTING) {
                WPRINTK("(%2d,%2d) DISCONNECTING\n", 
                   blkif->domid, blkif->handle);
            } else if (blkif->blk_ring.sring == NULL) {
                WPRINTK("(%2d,%2d) CONNECTED, but null sring!\n", 
                   blkif->domid, blkif->handle);
            } else {
                blkif_get(blkif);
                WPRINTK("(%2d,%2d): req_cons: %2d, rsp_prod_prv: %2d "
                    "| req_prod: %2d, rsp_prod: %2d\n",
                    blkif->domid, blkif->handle,
                    blkif->blk_ring.req_cons,
                    blkif->blk_ring.rsp_prod_pvt,
                    blkif->blk_ring.sring->req_prod,
                    blkif->blk_ring.sring->rsp_prod);
                blkif_put(blkif);
            } 
            blkif = blkif->hash_next;
        }
    }
}        
