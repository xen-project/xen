/******************************************************************************
 * arch/xen/drivers/usbif/backend/interface.c
 * 
 * USB device interface management.
 * 
 * by Mark Williamson, Copyright (c) 2004
 */

#include "common.h"

#define USBIF_HASHSZ 1024
#define USBIF_HASH(_d) (((int)(_d))&(USBIF_HASHSZ-1))

static kmem_cache_t      *usbif_priv_cachep;
static usbif_priv_t      *usbif_priv_hash[USBIF_HASHSZ];

usbif_priv_t *usbif_find(domid_t domid)
{
    usbif_priv_t *up = usbif_priv_hash[USBIF_HASH(domid)];
    while ( (up != NULL ) && ( up->domid != domid ) )
        up = up->hash_next;
    return up;
}

static void __usbif_disconnect_complete(void *arg)
{
    usbif_priv_t         *usbif = (usbif_priv_t *)arg;
    ctrl_msg_t            cmsg;
    usbif_be_disconnect_t disc;

    /*
     * These can't be done in usbif_disconnect() because at that point there
     * may be outstanding requests at the device whose asynchronous responses
     * must still be notified to the remote driver.
     */
    vfree(usbif->usb_ring.sring);

    /* Construct the deferred response message. */
    cmsg.type         = CMSG_USBIF_BE;
    cmsg.subtype      = CMSG_USBIF_BE_DISCONNECT;
    cmsg.id           = usbif->disconnect_rspid;
    cmsg.length       = sizeof(usbif_be_disconnect_t);
    disc.domid        = usbif->domid;
    disc.status       = USBIF_BE_STATUS_OKAY;
    memcpy(cmsg.msg, &disc, sizeof(disc));

    /*
     * Make sure message is constructed /before/ status change, because
     * after the status change the 'usbif' structure could be deallocated at
     * any time. Also make sure we send the response /after/ status change,
     * as otherwise a subsequent CONNECT request could spuriously fail if
     * another CPU doesn't see the status change yet.
     */
    mb();
    if ( usbif->status != DISCONNECTING )
        BUG();
    usbif->status = DISCONNECTED;
    mb();

    /* Send the successful response. */
    ctrl_if_send_response(&cmsg);
}

void usbif_disconnect_complete(usbif_priv_t *up)
{
    INIT_WORK(&up->work, __usbif_disconnect_complete, (void *)up);
    schedule_work(&up->work);
}

void usbif_create(usbif_be_create_t *create)
{
    domid_t       domid  = create->domid;
    usbif_priv_t **pup, *up;

    if ( (up = kmem_cache_alloc(usbif_priv_cachep, GFP_KERNEL)) == NULL )
    {
        DPRINTK("Could not create usbif: out of memory\n");
        create->status = USBIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    memset(up, 0, sizeof(*up));
    up->domid  = domid;
    up->status = DISCONNECTED;
    spin_lock_init(&up->usb_ring_lock);
    atomic_set(&up->refcnt, 0);

    pup = &usbif_priv_hash[USBIF_HASH(domid)];
    while ( *pup != NULL )
    {
        if ( (*pup)->domid == domid )
        {
            create->status = USBIF_BE_STATUS_INTERFACE_EXISTS;
            kmem_cache_free(usbif_priv_cachep, up);
            return;
        }
        pup = &(*pup)->hash_next;
    }

    up->hash_next = *pup;
    *pup = up;

    create->status = USBIF_BE_STATUS_OKAY;
}

void usbif_destroy(usbif_be_destroy_t *destroy)
{
    domid_t       domid  = destroy->domid;
    usbif_priv_t  **pup, *up;

    pup = &usbif_priv_hash[USBIF_HASH(domid)];
    while ( (up = *pup) != NULL )
    {
        if ( up->domid == domid )
        {
            if ( up->status != DISCONNECTED )
                goto still_connected;
            goto destroy;
        }
        pup = &up->hash_next;
    }

    destroy->status = USBIF_BE_STATUS_INTERFACE_NOT_FOUND;
    return;

 still_connected:
    destroy->status = USBIF_BE_STATUS_INTERFACE_CONNECTED;
    return;

 destroy:
    *pup = up->hash_next;
    usbif_release_ports(up);
    kmem_cache_free(usbif_priv_cachep, up);
    destroy->status = USBIF_BE_STATUS_OKAY;
}

void usbif_connect(usbif_be_connect_t *connect)
{
    domid_t       domid  = connect->domid;
    unsigned int  evtchn = connect->evtchn;
    unsigned long shmem_frame = connect->shmem_frame;
    struct vm_struct *vma;
    pgprot_t      prot;
    int           error;
    usbif_priv_t *up;
    usbif_sring_t *sring;

    up = usbif_find(domid);
    if ( unlikely(up == NULL) )
    {
        DPRINTK("usbif_connect attempted for non-existent usbif (%u)\n", 
                connect->domid); 
        connect->status = USBIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
    {
        connect->status = USBIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    prot = __pgprot(_KERNPG_TABLE);
    error = direct_remap_pfn_range(&init_mm, VMALLOC_VMADDR(vma->addr),
                                    shmem_frame, PAGE_SIZE,
                                    prot, domid);
    if ( error != 0 )
    {
        if ( error == -ENOMEM )
            connect->status = USBIF_BE_STATUS_OUT_OF_MEMORY;
        else if ( error == -EFAULT )
            connect->status = USBIF_BE_STATUS_MAPPING_ERROR;
        else
            connect->status = USBIF_BE_STATUS_ERROR;
        vfree(vma->addr);
        return;
    }

    if ( up->status != DISCONNECTED )
    {
        connect->status = USBIF_BE_STATUS_INTERFACE_CONNECTED;
        vfree(vma->addr);
        return;
    }

    sring = (usbif_sring_t *)vma->addr;
    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&up->usb_ring, sring, PAGE_SIZE);

    up->evtchn        = evtchn;
    up->shmem_frame   = shmem_frame;
    up->status        = CONNECTED;
    usbif_get(up);

    (void)bind_evtchn_to_irqhandler(
        evtchn, usbif_be_int, 0, "usbif-backend", up);

    connect->status = USBIF_BE_STATUS_OKAY;
}

/* Remove URBs for this interface before destroying it. */
void usbif_deschedule(usbif_priv_t *up)
{
    remove_from_usbif_list(up);
}

int usbif_disconnect(usbif_be_disconnect_t *disconnect, u8 rsp_id)
{
    domid_t       domid  = disconnect->domid;
    usbif_priv_t *up;

    up = usbif_find(domid);
    if ( unlikely(up == NULL) )
    {
        DPRINTK("usbif_disconnect attempted for non-existent usbif"
                " (%u)\n", disconnect->domid); 
        disconnect->status = USBIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return 1; /* Caller will send response error message. */
    }

    if ( up->status == CONNECTED )
    {
        up->status = DISCONNECTING;
        up->disconnect_rspid = rsp_id;
        wmb(); /* Let other CPUs see the status change. */
        unbind_evtchn_from_irqhandler(up->evtchn, up);
	usbif_deschedule(up);
        usbif_put(up);
        return 0; /* Caller should not send response message. */
    }

    disconnect->status = USBIF_BE_STATUS_OKAY;
    return 1;
}

void __init usbif_interface_init(void)
{
    usbif_priv_cachep = kmem_cache_create("usbif_priv_cache",
					  sizeof(usbif_priv_t), 
					  0, 0, NULL, NULL);
    memset(usbif_priv_hash, 0, sizeof(usbif_priv_hash));
}
