/******************************************************************************
 * arch/xen/drivers/blkif/backend/interface.c
 * 
 * Block-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define VMALLOC_VMADDR(x) ((unsigned long)(x))
#endif

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

    /*
     * These can't be done in blkif_disconnect() because at that point there
     * may be outstanding requests at the disc whose asynchronous responses
     * must still be notified to the remote driver.
     */
    unbind_evtchn_from_irq(blkif->evtchn);
    vfree(blkif->blk_ring_base);

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

void blkif_create(blkif_be_create_t *create)
{
    domid_t       domid  = create->domid;
    unsigned int  handle = create->blkif_handle;
    blkif_t     **pblkif, *blkif;

    if ( (blkif = kmem_cache_alloc(blkif_cachep, GFP_KERNEL)) == NULL )
    {
        DPRINTK("Could not create blkif: out of memory\n");
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    memset(blkif, 0, sizeof(*blkif));
    blkif->domid  = domid;
    blkif->handle = handle;
    blkif->status = DISCONNECTED;
    spin_lock_init(&blkif->vbd_lock);
    spin_lock_init(&blkif->blk_ring_lock);
    atomic_set(&blkif->refcnt, 0);

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif != NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
        {
            DPRINTK("Could not create blkif: already exists\n");
            create->status = BLKIF_BE_STATUS_INTERFACE_EXISTS;
            kmem_cache_free(blkif_cachep, blkif);
            return;
        }
        pblkif = &(*pblkif)->hash_next;
    }

    blkif->hash_next = *pblkif;
    *pblkif = blkif;

    DPRINTK("Successfully created blkif\n");
    create->status = BLKIF_BE_STATUS_OKAY;
}

void blkif_destroy(blkif_be_destroy_t *destroy)
{
    domid_t       domid  = destroy->domid;
    unsigned int  handle = destroy->blkif_handle;
    blkif_t     **pblkif, *blkif;

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
    destroy_all_vbds(blkif);
    kmem_cache_free(blkif_cachep, blkif);
    destroy->status = BLKIF_BE_STATUS_OKAY;
}

void blkif_connect(blkif_be_connect_t *connect)
{
    domid_t       domid  = connect->domid;
    unsigned int  handle = connect->blkif_handle;
    unsigned int  evtchn = connect->evtchn;
    unsigned long shmem_frame = connect->shmem_frame;
    struct vm_struct *vma;
    pgprot_t      prot;
    int           error;
    blkif_t      *blkif;

    blkif = blkif_find_by_handle(domid, handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("blkif_connect attempted for non-existent blkif (%u,%u)\n", 
                connect->domid, connect->blkif_handle); 
        connect->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

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
        if ( error == -ENOMEM )
            connect->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        else if ( error == -EFAULT )
            connect->status = BLKIF_BE_STATUS_MAPPING_ERROR;
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
    blkif_get(blkif);

    request_irq(blkif->irq, blkif_be_int, 0, "blkif-backend", blkif);

    connect->status = BLKIF_BE_STATUS_OKAY;
}

int blkif_disconnect(blkif_be_disconnect_t *disconnect, u8 rsp_id)
{
    domid_t       domid  = disconnect->domid;
    unsigned int  handle = disconnect->blkif_handle;
    blkif_t      *blkif;

    blkif = blkif_find_by_handle(domid, handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("blkif_disconnect attempted for non-existent blkif"
                " (%u,%u)\n", disconnect->domid, disconnect->blkif_handle); 
        disconnect->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return 1; /* Caller will send response error message. */
    }

    if ( blkif->status == CONNECTED )
    {
        blkif->status = DISCONNECTING;
        blkif->disconnect_rspid = rsp_id;
        wmb(); /* Let other CPUs see the status change. */
        free_irq(blkif->irq, blkif);
        blkif_deschedule(blkif);
        blkif_put(blkif);
        return 0; /* Caller should not send response message. */
    }

    disconnect->status = BLKIF_BE_STATUS_OKAY;
    return 1;
}

void __init blkif_interface_init(void)
{
    blkif_cachep = kmem_cache_create("blkif_cache", sizeof(blkif_t), 
                                     0, 0, NULL, NULL);
    memset(blkif_hash, 0, sizeof(blkif_hash));
}
