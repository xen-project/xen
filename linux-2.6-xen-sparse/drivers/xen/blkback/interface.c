/******************************************************************************
 * arch/xen/drivers/blkif/backend/interface.c
 * 
 * Block-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"
#include <asm-xen/ctrl_if.h>
#include <asm-xen/evtchn.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define VMALLOC_VMADDR(x) ((unsigned long)(x))
#endif

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d) (((int)(_d))&(BLKIF_HASHSZ-1))

static kmem_cache_t *blkif_cachep;
static blkif_t      *blkif_hash[BLKIF_HASHSZ];

blkif_t *blkif_find(domid_t domid)
{
    blkif_t *blkif = blkif_hash[BLKIF_HASH(domid)];

    while (blkif) {
	if (blkif->domid == domid) {
	    blkif_get(blkif);
	    return blkif;
	}
        blkif = blkif->hash_next;
    }

    blkif = kmem_cache_alloc(blkif_cachep, GFP_KERNEL);
    if (!blkif)
	    return ERR_PTR(-ENOMEM);

    memset(blkif, 0, sizeof(*blkif));
    blkif->domid = domid;
    blkif->status = DISCONNECTED;
    spin_lock_init(&blkif->vbd_lock);
    spin_lock_init(&blkif->blk_ring_lock);
    atomic_set(&blkif->refcnt, 1);

    blkif->hash_next = blkif_hash[BLKIF_HASH(domid)];
    blkif_hash[BLKIF_HASH(domid)] = blkif;
    return blkif;
}

#ifndef CONFIG_XEN_BLKDEV_GRANT
static int map_frontend_page(blkif_t *blkif, unsigned long localaddr,
			     unsigned long shared_page)
{
    return direct_remap_area_pages(&init_mm, localaddr,
				   shared_page<<PAGE_SHIFT, PAGE_SIZE,
				   __pgprot(_KERNPG_TABLE), blkif->domid);
}

static void unmap_frontend_page(blkif_t *blkif)
{
}
#else
static int map_frontend_page(blkif_t *blkif, unsigned long localaddr,
			     unsigned long shared_page)
{
    struct gnttab_map_grant_ref op;
    op.host_addr = localaddr;
    op.flags = GNTMAP_host_map;
    op.ref = shared_page;
    op.dom = blkif->domid;
       
    BUG_ON( HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1) );

    if (op.handle < 0) {
	DPRINTK(" Grant table operation failure !\n");
	return op.handle;
    }

    blkif->shmem_ref = shared_page;
    blkif->shmem_handle = op.handle;
    blkif->shmem_vaddr = localaddr;
    return 0;
}

static void unmap_frontend_page(blkif_t *blkif)
{
    struct gnttab_unmap_grant_ref op;

    op.host_addr = blkif->shmem_vaddr;
    op.handle = blkif->shmem_handle;
    op.dev_bus_addr = 0;
    BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1));
}
#endif /* CONFIG_XEN_BLKDEV_GRANT */

int blkif_map(blkif_t *blkif, unsigned long shared_page, unsigned int evtchn)
{
    struct vm_struct *vma;
    blkif_sring_t *sring;
    evtchn_op_t op = { .cmd = EVTCHNOP_bind_interdomain };
    int err;

    BUG_ON(blkif->remote_evtchn);

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
	return -ENOMEM;

    err = map_frontend_page(blkif, VMALLOC_VMADDR(vma->addr), shared_page);
    if (err) {
        vfree(vma->addr);
	return err;
    }

    op.u.bind_interdomain.dom1 = DOMID_SELF;
    op.u.bind_interdomain.dom2 = blkif->domid;
    op.u.bind_interdomain.port1 = 0;
    op.u.bind_interdomain.port2 = evtchn;
    err = HYPERVISOR_event_channel_op(&op);
    if (err) {
	unmap_frontend_page(blkif);
	vfree(vma->addr);
	return err;
    }

    blkif->evtchn = op.u.bind_interdomain.port1;
    blkif->remote_evtchn = evtchn;

    sring = (blkif_sring_t *)vma->addr;
    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&blkif->blk_ring, sring, PAGE_SIZE);

    bind_evtchn_to_irqhandler(blkif->evtchn, blkif_be_int, 0, "blkif-backend",
			      blkif);
    blkif->status        = CONNECTED;
    blkif->shmem_frame   = shared_page;

    return 0;
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
    unmap_frontend_page(blkif);
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
    BUG_ON(blkif->status != DISCONNECTING);
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

void free_blkif(blkif_t *blkif)
{
    blkif_t     **pblkif;
    evtchn_op_t op = { .cmd = EVTCHNOP_close };

    op.u.close.port = blkif->evtchn;
    op.u.close.dom = DOMID_SELF;
    HYPERVISOR_event_channel_op(&op);
    op.u.close.port = blkif->remote_evtchn;
    op.u.close.dom = blkif->domid;
    HYPERVISOR_event_channel_op(&op);

    if (blkif->evtchn)
        unbind_evtchn_from_irqhandler(blkif->evtchn, blkif);

    if (blkif->blk_ring.sring)
	    vfree(blkif->blk_ring.sring);

    pblkif = &blkif_hash[BLKIF_HASH(blkif->domid)];
    while ( *pblkif != blkif )
    {
	BUG_ON(!*pblkif);
        pblkif = &(*pblkif)->hash_next;
    }
    *pblkif = blkif->hash_next;
    destroy_all_vbds(blkif);
    kmem_cache_free(blkif_cachep, blkif);
}

void __init blkif_interface_init(void)
{
    blkif_cachep = kmem_cache_create("blkif_cache", sizeof(blkif_t), 
                                     0, 0, NULL, NULL);
    memset(blkif_hash, 0, sizeof(blkif_hash));
}
