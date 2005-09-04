/******************************************************************************
 * arch/xen/drivers/blkif/backend/interface.c
 * 
 * Block-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"
#include <asm-xen/evtchn.h>

static kmem_cache_t *blkif_cachep;

blkif_t *alloc_blkif(domid_t domid)
{
    blkif_t *blkif;

    blkif = kmem_cache_alloc(blkif_cachep, GFP_KERNEL);
    if (!blkif)
	    return ERR_PTR(-ENOMEM);

    memset(blkif, 0, sizeof(*blkif));
    blkif->domid = domid;
    blkif->status = DISCONNECTED;
    spin_lock_init(&blkif->blk_ring_lock);
    atomic_set(&blkif->refcnt, 1);

    return blkif;
}

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

int blkif_map(blkif_t *blkif, unsigned long shared_page, unsigned int evtchn)
{
    struct vm_struct *vma;
    blkif_sring_t *sring;
    evtchn_op_t op = { .cmd = EVTCHNOP_bind_interdomain };
    int err;

    BUG_ON(blkif->remote_evtchn);

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
	return -ENOMEM;

    err = map_frontend_page(blkif, (unsigned long)vma->addr, shared_page);
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

static void free_blkif(void *arg)
{
    evtchn_op_t op = { .cmd = EVTCHNOP_close };
    blkif_t *blkif = (blkif_t *)arg;

    op.u.close.port = blkif->evtchn;
    op.u.close.dom = DOMID_SELF;
    HYPERVISOR_event_channel_op(&op);
    op.u.close.port = blkif->remote_evtchn;
    op.u.close.dom = blkif->domid;
    HYPERVISOR_event_channel_op(&op);

    if (blkif->evtchn)
        unbind_evtchn_from_irqhandler(blkif->evtchn, blkif);

    if (blkif->blk_ring.sring) {
	unmap_frontend_page(blkif);
	vfree(blkif->blk_ring.sring);
	blkif->blk_ring.sring = NULL;
    }

    kmem_cache_free(blkif_cachep, blkif);
}

void free_blkif_callback(blkif_t *blkif)
{
    INIT_WORK(&blkif->free_work, free_blkif, (void *)blkif);
    schedule_work(&blkif->free_work);
}

void __init blkif_interface_init(void)
{
    blkif_cachep = kmem_cache_create("blkif_cache", sizeof(blkif_t), 
                                     0, 0, NULL, NULL);
}
