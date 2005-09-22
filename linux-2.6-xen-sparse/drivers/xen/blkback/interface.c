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

static int map_frontend_page(blkif_t *blkif, unsigned long shared_page)
{
	struct gnttab_map_grant_ref op;

	op.host_addr = (unsigned long)blkif->blk_ring_area->addr;
	op.flags     = GNTMAP_host_map;
	op.ref       = shared_page;
	op.dom       = blkif->domid;

	lock_vm_area(blkif->blk_ring_area);
	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1));
	unlock_vm_area(blkif->blk_ring_area);

	if (op.handle < 0) {
		DPRINTK(" Grant table operation failure !\n");
		return op.handle;
	}

	blkif->shmem_ref = shared_page;
	blkif->shmem_handle = op.handle;

	return 0;
}

static void unmap_frontend_page(blkif_t *blkif)
{
	struct gnttab_unmap_grant_ref op;

	op.host_addr    = (unsigned long)blkif->blk_ring_area->addr;
	op.handle       = blkif->shmem_handle;
	op.dev_bus_addr = 0;

	lock_vm_area(blkif->blk_ring_area);
	BUG_ON(HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1));
	unlock_vm_area(blkif->blk_ring_area);
}

int blkif_map(blkif_t *blkif, unsigned long shared_page, unsigned int evtchn)
{
	blkif_sring_t *sring;
	evtchn_op_t op = { .cmd = EVTCHNOP_bind_interdomain };
	int err;

	BUG_ON(blkif->remote_evtchn);

	if ( (blkif->blk_ring_area = alloc_vm_area(PAGE_SIZE)) == NULL )
		return -ENOMEM;

	err = map_frontend_page(blkif, shared_page);
	if (err) {
		free_vm_area(blkif->blk_ring_area);
		return err;
	}

	op.u.bind_interdomain.dom1 = DOMID_SELF;
	op.u.bind_interdomain.dom2 = blkif->domid;
	op.u.bind_interdomain.port1 = 0;
	op.u.bind_interdomain.port2 = evtchn;
	err = HYPERVISOR_event_channel_op(&op);
	if (err) {
		unmap_frontend_page(blkif);
		free_vm_area(blkif->blk_ring_area);
		return err;
	}

	blkif->evtchn = op.u.bind_interdomain.port1;
	blkif->remote_evtchn = evtchn;

	sring = (blkif_sring_t *)blkif->blk_ring_area->addr;
	SHARED_RING_INIT(sring);
	BACK_RING_INIT(&blkif->blk_ring, sring, PAGE_SIZE);

	bind_evtchn_to_irqhandler(
		blkif->evtchn, blkif_be_int, 0, "blkif-backend", blkif);
	blkif->status = CONNECTED;

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

	vbd_free(&blkif->vbd);

	if (blkif->evtchn)
		unbind_evtchn_from_irqhandler(blkif->evtchn, blkif);

	if (blkif->blk_ring.sring) {
		unmap_frontend_page(blkif);
		free_vm_area(blkif->blk_ring_area);
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

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
