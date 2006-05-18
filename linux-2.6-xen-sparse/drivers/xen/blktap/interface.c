/******************************************************************************
 * arch/xen/drivers/blkif/backend/interface.c
 * 
 * Block-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"
#include <xen/evtchn.h>

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
	int ret;

	gnttab_set_map_op(&op, (unsigned long)blkif->blk_ring_area->addr,
			  GNTMAP_host_map, shared_page, blkif->domid);

	lock_vm_area(blkif->blk_ring_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
	unlock_vm_area(blkif->blk_ring_area);
	BUG_ON(ret);

	if (op.status) {
		DPRINTK(" Grant table operation failure !\n");
		return op.status;
	}

	blkif->shmem_ref    = shared_page;
	blkif->shmem_handle = op.handle;

	return 0;
}

static void unmap_frontend_page(blkif_t *blkif)
{
	struct gnttab_unmap_grant_ref op;
	int ret;

	gnttab_set_unmap_op(&op, (unsigned long)blkif->blk_ring_area->addr,
			    GNTMAP_host_map, blkif->shmem_handle);

	lock_vm_area(blkif->blk_ring_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
	unlock_vm_area(blkif->blk_ring_area);
	BUG_ON(ret);
}

int blkif_map(blkif_t *blkif, unsigned long shared_page, unsigned int evtchn)
{
	blkif_sring_t *sring;
	int err;
	struct evtchn_bind_interdomain bind_interdomain;

	if ((blkif->blk_ring_area = alloc_vm_area(PAGE_SIZE)) == NULL)
		return -ENOMEM;

	err = map_frontend_page(blkif, shared_page);
	if (err) {
		free_vm_area(blkif->blk_ring_area);
		return err;
	}

	bind_interdomain.remote_dom  = blkif->domid;
	bind_interdomain.remote_port = evtchn;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain,
					  &bind_interdomain);
	if (err) {
		unmap_frontend_page(blkif);
		free_vm_area(blkif->blk_ring_area);
		return err;
	}

	blkif->evtchn = bind_interdomain.local_port;

	sring = (blkif_sring_t *)blkif->blk_ring_area->addr;
	BACK_RING_INIT(&blkif->blk_ring, sring, PAGE_SIZE);

	blkif->irq = bind_evtchn_to_irqhandler(
		blkif->evtchn, blkif_be_int, 0, "blkif-backend", blkif);

	blkif->status = CONNECTED;

	return 0;
}

static void free_blkif(void *arg)
{
	blkif_t *blkif = (blkif_t *)arg;

	if (blkif->irq)
		unbind_from_irqhandler(blkif->irq, blkif);

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
	blkif_cachep = kmem_cache_create(
		"blkif_cache", sizeof(blkif_t), 0, 0, NULL, NULL);
}
