/******************************************************************************
 * arch/xen/drivers/vblkif/backend/interface.c
 * 
 * Block-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d,_h) \
    (((int)(_d)^(int)((_d)>>32)^(int)(_h))&(BLKIF_HASHSZ-1))

static blkif_t *blkif_hash[BLKIF_HASHSZ];

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle)
{
    blkif_t *blkif = blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif != NULL) && 
            (blkif->domid != domid) && 
            (blkif->handle != handle) )
        blkif = blkif->hash_next;
    return blkif;
}

void blkif_create(blkif_create_t *create)
{
    domid_t       domid  = create->domid;
    unsigned int  handle = create->blkif_handle;
    unsigned int  evtchn = create->evtchn;
    unsigned long shmem_frame = create->shmem_frame;
    blkif_t     **pblkif, *blkif;

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif == NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
            goto found_match;
        pblkif = &(*pblkif)->hash_next;
    }

    blkif = kmem_cache_alloc(blkif_cachep, GFP_KERNEL);
    memset(blkif, 0, sizeof(*blkif));
    blkif->domid       = domid;
    blkif->handle      = handle;
    blkif->evtchn      = evtchn;
    blkif->irq         = bind_evtchn_to_irq(evtchn);
    blkif->shmem_frame = shmem_frame;
    blkif->shmem_vbase = ioremap(shmem_frame<<PAGE_SHIFT, PAGE_SIZE);
    spin_lock_init(&blkif->vbd_lock);
    spin_lock_init(&blkif->blk_ring_lock);

    request_irq(irq, vblkif_be_int, 0, "vblkif-backend", blkif);

    blkif->hash_next = *pblkif;
    *pblkif = blkif;

    create->status = BLKIF_STATUS_OKAY;
    return;

 found_match:
    create->status = BLKIF_STATUS_INTERFACE_EXISTS;
    return;

 evtchn_in_use:
    unbind_evtchn_from_irq(evtchn); /* drop refcnt */
    create->status = BLKIF_STATUS_ERROR;
    return;
}

void blkif_destroy(blkif_destroy_t *destroy)
{
    domid_t       domid  = destroy->domid;
    unsigned int  handle = destroy->blkif_handle;
    blkif_t     **pblkif, *blkif;

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif = *pblkif) == NULL )
    {
        if ( (blkif->domid == domid) && (blkif->handle == handle) )
            goto found_match;
        pblkif = &blkif->hash_next;
    }

    destroy->status = BLKIF_STATUS_INTERFACE_NOT_FOUND;
    return;

 found_match:
    free_irq(blkif->irq, NULL);
    unbind_evtchn_from_irq(blkif->evtchn);
    *pblkif = blkif->hash_next;
    kmem_cache_free(blkif_cachep, blkif);
    destroy->status = BLKIF_STATUS_OKAY;
}

