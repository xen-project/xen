/******************************************************************************
 * arch/xen/drivers/blkif/backend/interface.c
 * 
 * Block-device interface management.
 * 
 * Copyright (c) 2004, Keir Fraser
 */

#include "common.h"

#define BLKIF_HASHSZ 1024
#define BLKIF_HASH(_d,_h) \
    (((int)(_d)^(int)((_d)>>32)^(int)(_h))&(BLKIF_HASHSZ-1))

static kmem_cache_t *blkif_cachep;
static blkif_t      *blkif_hash[BLKIF_HASHSZ];
static spinlock_t    blkif_hash_lock;

blkif_t *blkif_find_by_handle(domid_t domid, unsigned int handle)
{
    blkif_t      *blkif;
    unsigned long flags;
    
    spin_lock_irqsave(&blkif_hash_lock, flags);
    blkif = blkif_hash[BLKIF_HASH(domid, handle)];
    while ( blkif != NULL )
    {
        if ( (blkif->domid == domid) && (blkif->handle == handle) )
        {
            blkif_get(blkif);
            break;
        }
        blkif = blkif->hash_next;
    }
    spin_unlock_irqrestore(&blkif_hash_lock, flags);

    return blkif;
}

void __blkif_destroy(blkif_t *blkif)
{
    free_irq(blkif->irq, NULL);
    unbind_evtchn_from_irq(blkif->evtchn);
    vfree(blkif->blk_ring_base);
    destroy_all_vbds(blkif);
    kmem_cache_free(blkif_cachep, blkif);    
}

void blkif_create(blkif_be_create_t *create)
{
    domid_t       domid  = create->domid;
    unsigned int  handle = create->blkif_handle;
    unsigned int  evtchn = create->evtchn;
    unsigned long shmem_frame = create->shmem_frame;
    unsigned long flags;
    blkif_t     **pblkif, *blkif;
    struct vm_struct *vma;
    pgprot_t      prot;
    int           error;

    if ( (vma = get_vm_area(PAGE_SIZE, VM_IOREMAP)) == NULL )
    {
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    if ( (blkif = kmem_cache_alloc(blkif_cachep, GFP_KERNEL)) == NULL )
    {
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        goto fail1;
    }

    prot = __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED);
    error = direct_remap_area_pages(&init_mm, VMALLOC_VMADDR(vma->addr),
                                    shmem_frame<<PAGE_SHIFT, PAGE_SIZE,
                                    prot, domid);
    if ( error != 0 )
    {
        if ( error == -ENOMEM )
            create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        else if ( error == -EFAULT )
            create->status = BLKIF_BE_STATUS_MAPPING_ERROR;
        else
            create->status = BLKIF_BE_STATUS_ERROR;
        goto fail2;
    }

    memset(blkif, 0, sizeof(*blkif));
    blkif->domid         = domid;
    blkif->handle        = handle;
    blkif->evtchn        = evtchn;
    blkif->irq           = bind_evtchn_to_irq(evtchn);
    blkif->shmem_frame   = shmem_frame;
    blkif->blk_ring_base = (blkif_ring_t *)vma->addr;
    spin_lock_init(&blkif->vbd_lock);
    spin_lock_init(&blkif->blk_ring_lock);

    spin_lock_irqsave(&blkif_hash_lock, flags);

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( *pblkif == NULL )
    {
        if ( ((*pblkif)->domid == domid) && ((*pblkif)->handle == handle) )
        {
            spin_unlock_irqrestore(&blkif_hash_lock, flags);
            create->status = BLKIF_BE_STATUS_INTERFACE_EXISTS;
            goto fail3;
        }
        pblkif = &(*pblkif)->hash_next;
    }

    atomic_set(&blkif->refcnt, 1);
    blkif->hash_next = *pblkif;
    *pblkif = blkif;

    spin_unlock_irqrestore(&blkif_hash_lock, flags);

    request_irq(blkif->irq, blkif_be_int, 0, "blkif-backend", blkif);

    create->status = BLKIF_BE_STATUS_OKAY;
    return;

 fail3: unbind_evtchn_from_irq(evtchn);
 fail2: kmem_cache_free(blkif_cachep, blkif);
 fail1: vfree(vma->addr);
}

void blkif_destroy(blkif_be_destroy_t *destroy)
{
    domid_t       domid  = destroy->domid;
    unsigned int  handle = destroy->blkif_handle;
    unsigned long flags;
    blkif_t     **pblkif, *blkif;

    spin_lock_irqsave(&blkif_hash_lock, flags);

    pblkif = &blkif_hash[BLKIF_HASH(domid, handle)];
    while ( (blkif = *pblkif) == NULL )
    {
        if ( (blkif->domid == domid) && (blkif->handle == handle) )
        {
            *pblkif = blkif->hash_next;
            spin_unlock_irqrestore(&blkif_hash_lock, flags);
            blkif_deschedule(blkif);
            blkif_put(blkif);
            destroy->status = BLKIF_BE_STATUS_OKAY;
            return;
        }
        pblkif = &blkif->hash_next;
    }

    spin_unlock_irqrestore(&blkif_hash_lock, flags);

    destroy->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
}

void __init blkif_interface_init(void)
{
    blkif_cachep = kmem_cache_create("blkif_cache", sizeof(blkif_t), 
                                     0, 0, NULL, NULL);
    memset(blkif_hash, 0, sizeof(blkif_hash));
    spin_lock_init(&blkif_hash_lock);
}
