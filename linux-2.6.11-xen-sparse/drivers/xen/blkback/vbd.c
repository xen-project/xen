/******************************************************************************
 * blkback/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * NOTE: vbd_lock protects updates to the rb_tree against concurrent lookups 
 * in vbd_translate.  All other lookups are implicitly protected because the 
 * only caller (the control message dispatch routine) serializes the calls.
 * 
 * Copyright (c) 2003-2005, Keir Fraser & Steve Hand
 */

#include "common.h"

struct vbd { 
    blkif_vdev_t   vdevice;     /* what the domain refers to this vbd as */
    unsigned char  readonly;    /* Non-zero -> read-only */
    unsigned char  type;        /* VDISK_TYPE_xxx */
    blkif_pdev_t   pdevice;     /* phys device that this vbd maps to */
    struct block_device *bdev;
    rb_node_t      rb;          /* for linking into R-B tree lookup struct */
}; 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static inline dev_t vbd_map_devnum(blkif_pdev_t cookie)
{ return MKDEV(cookie>>8, cookie&0xff); }
#define vbd_sz(_v)   ((_v)->bdev->bd_part ? \
    (_v)->bdev->bd_part->nr_sects : (_v)->bdev->bd_disk->capacity)
#define bdev_put(_b) blkdev_put(_b)
#else
#define vbd_sz(_v)   (blk_size[MAJOR((_v)->pdevice)][MINOR((_v)->pdevice)]*2)
#define bdev_put(_b) ((void)0)
#endif

void vbd_create(blkif_be_vbd_create_t *create) 
{
    struct vbd  *vbd; 
    rb_node_t  **rb_p, *rb_parent = NULL;
    blkif_t     *blkif;
    blkif_vdev_t vdevice = create->vdevice;

    blkif = blkif_find_by_handle(create->domid, create->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_create attempted for non-existent blkif (%u,%u)\n", 
                create->domid, create->blkif_handle); 
        create->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    rb_p = &blkif->vbd_rb.rb_node;
    while ( *rb_p != NULL )
    {
        rb_parent = *rb_p;
        vbd = rb_entry(rb_parent, struct vbd, rb);
        if ( vdevice < vbd->vdevice )
        {
            rb_p = &rb_parent->rb_left;
        }
        else if ( vdevice > vbd->vdevice )
        {
            rb_p = &rb_parent->rb_right;
        }
        else
        {
            DPRINTK("vbd_create attempted for already existing vbd\n");
            create->status = BLKIF_BE_STATUS_VBD_EXISTS;
            return;
        }
    }

    if ( unlikely((vbd = kmalloc(sizeof(struct vbd), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_create: out of memory\n");
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    vbd->vdevice  = vdevice; 
    vbd->readonly = create->readonly;
    vbd->type     = VDISK_TYPE_DISK | VDISK_FLAG_VIRT;

    /* Mask to 16-bit for compatibility with old tools */
    vbd->pdevice  = create->pdevice & 0xffff;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    vbd->bdev = open_by_devnum(
        vbd_map_devnum(vbd->pdevice),
        vbd->readonly ? FMODE_READ : FMODE_WRITE);
    if ( IS_ERR(vbd->bdev) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        create->status = BLKIF_BE_STATUS_PHYSDEV_NOT_FOUND;
        return;
    }

    if ( (vbd->bdev->bd_disk == NULL) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        create->status = BLKIF_BE_STATUS_PHYSDEV_NOT_FOUND;
        bdev_put(vbd->bdev);
        return;
    }
#else
    if ( (blk_size[MAJOR(vbd->pdevice)] == NULL) || (vbd_sz(vbd) == 0) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        create->status = BLKIF_BE_STATUS_PHYSDEV_NOT_FOUND;
        return;
    }
#endif

    spin_lock(&blkif->vbd_lock);
    rb_link_node(&vbd->rb, rb_parent, rb_p);
    rb_insert_color(&vbd->rb, &blkif->vbd_rb);
    spin_unlock(&blkif->vbd_lock);

    DPRINTK("Successful creation of vdev=%04x (dom=%u)\n",
            vdevice, create->domid);
    create->status = BLKIF_BE_STATUS_OKAY;
}


void vbd_destroy(blkif_be_vbd_destroy_t *destroy) 
{
    blkif_t           *blkif;
    struct vbd        *vbd;
    rb_node_t         *rb;
    blkif_vdev_t       vdevice = destroy->vdevice;

    blkif = blkif_find_by_handle(destroy->domid, destroy->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_destroy attempted for non-existent blkif (%u,%u)\n", 
                destroy->domid, destroy->blkif_handle); 
        destroy->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    rb = blkif->vbd_rb.rb_node;
    while ( rb != NULL )
    {
        vbd = rb_entry(rb, struct vbd, rb);
        if ( vdevice < vbd->vdevice )
            rb = rb->rb_left;
        else if ( vdevice > vbd->vdevice )
            rb = rb->rb_right;
        else
            goto found;
    }

    destroy->status = BLKIF_BE_STATUS_VBD_NOT_FOUND;
    return;

 found:
    spin_lock(&blkif->vbd_lock);
    rb_erase(rb, &blkif->vbd_rb);
    spin_unlock(&blkif->vbd_lock);
    bdev_put(vbd->bdev);
    kfree(vbd);
}


void destroy_all_vbds(blkif_t *blkif)
{
    struct vbd *vbd;
    rb_node_t  *rb;

    spin_lock(&blkif->vbd_lock);

    while ( (rb = blkif->vbd_rb.rb_node) != NULL )
    {
        vbd = rb_entry(rb, struct vbd, rb);
        rb_erase(rb, &blkif->vbd_rb);
        spin_unlock(&blkif->vbd_lock);
        bdev_put(vbd->bdev);
        kfree(vbd);
        spin_lock(&blkif->vbd_lock);
    }

    spin_unlock(&blkif->vbd_lock);
}


static void vbd_probe_single(
    blkif_t *blkif, vdisk_t *vbd_info, struct vbd *vbd)
{
    vbd_info->device   = vbd->vdevice; 
    vbd_info->info     = vbd->type | (vbd->readonly ? VDISK_FLAG_RO : 0);
    vbd_info->capacity = vbd_sz(vbd);
}


int vbd_probe(blkif_t *blkif, vdisk_t *vbd_info, int max_vbds)
{
    int        rc = 0, nr_vbds = 0;
    rb_node_t *rb;

    spin_lock(&blkif->vbd_lock);

    if ( (rb = blkif->vbd_rb.rb_node) == NULL )
        goto out;

 new_subtree:
    /* STEP 1. Find least node (it'll be left-most). */
    while ( rb->rb_left != NULL )
        rb = rb->rb_left;

    for ( ; ; )
    {
        /* STEP 2. Dealt with left subtree. Now process current node. */
        vbd_probe_single(blkif, &vbd_info[nr_vbds],
                         rb_entry(rb, struct vbd, rb));
        if ( ++nr_vbds == max_vbds )
            goto out;

        /* STEP 3. Process right subtree, if any. */
        if ( rb->rb_right != NULL )
        {
            rb = rb->rb_right;
            goto new_subtree;
        }

        /* STEP 4. Done both subtrees. Head back through ancesstors. */
        for ( ; ; ) 
        {
            /* We're done when we get back to the root node. */
            if ( rb->rb_parent == NULL )
                goto out;
            /* If we are left of parent, then parent is next to process. */
            if ( rb->rb_parent->rb_left == rb )
                break;
            /* If we are right of parent, then we climb to grandparent. */
            rb = rb->rb_parent;
        }

        rb = rb->rb_parent;
    }

 out:
    spin_unlock(&blkif->vbd_lock);
    return (rc == 0) ? nr_vbds : rc;  
}


int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation)
{
    struct vbd *vbd;
    rb_node_t  *rb;
    int         rc = -EACCES;

    /* Take the vbd_lock because another thread could be updating the tree. */
    spin_lock(&blkif->vbd_lock);

    rb = blkif->vbd_rb.rb_node;
    while ( rb != NULL )
    {
        vbd = rb_entry(rb, struct vbd, rb);
        if ( req->dev < vbd->vdevice )
            rb = rb->rb_left;
        else if ( req->dev > vbd->vdevice )
            rb = rb->rb_right;
        else
            goto found;
    }

    DPRINTK("vbd_translate; domain %u attempted to access "
            "non-existent VBD.\n", blkif->domid);
    rc = -ENODEV;
    goto out;

 found:

    if ( (operation == WRITE) && vbd->readonly )
        goto out;

    if ( unlikely((req->sector_number + req->nr_sects) > vbd_sz(vbd)) )
        goto out;

    req->dev  = vbd->pdevice;
    req->bdev = vbd->bdev;
    rc = 0;

 out:
    spin_unlock(&blkif->vbd_lock);
    return rc;
}
