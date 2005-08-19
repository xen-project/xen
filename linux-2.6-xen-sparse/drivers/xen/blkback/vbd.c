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
#include <asm-xen/xenbus.h>

struct vbd { 
    blkif_vdev_t   handle;     /* what the domain refers to this vbd as */
    unsigned char  readonly;    /* Non-zero -> read-only */
    unsigned char  type;        /* VDISK_xxx */
    blkif_pdev_t   pdevice;     /* phys device that this vbd maps to */
    struct block_device *bdev;

    int active;
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
#define bdev_hardsect_size(_b) 512
#endif

unsigned long vbd_size(struct vbd *vbd)
{
	return vbd_sz(vbd);
}

unsigned int vbd_info(struct vbd *vbd)
{
	return vbd->type | (vbd->readonly?VDISK_READONLY:0);
}

unsigned long vbd_secsize(struct vbd *vbd)
{
	return bdev_hardsect_size(vbd->bdev);
}

int vbd_is_active(struct vbd *vbd)
{
	return vbd->active;
}

struct vbd *vbd_create(blkif_t *blkif, blkif_vdev_t handle,
		       blkif_pdev_t pdevice, int readonly)
{
    struct vbd  *vbd; 

    if ( unlikely((vbd = kmalloc(sizeof(struct vbd), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_create: out of memory\n");
	return ERR_PTR(-ENOMEM);
    }

    vbd->handle   = handle; 
    vbd->readonly = readonly;
    vbd->type     = 0;
    vbd->active   = 0;

    vbd->pdevice  = pdevice;

    /* FIXME: Who frees vbd on failure? --RR */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    vbd->bdev = open_by_devnum(
        vbd_map_devnum(vbd->pdevice),
        vbd->readonly ? FMODE_READ : FMODE_WRITE);
    if ( IS_ERR(vbd->bdev) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        return ERR_PTR(-ENOENT);
    }

    if ( (vbd->bdev->bd_disk == NULL) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        bdev_put(vbd->bdev);
        return ERR_PTR(-ENOENT);
    }

    if ( vbd->bdev->bd_disk->flags & GENHD_FL_CD )
        vbd->type |= VDISK_CDROM;
    if ( vbd->bdev->bd_disk->flags & GENHD_FL_REMOVABLE )
        vbd->type |= VDISK_REMOVABLE;

#else
    if ( (blk_size[MAJOR(vbd->pdevice)] == NULL) || (vbd_sz(vbd) == 0) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        return ERR_PTR(-ENOENT);
    }
#endif

    DPRINTK("Successful creation of handle=%04x (dom=%u)\n",
            handle, blkif->domid);
    return vbd;
}

void vbd_activate(blkif_t *blkif, struct vbd *vbd)
{
    rb_node_t  **rb_p, *rb_parent = NULL;
    struct vbd *i;
    BUG_ON(vbd_is_active(vbd));

    /* Find where to put it. */
    rb_p = &blkif->vbd_rb.rb_node;
    while ( *rb_p != NULL )
    {
        rb_parent = *rb_p;
        i = rb_entry(rb_parent, struct vbd, rb);
        if ( vbd->handle < i->handle )
        {
            rb_p = &rb_parent->rb_left;
        }
        else if ( vbd->handle > i->handle )
        {
            rb_p = &rb_parent->rb_right;
        }
        else
        {
	    /* We never create two of same vbd, so not possible. */
	    BUG();
        }
    }

    /* Now we're active. */
    vbd->active = 1;
    blkif_get(blkif);

    spin_lock(&blkif->vbd_lock);
    rb_link_node(&vbd->rb, rb_parent, rb_p);
    rb_insert_color(&vbd->rb, &blkif->vbd_rb);
    spin_unlock(&blkif->vbd_lock);
}

void vbd_free(blkif_t *blkif, struct vbd *vbd)
{
    if (vbd_is_active(vbd)) {
	spin_lock(&blkif->vbd_lock);
	rb_erase(&vbd->rb, &blkif->vbd_rb);
	spin_unlock(&blkif->vbd_lock);
	blkif_put(blkif);
    }
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
        blkif_put(blkif);
    }

    spin_unlock(&blkif->vbd_lock);
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
        if ( req->dev < vbd->handle )
            rb = rb->rb_left;
        else if ( req->dev > vbd->handle )
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
