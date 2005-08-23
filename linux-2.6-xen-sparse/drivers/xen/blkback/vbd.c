/******************************************************************************
 * blkback/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * Copyright (c) 2003-2005, Keir Fraser & Steve Hand
 */

#include "common.h"
#include <asm-xen/xenbus.h>

struct vbd {
    blkif_vdev_t   handle;      /* what the domain refers to this vbd as */
    unsigned char  readonly;    /* Non-zero -> read-only */
    unsigned char  type;        /* VDISK_xxx */
    blkif_pdev_t   pdevice;     /* phys device that this vbd maps to */
    struct block_device *bdev;

    int active;
}; 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static inline dev_t vbd_map_devnum(blkif_pdev_t cookie)
{
    return MKDEV(BLKIF_MAJOR(cookie), BLKIF_MINOR(cookie));
}
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
    struct vbd *vbd, *err; 

    if ( unlikely((vbd = kmalloc(sizeof(struct vbd), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_create: out of memory\n");
	return ERR_PTR(-ENOMEM);
    }

    blkif->vbd = vbd;
    vbd->handle   = handle; 
    vbd->readonly = readonly;
    vbd->type     = 0;
    vbd->active   = 0;

    vbd->pdevice  = pdevice;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    vbd->bdev = open_by_devnum(
        vbd_map_devnum(vbd->pdevice),
        vbd->readonly ? FMODE_READ : FMODE_WRITE);
    if ( IS_ERR(vbd->bdev) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        err = ERR_PTR(-ENOENT);
	goto out;
    }

    if ( (vbd->bdev->bd_disk == NULL) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        bdev_put(vbd->bdev);
        err = ERR_PTR(-ENOENT);
	goto out;
    }

    if ( vbd->bdev->bd_disk->flags & GENHD_FL_CD )
        vbd->type |= VDISK_CDROM;
    if ( vbd->bdev->bd_disk->flags & GENHD_FL_REMOVABLE )
        vbd->type |= VDISK_REMOVABLE;
#else
    if ( (blk_size[MAJOR(vbd->pdevice)] == NULL) || (vbd_sz(vbd) == 0) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        err = ERR_PTR(-ENOENT);
	goto out;
    }
#endif

    DPRINTK("Successful creation of handle=%04x (dom=%u)\n",
            handle, blkif->domid);
    return vbd;

 out:
    kfree(vbd);
    return err;
}

void vbd_activate(blkif_t *blkif, struct vbd *vbd)
{
    BUG_ON(vbd_is_active(vbd));

    /* Now we're active. */
    vbd->active = 1;
    blkif_get(blkif);
}

void vbd_free(blkif_t *blkif, struct vbd *vbd)
{
    if (vbd_is_active(vbd)) {
	blkif_put(blkif);
    }
    bdev_put(vbd->bdev);
    kfree(vbd);
}

int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation)
{
    struct vbd *vbd = blkif->vbd;
    int rc = -EACCES;

    if ((operation == WRITE) && vbd->readonly)
        goto out;

    if (unlikely((req->sector_number + req->nr_sects) > vbd_sz(vbd)))
        goto out;

    req->dev  = vbd->pdevice;
    req->bdev = vbd->bdev;
    rc = 0;

 out:
    return rc;
}
