/******************************************************************************
 * blkback/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * Copyright (c) 2003-2005, Keir Fraser & Steve Hand
 */

#include "common.h"
#include <asm-xen/xenbus.h>

static inline dev_t vbd_map_devnum(blkif_pdev_t cookie)
{
    return MKDEV(BLKIF_MAJOR(cookie), BLKIF_MINOR(cookie));
}
#define vbd_sz(_v)   ((_v)->bdev->bd_part ? \
    (_v)->bdev->bd_part->nr_sects : (_v)->bdev->bd_disk->capacity)
#define bdev_put(_b) blkdev_put(_b)

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

int vbd_create(blkif_t *blkif, blkif_vdev_t handle,
	       blkif_pdev_t pdevice, int readonly)
{
    struct vbd *vbd;

    vbd = &blkif->vbd;
    vbd->handle   = handle; 
    vbd->readonly = readonly;
    vbd->type     = 0;

    vbd->pdevice  = pdevice;

    vbd->bdev = open_by_devnum(
        vbd_map_devnum(vbd->pdevice),
        vbd->readonly ? FMODE_READ : FMODE_WRITE);
    if ( IS_ERR(vbd->bdev) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
        return -ENOENT;
    }

    if ( (vbd->bdev->bd_disk == NULL) )
    {
        DPRINTK("vbd_creat: device %08x doesn't exist.\n", vbd->pdevice);
	vbd_free(vbd);
        return -ENOENT;
    }

    if ( vbd->bdev->bd_disk->flags & GENHD_FL_CD )
        vbd->type |= VDISK_CDROM;
    if ( vbd->bdev->bd_disk->flags & GENHD_FL_REMOVABLE )
        vbd->type |= VDISK_REMOVABLE;

    DPRINTK("Successful creation of handle=%04x (dom=%u)\n",
            handle, blkif->domid);
    return 0;
}

void vbd_free(struct vbd *vbd)
{
    if (vbd->bdev)
	bdev_put(vbd->bdev);
    vbd->bdev = NULL;
}

int vbd_translate(struct phys_req *req, blkif_t *blkif, int operation)
{
    struct vbd *vbd = &blkif->vbd;
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
