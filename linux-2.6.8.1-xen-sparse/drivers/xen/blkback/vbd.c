/******************************************************************************
 * blkback/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * NOTE: vbd_lock protects updates to the rb_tree against concurrent lookups 
 * in vbd_translate.  All other lookups are implicitly protected because the 
 * only caller (the control message dispatch routine) serializes the calls.
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 */

#include "common.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static dev_t vbd_map_devnum(blkif_pdev_t);
#endif

void vbd_create(blkif_be_vbd_create_t *create) 
{
    vbd_t       *vbd; 
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
        vbd = rb_entry(rb_parent, vbd_t, rb);
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

    if ( unlikely((vbd = kmalloc(sizeof(vbd_t), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_create: out of memory\n");
        create->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    vbd->vdevice  = vdevice; 
    vbd->readonly = create->readonly;
    vbd->type     = VDISK_TYPE_DISK | VDISK_FLAG_VIRT;
    vbd->extents  = NULL; 

    spin_lock(&blkif->vbd_lock);
    rb_link_node(&vbd->rb, rb_parent, rb_p);
    rb_insert_color(&vbd->rb, &blkif->vbd_rb);
    spin_unlock(&blkif->vbd_lock);

    DPRINTK("Successful creation of vdev=%04x (dom=%u)\n",
            vdevice, create->domid);
    create->status = BLKIF_BE_STATUS_OKAY;
}


/* Grow a VBD by appending a new extent. Fails if the VBD doesn't exist. */
void vbd_grow(blkif_be_vbd_grow_t *grow) 
{
    blkif_t            *blkif;
    blkif_extent_le_t **px, *x; 
    vbd_t              *vbd = NULL;
    rb_node_t          *rb;
    blkif_vdev_t        vdevice = grow->vdevice;
    unsigned long       sz;

    blkif = blkif_find_by_handle(grow->domid, grow->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_grow attempted for non-existent blkif (%u,%u)\n", 
                grow->domid, grow->blkif_handle); 
        grow->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    rb = blkif->vbd_rb.rb_node;
    while ( rb != NULL )
    {
        vbd = rb_entry(rb, vbd_t, rb);
        if ( vdevice < vbd->vdevice )
            rb = rb->rb_left;
        else if ( vdevice > vbd->vdevice )
            rb = rb->rb_right;
        else
            break;
    }

    if ( unlikely(vbd == NULL) || unlikely(vbd->vdevice != vdevice) )
    {
        DPRINTK("vbd_grow: attempted to append extent to non-existent VBD.\n");
        grow->status = BLKIF_BE_STATUS_VBD_NOT_FOUND;
        return;
    } 

    if ( grow->extent.sector_start > 0 )
    {
        DPRINTK("vbd_grow: dev %08x start not zero.\n", grow->extent.device);
        grow->status = BLKIF_BE_STATUS_EXTENT_NOT_FOUND;
        return;
    }

    if ( unlikely((x = kmalloc(sizeof(blkif_extent_le_t), 
                               GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_grow: out of memory\n");
        grow->status = BLKIF_BE_STATUS_OUT_OF_MEMORY;
        return;
    }

    x->extent.device        = grow->extent.device;
    x->extent.sector_start  = grow->extent.sector_start;
    x->extent.sector_length = grow->extent.sector_length;
    x->next                 = (blkif_extent_le_t *)NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    x->bdev = open_by_devnum(vbd_map_devnum(x->extent.device),
                             vbd->readonly ? FMODE_READ : FMODE_WRITE);
    if ( IS_ERR(x->bdev) )
    {
        DPRINTK("vbd_grow: device %08x doesn't exist.\n", x->extent.device);
        grow->status = BLKIF_BE_STATUS_EXTENT_NOT_FOUND;
        goto out;
    }
    /* XXXcl maybe bd_claim? */

    if ( (x->bdev->bd_disk == NULL) )
    {
        DPRINTK("vbd_grow: device %08x doesn't exist.\n", x->extent.device);
        grow->status = BLKIF_BE_STATUS_EXTENT_NOT_FOUND;
        blkdev_put(x->bdev);
        goto out;
    }

    /* get size in sectors */   
    if ( x->bdev->bd_part )
	 sz = x->bdev->bd_part->nr_sects;
    else
	 sz = x->bdev->bd_disk->capacity;

#else
    if( !blk_size[MAJOR(x->extent.device)] )
    {
        DPRINTK("vbd_grow: device %08x doesn't exist.\n", x->extent.device);
        grow->status = BLKIF_BE_STATUS_EXTENT_NOT_FOUND;
        goto out;
    }
    
    /* convert blocks (1KB) to sectors */
    sz = blk_size[MAJOR(x->extent.device)][MINOR(x->extent.device)] * 2;    
    
    if ( sz == 0 )
    {
        DPRINTK("vbd_grow: device %08x zero size!\n", x->extent.device);
        grow->status = BLKIF_BE_STATUS_EXTENT_NOT_FOUND;
        goto out;
    }
#endif

    /*
     * NB. This test assumes sector_start == 0, which is always the case
     * in Xen 1.3. In fact the whole grow/shrink interface could do with
     * some simplification.
     */
    if ( x->extent.sector_length > sz )
        x->extent.sector_length = sz;
    
    DPRINTK("vbd_grow: requested_len %llu actual_len %lu\n", 
            x->extent.sector_length, sz);

    for ( px = &vbd->extents; *px != NULL; px = &(*px)->next ) 
        continue;
    
    *px = x; /* ATOMIC: no need for vbd_lock. */

    DPRINTK("Successful grow of vdev=%04x (dom=%u)\n",
            vdevice, grow->domid);
    
    grow->status = BLKIF_BE_STATUS_OKAY;
    return;

 out:
    kfree(x);
}


void vbd_shrink(blkif_be_vbd_shrink_t *shrink)
{
    blkif_t            *blkif;
    blkif_extent_le_t **px, *x; 
    vbd_t              *vbd = NULL;
    rb_node_t          *rb;
    blkif_vdev_t        vdevice = shrink->vdevice;

    blkif = blkif_find_by_handle(shrink->domid, shrink->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_shrink attempted for non-existent blkif (%u,%u)\n", 
                shrink->domid, shrink->blkif_handle); 
        shrink->status = BLKIF_BE_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    rb = blkif->vbd_rb.rb_node;
    while ( rb != NULL )
    {
        vbd = rb_entry(rb, vbd_t, rb);
        if ( vdevice < vbd->vdevice )
            rb = rb->rb_left;
        else if ( vdevice > vbd->vdevice )
            rb = rb->rb_right;
        else
            break;
    }

    if ( unlikely(vbd == NULL) || unlikely(vbd->vdevice != vdevice) )
    {
        shrink->status = BLKIF_BE_STATUS_VBD_NOT_FOUND;
        return;
    }

    if ( unlikely(vbd->extents == NULL) )
    {
        shrink->status = BLKIF_BE_STATUS_EXTENT_NOT_FOUND;
        return;
    }

    /* Find the last extent. We now know that there is at least one. */
    for ( px = &vbd->extents; (*px)->next != NULL; px = &(*px)->next )
        continue;

    x   = *px;
    *px = x->next; /* ATOMIC: no need for vbd_lock. */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    blkdev_put(x->bdev);
#endif
    kfree(x);

    shrink->status = BLKIF_BE_STATUS_OKAY;
}


void vbd_destroy(blkif_be_vbd_destroy_t *destroy) 
{
    blkif_t           *blkif;
    vbd_t             *vbd;
    rb_node_t         *rb;
    blkif_extent_le_t *x, *t;
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
        vbd = rb_entry(rb, vbd_t, rb);
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

    x = vbd->extents;
    kfree(vbd);

    while ( x != NULL )
    {
        t = x->next;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        blkdev_put(x->bdev);
#endif
        kfree(x);
        x = t;
    }
}


void destroy_all_vbds(blkif_t *blkif)
{
    vbd_t             *vbd;
    rb_node_t         *rb;
    blkif_extent_le_t *x, *t;

    spin_lock(&blkif->vbd_lock);

    while ( (rb = blkif->vbd_rb.rb_node) != NULL )
    {
        vbd = rb_entry(rb, vbd_t, rb);

        rb_erase(rb, &blkif->vbd_rb);
        x = vbd->extents;
        kfree(vbd);
        
        while ( x != NULL )
        {
            t = x->next;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
            blkdev_put(x->bdev);
#endif
            kfree(x);
            x = t;
        }          
    }

    spin_unlock(&blkif->vbd_lock);
}


static int vbd_probe_single(blkif_t *blkif, vdisk_t *vbd_info, vbd_t *vbd)
{
    blkif_extent_le_t *x; 

    vbd_info->device = vbd->vdevice; 
    vbd_info->info   = vbd->type;
    if ( vbd->readonly )
        vbd_info->info |= VDISK_FLAG_RO; 
    vbd_info->capacity = 0ULL;
    for ( x = vbd->extents; x != NULL; x = x->next )
        vbd_info->capacity += x->extent.sector_length; 
        
    return 0;
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
        if ( (rc = vbd_probe_single(blkif, &vbd_info[nr_vbds], 
                                    rb_entry(rb, vbd_t, rb))) != 0 )
            goto out;
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


int vbd_translate(phys_seg_t *pseg, blkif_t *blkif, int operation)
{
    blkif_extent_le_t *x; 
    vbd_t             *vbd;
    rb_node_t         *rb;
    blkif_sector_t     sec_off;
    unsigned long      nr_secs;

    /* Take the vbd_lock because another thread could be updating the tree. */
    spin_lock(&blkif->vbd_lock);

    rb = blkif->vbd_rb.rb_node;
    while ( rb != NULL )
    {
        vbd = rb_entry(rb, vbd_t, rb);
        if ( pseg->dev < vbd->vdevice )
            rb = rb->rb_left;
        else if ( pseg->dev > vbd->vdevice )
            rb = rb->rb_right;
        else
            goto found;
    }

    DPRINTK("vbd_translate; domain %u attempted to access "
            "non-existent VBD.\n", blkif->domid);

    spin_unlock(&blkif->vbd_lock);
    return -ENODEV; 

 found:

    if ( (operation == WRITE) && vbd->readonly )
    {
        spin_unlock(&blkif->vbd_lock);
        return -EACCES; 
    }

    /*
     * Now iterate through the list of blkif_extents, working out which should 
     * be used to perform the translation.
     */
    sec_off = pseg->sector_number; 
    nr_secs = pseg->nr_sects;
    for ( x = vbd->extents; x != NULL; x = x->next )
    { 
        if ( sec_off < x->extent.sector_length )
        {
            pseg->dev  = x->extent.device;
            pseg->bdev = x->bdev;
            pseg->sector_number = x->extent.sector_start + sec_off;
            if ( unlikely((sec_off + nr_secs) > x->extent.sector_length) )
                goto overrun;
            spin_unlock(&blkif->vbd_lock);
            return 1;
        } 
        sec_off -= x->extent.sector_length; 
    }

    DPRINTK("vbd_translate: end of vbd.\n");
    spin_unlock(&blkif->vbd_lock);
    return -EACCES; 

    /*
     * Here we deal with overrun onto the following extent. We don't deal with 
     * overrun of more than one boundary since each request is restricted to 
     * 2^9 512-byte sectors, so it should be trivial for control software to 
     * ensure that extents are large enough to prevent excessive overrun.
     */
 overrun:

    /* Adjust length of first chunk to run to end of first extent. */
    pseg[0].nr_sects = x->extent.sector_length - sec_off;

    /* Set second chunk buffer and length to start where first chunk ended. */
    pseg[1].buffer   = pseg[0].buffer + (pseg[0].nr_sects << 9);
    pseg[1].nr_sects = nr_secs - pseg[0].nr_sects;

    /* Now move to the next extent. Check it exists and is long enough! */
    if ( unlikely((x = x->next) == NULL) || 
         unlikely(x->extent.sector_length < pseg[1].nr_sects) )
    {
        DPRINTK("vbd_translate: multiple overruns or end of vbd.\n");
        spin_unlock(&blkif->vbd_lock);
        return -EACCES;
    }

    /* Store the real device and start sector for the second chunk. */
    pseg[1].dev           = x->extent.device;
    pseg[1].bdev          = x->bdev;
    pseg[1].sector_number = x->extent.sector_start;
    
    spin_unlock(&blkif->vbd_lock);
    return 2;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#define MAJOR_XEN(dev) ((dev)>>8)
#define MINOR_XEN(dev) ((dev) & 0xff)

#ifndef FANCY_REMAPPING
static dev_t vbd_map_devnum(blkif_pdev_t cookie)
{
    int major = MAJOR_XEN(cookie);
    int minor = MINOR_XEN(cookie);

    return MKDEV(major, minor);
}
#else
#define XEN_IDE0_MAJOR IDE0_MAJOR
#define XEN_IDE1_MAJOR IDE1_MAJOR
#define XEN_IDE2_MAJOR IDE2_MAJOR
#define XEN_IDE3_MAJOR IDE3_MAJOR
#define XEN_IDE4_MAJOR IDE4_MAJOR
#define XEN_IDE5_MAJOR IDE5_MAJOR
#define XEN_IDE6_MAJOR IDE6_MAJOR
#define XEN_IDE7_MAJOR IDE7_MAJOR
#define XEN_IDE8_MAJOR IDE8_MAJOR
#define XEN_IDE9_MAJOR IDE9_MAJOR
#define XEN_SCSI_DISK0_MAJOR SCSI_DISK0_MAJOR
#define XEN_SCSI_DISK1_MAJOR SCSI_DISK1_MAJOR
#define XEN_SCSI_DISK2_MAJOR SCSI_DISK2_MAJOR
#define XEN_SCSI_DISK3_MAJOR SCSI_DISK3_MAJOR
#define XEN_SCSI_DISK4_MAJOR SCSI_DISK4_MAJOR
#define XEN_SCSI_DISK5_MAJOR SCSI_DISK5_MAJOR
#define XEN_SCSI_DISK6_MAJOR SCSI_DISK6_MAJOR
#define XEN_SCSI_DISK7_MAJOR SCSI_DISK7_MAJOR
#define XEN_SCSI_CDROM_MAJOR SCSI_CDROM_MAJOR

static dev_t vbd_map_devnum(blkif_pdev_t cookie)
{
    int new_major;
    int major = MAJOR_XEN(cookie);
    int minor = MINOR_XEN(cookie);

    switch (major) {
    case XEN_IDE0_MAJOR: new_major = IDE0_MAJOR; break;
    case XEN_IDE1_MAJOR: new_major = IDE1_MAJOR; break;
    case XEN_IDE2_MAJOR: new_major = IDE2_MAJOR; break;
    case XEN_IDE3_MAJOR: new_major = IDE3_MAJOR; break;
    case XEN_IDE4_MAJOR: new_major = IDE4_MAJOR; break;
    case XEN_IDE5_MAJOR: new_major = IDE5_MAJOR; break;
    case XEN_IDE6_MAJOR: new_major = IDE6_MAJOR; break;
    case XEN_IDE7_MAJOR: new_major = IDE7_MAJOR; break;
    case XEN_IDE8_MAJOR: new_major = IDE8_MAJOR; break;
    case XEN_IDE9_MAJOR: new_major = IDE9_MAJOR; break;
    case XEN_SCSI_DISK0_MAJOR: new_major = SCSI_DISK0_MAJOR; break;
    case XEN_SCSI_DISK1_MAJOR ... XEN_SCSI_DISK7_MAJOR:
        new_major = SCSI_DISK1_MAJOR + major - XEN_SCSI_DISK1_MAJOR;
        break;
    case XEN_SCSI_CDROM_MAJOR: new_major = SCSI_CDROM_MAJOR; break;
    default: new_major = 0; break;
    }

    return MKDEV(new_major, minor);
}
#endif

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION_CODE(2,6,0) */
