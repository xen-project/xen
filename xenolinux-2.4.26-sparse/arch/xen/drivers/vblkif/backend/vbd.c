/******************************************************************************
 * arch/xen/drivers/vblkif/backend/vbd.c
 * 
 * Routines for managing virtual block devices (VBDs).
 * 
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 */

#include "common.h"

void vbd_create(blkif_vbd_create_t *create) 
{
    vbd_t       *vbd; 
    rb_node_t  **rb_p, *rb_parent = NULL;
    blkif_t     *blkif;
    blkif_vdev_t vdevice = create->vdevice;

    blkif = blkif_find_by_handle(create->domid, create->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_create attempted for non-existent blkif (%llu,&u)\n", 
                create->domid, create->blkif_handle); 
        create->status = BLKIF_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    spin_lock(&blkif->vbd_lock);

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
            create->status = BLKIF_STATUS_VBD_EXISTS;
            goto out;
        }
    }

    if ( unlikely((vbd = kmalloc(sizeof(vbd_t), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_create: out of memory\n");
        create->status = BLKIF_STATUS_OUT_OF_MEMORY;
        goto out;
    }

    vbd->vdevice = vdevice; 
    vbd->mode    = create->mode; 
    vbd->type    = VDISK_TYPE_DISK | VDISK_FLAG_VIRT;
    vbd->extents = NULL; 

    rb_link_node(&vbd->rb, rb_parent, rb_p);
    rb_insert_color(&vbd->rb, &blkif->vbd_rb);

    create->status = BLKIF_STATUS_OKAY;

 out:
    spin_unlock(&blkif->vbd_lock);
    blkif_put(blkif);
}


/* Grow a VBD by appending a new extent. Fails if the VBD doesn't exist. */
void vbd_grow(blkif_vbd_grow_t *grow) 
{
    blkif_t          *blkif;
    xen_extent_le_t **px, *x; 
    vbd_t            *vbd = NULL;
    rb_node_t        *rb;
    blkif_vdev_t      vdevice = grow->vdevice;

    blkif = blkif_find_by_handle(grow->domid, grow->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_grow attempted for non-existent blkif (%llu,&u)\n", 
                grow->domid, grow->blkif_handle); 
        grow->status = BLKIF_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    spin_lock(&blkif->vbd_lock);

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
        grow->status = BLKIF_STATUS_VBD_NOT_FOUND;
        goto out;
    } 

    if ( unlikely((x = kmalloc(sizeof(xen_extent_le_t), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_grow: out of memory\n");
        grow->status = BLKIF_STATUS_OUT_OF_MEMORY;
        goto out;
    }
 
    x->extent.device        = grow->extent.device; 
    x->extent.sector_start  = grow->extent.sector_start; 
    x->extent.sector_length = grow->extent.sector_length; 
    x->next                 = (xen_extent_le_t *)NULL; 

    for ( px = &vbd->extents; *px != NULL; px = &(*px)->next ) 
        continue;

    *px = x;

    grow->status = BLKIF_STATUS_OKAY;

 out:
    spin_unlock(&blkif->vbd_lock);
    blkif_put(blkif);
}


void vbd_shrink(blkif_vbd_shrink_t *shrink)
{
    blkif_t          *blkif;
    xen_extent_le_t **px, *x; 
    vbd_t            *vbd = NULL;
    rb_node_t        *rb;
    blkif_vdev_t      vdevice = shrink->vdevice;

    blkif = blkif_find_by_handle(shrink->domid, shrink->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_shrink attempted for non-existent blkif (%llu,&u)\n", 
                shrink->domid, shrink->blkif_handle); 
        shrink->status = BLKIF_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    spin_lock(&blkif->vbd_lock);

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
        shrink->status = BLKIF_STATUS_VBD_NOT_FOUND;
        goto out;
    }

    if ( unlikely(vbd->extents == NULL) )
    {
        shrink->status = BLKIF_STATUS_EXTENT_NOT_FOUND;
        goto out;
    }

    /* Find the last extent. We now know that there is at least one. */
    for ( px = &vbd->extents; (*px)->next != NULL; px = &(*px)->next )
        continue;

    x   = *px;
    *px = x->next;
    kfree(x);

    shrink->status = BLKIF_STATUS_OKAY;

 out:
    spin_unlock(&blkif->vbd_lock);
    blkif_put(blkif);
}


void vbd_destroy(blkif_vbd_destroy_t *destroy) 
{
    blkif_t         *blkif;
    vbd_t           *vbd;
    rb_node_t       *rb;
    xen_extent_le_t *x, *t;
    blkif_vdev_t     vdevice = destroy->vdevice;

    blkif = blkif_find_by_handle(destroy->domid, destroy->blkif_handle);
    if ( unlikely(blkif == NULL) )
    {
        DPRINTK("vbd_destroy attempted for non-existent blkif (%llu,&u)\n", 
                destroy->domid, destroy->blkif_handle); 
        destroy->status = BLKIF_STATUS_INTERFACE_NOT_FOUND;
        return;
    }

    spin_lock(&blkif->vbd_lock);

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

    destroy->status = BLKIF_STATUS_VBD_NOT_FOUND;
    goto out;

 found:
    rb_erase(rb, &blkif->vbd_rb);
    x = vbd->extents;
    kfree(vbd);

    while ( x != NULL )
    {
        t = x->next;
        kfree(x);
        x = t;
    }
    
 out:
    spin_unlock(&blkif->vbd_lock);
    blkif_put(blkif);
}


void destroy_all_vbds(blkif_t *blkif)
{
    vbd_t *vbd;
    rb_node_t *rb;
    xen_extent_le_t *x, *t;

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
            kfree(x);
            x = t;
        }          
    }

    spin_unlock(&blkif->vbd_lock);
}


static int vbd_probe_single(xen_disk_info_t *xdi, 
                            vbd_t *vbd, 
                            struct task_struct *p)
{
    xen_extent_le_t *x; 
    xen_disk_t cur_disk; 

    if ( xdi->count == xdi->max )
    {
        DPRINTK("vbd_probe_devices: out of space for probe.\n"); 
        return -ENOMEM; 
    }

    cur_disk.device = vbd->vdevice; 
    cur_disk.info   = vbd->type;
    if ( !VBD_CAN_WRITE(vbd) )
        cur_disk.info |= XD_FLAG_RO; 
    cur_disk.capacity = 0ULL;
    for ( x = vbd->extents; x != NULL; x = x->next )
        cur_disk.capacity += x->extent.nr_sectors; 
    cur_disk.domain = p->domain; 
        
    /* Now copy into relevant part of user-space buffer */
    if( copy_to_user(&xdi->disks[xdi->count], 
                     &cur_disk, 
                     sizeof(xen_disk_t)) )
    { 
        DPRINTK("vbd_probe_devices: copy_to_user failed\n");
        return -EFAULT;
    } 
        
    xdi->count++; 

    return 0;
}


static int vbd_probe_devices(xen_disk_info_t *xdi, struct task_struct *p)
{
    int rc = 0;
    rb_node_t *rb;

    spin_lock(&p->vbd_lock);

    if ( (rb = p->vbd_rb.rb_node) == NULL )
        goto out;

 new_subtree:
    /* STEP 1. Find least node (it'll be left-most). */
    while ( rb->rb_left != NULL )
        rb = rb->rb_left;

    for ( ; ; )
    {
        /* STEP 2. Dealt with left subtree. Now process current node. */
        if ( (rc = vbd_probe_single(xdi, rb_entry(rb, vbd_t, rb), p)) != 0 )
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
    spin_unlock(&p->vbd_lock);
    return rc;  
}


/*
 * Return information about the VBDs available for a given domain, or for all 
 * domains; in the general case the 'domain' argument will be 0 which means 
 * "information about the caller"; otherwise the 'domain' argument will 
 * specify either a given domain, or all domains ("VBD_PROBE_ALL") -- both of 
 * these cases require the caller to be privileged.
 */
long vbd_probe(vbd_probe_t *probe) 
{
    struct task_struct *p = NULL; 
    unsigned long flags;
    long ret = 0;  

    if ( probe->domain != 0 )
    { 
        /* We can only probe for ourselves (unless we're privileged). */
        if( (probe->domain != current->domain) && !IS_PRIV(current) )
            return -EPERM; 

        if ( (probe->domain != VBD_PROBE_ALL) &&
             ((p = find_domain_by_id(probe->domain)) == NULL) )
        {
            DPRINTK("vbd_probe attempted for non-existent domain %llu\n", 
                    probe->domain); 
            return -EINVAL; 
        }
    }
    else
    { 
        /* Default is to probe for ourselves. */
        p = current; 
        get_task_struct(p); /* to mirror final put_task_struct */
    }

    if ( probe->domain == VBD_PROBE_ALL )
    { 
        read_lock_irqsave(&tasklist_lock, flags);
        for_each_domain ( p )
        {
            if ( (ret = vbd_probe_devices(&probe->xdi, p)) != 0 )
            { 
                read_unlock_irqrestore(&tasklist_lock, flags);
                goto out; 
            }
        }
        read_unlock_irqrestore(&tasklist_lock, flags);
    } 
    else if ( (ret = vbd_probe_devices(&probe->xdi, p)) != 0 )
        goto out; 

 out: 
    if ( ret != 0 )
        DPRINTK("vbd_probe: err %ld in probing virtual devices\n", ret); 
    if ( p != NULL )
        put_task_struct(p); 
    return ret; 
}


long vbd_info(vbd_info_t *info) 
{
    struct task_struct *p; 
    xen_extent_le_t *x; 
    xen_extent_t *extents; 
    vbd_t *vbd = NULL;
    rb_node_t *rb;
    long ret = 0;  
   
    if ( (info->domain != current->domain) && !IS_PRIV(current) )
        return -EPERM; 

    if ( (p = find_domain_by_id(info->domain)) == NULL )
    {
        DPRINTK("vbd_info attempted for non-existent domain %llu\n", 
                info->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    rb = p->vbd_rb.rb_node;
    while ( rb != NULL )
    {
        vbd = rb_entry(rb, vbd_t, rb);
        if ( info->vdevice < vbd->vdevice )
            rb = rb->rb_left;
        else if ( info->vdevice > vbd->vdevice )
            rb = rb->rb_right;
        else
            break;
    }

    if ( unlikely(vbd == NULL) || unlikely(vbd->vdevice != info->vdevice) )
    {
        DPRINTK("vbd_info attempted on non-existent VBD.\n"); 
        ret = -EINVAL; 
        goto out; 
    }

    info->mode     = vbd->mode;
    info->nextents = 0; 

    extents = info->extents;
    for ( x = vbd->extents; x != NULL; x = x->next )
    {
        if ( info->nextents == info->maxextents )
            break;
        if ( copy_to_user(extents, &x->extent, sizeof(xen_extent_t)) )
        {
            DPRINTK("vbd_info: copy_to_user failed\n");
            ret = -EFAULT;
            goto out; 
        } 
        extents++;
        info->nextents++;
    }

 out: 
    spin_unlock(&p->vbd_lock);
    put_task_struct(p); 
    return ret; 
}


int vbd_translate(phys_seg_t *pseg, struct task_struct *p, int operation)
{
    xen_extent_le_t *x; 
    vbd_t *vbd;
    rb_node_t *rb;
    xen_sector_t sec_off;
    unsigned long nr_secs;

    spin_lock(&p->vbd_lock);

    rb = p->vbd_rb.rb_node;
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

    DPRINTK("vbd_translate; domain %llu attempted to access "
            "non-existent VBD.\n", p->domain); 

    spin_unlock(&p->vbd_lock);
    return -ENODEV; 

 found:

    if ( ((operation == READ) && !VBD_CAN_READ(vbd)) ||
         ((operation == WRITE) && !VBD_CAN_WRITE(vbd)) )
    {
        spin_unlock(&p->vbd_lock);
        return -EACCES; 
    }

    /*
     * Now iterate through the list of xen_extents, working out which should 
     * be used to perform the translation.
     */
    sec_off = pseg->sector_number; 
    nr_secs = pseg->nr_sects;
    for ( x = vbd->extents; x != NULL; x = x->next )
    { 
        if ( sec_off < x->extent.nr_sectors )
        {
            pseg->dev = x->extent.device; 
            pseg->sector_number = x->extent.start_sector + sec_off;
            if ( unlikely((sec_off + nr_secs) > x->extent.nr_sectors) )
                goto overrun;
            spin_unlock(&p->vbd_lock);
            return 1;
        } 
        sec_off -= x->extent.nr_sectors; 
    }

    DPRINTK("vbd_translate: end of vbd.\n");
    spin_unlock(&p->vbd_lock);
    return -EACCES; 

    /*
     * Here we deal with overrun onto the following extent. We don't deal with 
     * overrun of more than one boundary since each request is restricted to 
     * 2^9 512-byte sectors, so it should be trivial for control software to 
     * ensure that extents are large enough to prevent excessive overrun.
     */
 overrun:

    /* Adjust length of first chunk to run to end of first extent. */
    pseg[0].nr_sects = x->extent.nr_sectors - sec_off;

    /* Set second chunk buffer and length to start where first chunk ended. */
    pseg[1].buffer   = pseg[0].buffer + (pseg[0].nr_sects << 9);
    pseg[1].nr_sects = nr_secs - pseg[0].nr_sects;

    /* Now move to the next extent. Check it exists and is long enough! */
    if ( unlikely((x = x->next) == NULL) || 
         unlikely(x->extent.nr_sectors < pseg[1].nr_sects) )
    {
        DPRINTK("vbd_translate: multiple overruns or end of vbd.\n");
        spin_unlock(&p->vbd_lock);
        return -EACCES;
    }

    /* Store the real device and start sector for the second chunk. */
    pseg[1].dev           = x->extent.device;
    pseg[1].sector_number = x->extent.start_sector;
    
    spin_unlock(&p->vbd_lock);
    return 2;
}
