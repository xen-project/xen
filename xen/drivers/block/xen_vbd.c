/*
 * xen_vbd.c : routines for managing virtual block devices 
 */

#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <asm/io.h>
#include <xeno/slab.h>
#include <xeno/sched.h>
#include <xeno/vbd.h>
#include <xeno/blkdev.h>
#include <xeno/keyhandler.h>
#include <asm/current.h>
#include <asm/domain_page.h>

/* 
** XXX SMH: the below probe functions /append/ their info to the 
** xdi array; i.e.  they assume that all earlier slots are correctly 
** filled, and that xdi->count points to the first  free entry in 
** the array. All kinda gross but it'll do for now.  
*/
extern int ide_probe_devices(xen_disk_info_t *xdi);
extern int scsi_probe_devices(xen_disk_info_t *xdi);

/* XXX SMH: crappy 'hash function' .. fix when care. */
#define HSH(_x) ((_x) & (VBD_HTAB_SZ - 1))


/* 
** Create a new VBD; all this involves is adding an entry to the domain's
** vbd hash table; caller must be privileged. 
*/
long vbd_create(vbd_create_t *create) 
{
    struct task_struct *p; 
    vbd_t *new_vbd, **pv; 
    long ret = 0;

    if ( unlikely(!IS_PRIV(current)) )
        return -EPERM; 

    if ( unlikely((p = find_domain_by_id(create->domain)) == NULL) )
    {
        DPRINTK("vbd_create attempted for non-existent domain %d\n", 
                create->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    for ( pv = &p->vbdtab[HSH(create->vdevice)]; 
          *pv != NULL; 
          pv = &(*pv)->next ) 
    {
        if ( unlikely((*pv)->vdevice == create->vdevice) )
        {
            DPRINTK("vbd_create attempted for already existing vbd\n");
            ret = -EINVAL;
            goto out;
        }
        if ( (*pv)->vdevice > create->vdevice )
            break;
    }

    if ( unlikely((new_vbd = kmalloc(sizeof(vbd_t), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_create: out of memory\n");
        ret = -ENOMEM;
        goto out;
    }

    new_vbd->vdevice = create->vdevice; 
    new_vbd->mode    = create->mode; 
    new_vbd->extents = NULL; 
    new_vbd->next    = *pv; 

    *pv = new_vbd;

 out:
    spin_unlock(&p->vbd_lock);
    put_task_struct(p);
    return ret; 
}


/* Grow a VBD by appending a new extent. Fails if the VBD doesn't exist. */
long vbd_grow(vbd_grow_t *grow) 
{
    struct task_struct *p; 
    xen_extent_le_t **px, *x; 
    vbd_t *v; 
    long ret = 0;

    if ( unlikely(!IS_PRIV(current)) )
        return -EPERM; 

    if ( unlikely((p = find_domain_by_id(grow->domain)) == NULL) )
    {
        DPRINTK("vbd_grow: attempted for non-existent domain %d\n", 
                grow->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    for ( v = p->vbdtab[HSH(grow->vdevice)]; v != NULL; v = v->next ) 
        if ( v->vdevice == grow->vdevice )
            break; 

    if ( unlikely(v == NULL) )
    {
        DPRINTK("vbd_grow: attempted to append extent to non-existent VBD.\n");
        ret = -EINVAL;
        goto out; 
    }

    if ( unlikely((x = kmalloc(sizeof(xen_extent_le_t), GFP_KERNEL)) == NULL) )
    {
        DPRINTK("vbd_grow: out of memory\n");
        ret = -ENOMEM;
        goto out;
    }
 
    x->extent.device       = grow->extent.device; 
    x->extent.start_sector = grow->extent.start_sector; 
    x->extent.nr_sectors   = grow->extent.nr_sectors; 
    x->next                = (xen_extent_le_t *)NULL; 

    for ( px = &v->extents; *px != NULL; px = &(*px)->next ) 
        continue;

    *px = x;

 out:
    spin_unlock(&p->vbd_lock);
    put_task_struct(p);
    return ret;
}


long vbd_shrink(vbd_shrink_t *shrink)
{
    struct task_struct *p; 
    xen_extent_le_t **px, *x; 
    vbd_t *v; 
    long ret = 0;

    if ( !IS_PRIV(current) )
        return -EPERM; 

    if ( (p = find_domain_by_id(shrink->domain)) == NULL )
    {
        DPRINTK("vbd_shrink attempted for non-existent domain %d\n", 
                shrink->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    for ( v = p->vbdtab[HSH(shrink->vdevice)]; v != NULL; v = v->next ) 
        if ( v->vdevice == shrink->vdevice )
            break; 

    if ( unlikely(v == NULL) || unlikely(v->extents == NULL) )
    {
        DPRINTK("vbd_shrink: attempt to remove non-existent extent.\n"); 
        ret = -EINVAL;
        goto out;
    }

    /* Find the last extent. We now know that there is at least one. */
    for ( px = &v->extents; (*px)->next != NULL; px = &(*px)->next )
        continue;

    x   = *px;
    *px = x->next;
    kfree(x);

 out:
    spin_unlock(&p->vbd_lock);
    put_task_struct(p);
    return ret; 
}


long vbd_setextents(vbd_setextents_t *setextents)
{
    struct task_struct *p; 
    xen_extent_t e;
    xen_extent_le_t *new_extents, *x, *t; 
    vbd_t *v; 
    int i;
    long ret = 0;

    if ( !IS_PRIV(current) )
        return -EPERM; 

    if ( (p = find_domain_by_id(setextents->domain)) == NULL )
    {
        DPRINTK("vbd_setextents attempted for non-existent domain %d\n", 
                setextents->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    for ( v = p->vbdtab[HSH(setextents->vdevice)]; v != NULL; v = v->next ) 
        if ( v->vdevice == setextents->vdevice )
            break; 

    if ( unlikely(v == NULL) )
    {
        DPRINTK("vbd_setextents: attempt to modify non-existent VBD.\n"); 
        ret = -EINVAL;
        goto out;
    }

    /* Construct the new extent list. */
    new_extents = NULL;
    for ( i = setextents->nr_extents; i >= 0; i++ )
    {
        if ( unlikely(copy_from_user(&e, 
                                     &setextents->extents[i], 
                                     sizeof(e)) != 0) )
        {
            DPRINTK("vbd_setextents: copy_from_user failed\n");
            ret = -EFAULT;
            goto free_and_out;
        }
        
        if ( unlikely((x = kmalloc(sizeof(xen_extent_le_t), GFP_KERNEL))
                      == NULL) )
        {
            DPRINTK("vbd_setextents: out of memory\n");
            ret = -ENOMEM;
            goto free_and_out;
        }
        
        x->extent = e;
        x->next   = new_extents;

        new_extents = x;
    }

    /* Delete the old extent list _after_ successfully creating the new. */
    for ( x = v->extents; x != NULL; x = t )
    {
        t = x->next;
        kfree(x);
    }

    /* Make the new list visible. */
    v->extents = new_extents;

 out:
    spin_unlock(&p->vbd_lock);
    put_task_struct(p);
    return ret;

 free_and_out:
    /* Failed part-way through the new list. Delete all that we managed. */
    for ( x = new_extents; x != NULL; x = t )
    {
        t = x->next;
        kfree(x);
    }
    goto out;
}


long vbd_delete(vbd_delete_t *delete) 
{
    struct task_struct *p; 
    vbd_t *v, **pv; 
    xen_extent_le_t *x, *t;

    if( !IS_PRIV(current) )
        return -EPERM; 

    if ( (p = find_domain_by_id(delete->domain)) == NULL )
    {
        DPRINTK("vbd_delete attempted for non-existent domain %d\n", 
                delete->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    for ( pv = &p->vbdtab[HSH(delete->vdevice)]; 
          *pv != NULL; 
          pv = &(*pv)->next ) 
    {
        if ( (*pv)->vdevice == delete->vdevice )
            goto found;
    }
    
    DPRINTK("vbd_delete attempted for non-existing VBD.\n");

    spin_unlock(&p->vbd_lock);
    put_task_struct(p);
    return -EINVAL;

 found:
    v = *pv;
    *pv = v->next;
    x = v->extents;
    kfree(v);

    while ( x != NULL )
    {
        t = x->next;
        kfree(x);
        x = t;
    }
    
    spin_unlock(&p->vbd_lock);
    put_task_struct(p);
    return 0;
}


void destroy_all_vbds(struct task_struct *p)
{
    int i;
    vbd_t *v; 
    xen_extent_le_t *x, *t;

    spin_lock(&p->vbd_lock);
    for ( i = 0; i < VBD_HTAB_SZ; i++ )
    {
        while ( (v = p->vbdtab[i]) != NULL )
        {
            p->vbdtab[i] = v->next;
      
            x = v->extents;
            kfree(v);
            
            while ( x != NULL )
            {
                t = x->next;
                kfree(x);
                x = t;
            }          
        }
    }
    spin_unlock(&p->vbd_lock);
}


/*
 * vbd_probe_devices: 
 *
 * add the virtual block devices for this domain to a xen_disk_info_t; 
 * we assume xdi->count points to the first unused place in the array. 
 */
static int vbd_probe_devices(xen_disk_info_t *xdi, struct task_struct *p)
{
    xen_extent_le_t *x; 
    xen_disk_t cur_disk; 
    vbd_t *v; 
    int i; 

    spin_lock(&p->vbd_lock);

    for ( i = 0; i < VBD_HTAB_SZ; i++ )
    { 
        for ( v = p->vbdtab[i]; v != NULL; v = v->next )
        { 
            if ( xdi->count == xdi->max )
            {
                DPRINTK("vbd_probe_devices: out of space for probe.\n"); 
                spin_unlock(&p->vbd_lock);
                return -ENOMEM; 
            }

            cur_disk.device = v->vdevice; 
            cur_disk.info   = XD_FLAG_VIRT | XD_TYPE_DISK; 
            if ( !VBD_CAN_WRITE(v) )
                cur_disk.info |= XD_FLAG_RO; 
            cur_disk.capacity = 0 ; 
            for ( x = v->extents; x != NULL; x = x->next )
                cur_disk.capacity += x->extent.nr_sectors; 
            cur_disk.domain = p->domain; 

            /* Now copy into relevant part of user-space buffer */
            if( copy_to_user(&xdi->disks[xdi->count], 
                             &cur_disk, 
                             sizeof(xen_disk_t)) )
            { 
                DPRINTK("vbd_probe_devices: copy_to_user failed\n");
                spin_unlock(&p->vbd_lock);
                return -EFAULT;
            } 
        
            xdi->count++; 
        }
    } 

    spin_unlock(&p->vbd_lock);
    return 0;  
}


/*
** Return information about the VBDs available for a given domain, 
** or for all domains; in the general case the 'domain' argument 
** will be 0 which means "information about the caller"; otherwise
** the 'domain' argument will specify either a given domain, or 
** all domains ("VBD_PROBE_ALL") -- both of these cases require the
** caller to be privileged. 
*/
long vbd_probe(vbd_probe_t *probe) 
{
    struct task_struct *p = NULL; 
    unsigned long flags;
    long ret = 0;  

    if ( probe->domain != 0 )
    { 
        /* We can only probe for ourselves unless we're privileged. */
        if( (probe->domain != current->domain) && !IS_PRIV(current) )
            return -EPERM; 

        if ( (probe->domain != VBD_PROBE_ALL) &&
             ((p = find_domain_by_id(probe->domain)) == NULL) )
        {
            DPRINTK("vbd_probe attempted for non-existent domain %d\n", 
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

    if ( (probe->domain == VBD_PROBE_ALL) || IS_PRIV(p) )
    { 
        /* Privileged domains always get access to the 'real' devices. */
        if ( ((ret = ide_probe_devices(&probe->xdi)) != 0) ||
             ((ret = scsi_probe_devices(&probe->xdi)) != 0) )
            goto out; 
    } 

    if ( probe->domain == VBD_PROBE_ALL )
    { 
        read_lock_irqsave(&tasklist_lock, flags);
        p = &idle0_task; 
        while ( (p = p->next_task) != &idle0_task )
        {
            if ( !is_idle_task(p) )
            { 
                if( (ret = vbd_probe_devices(&probe->xdi, p)) != 0 )
                { 
                    read_unlock_irqrestore(&tasklist_lock, flags);
                    goto out; 
                }
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
    vbd_t *v; 
    long ret = 0;  
   
    if ( (info->domain != current->domain) && !IS_PRIV(current) )
        return -EPERM; 

    if ( (p = find_domain_by_id(info->domain)) == NULL )
    {
        DPRINTK("vbd_info attempted for non-existent domain %d\n", 
                info->domain); 
        return -EINVAL; 
    }

    spin_lock(&p->vbd_lock);

    for ( v = p->vbdtab[HSH(info->vdevice)]; v != NULL; v = v->next ) 
        if ( v->vdevice == info->vdevice )
            break; 

    if ( v == NULL )
    {
        DPRINTK("vbd_info attempted on non-existent VBD.\n"); 
        ret = -EINVAL; 
        goto out; 
    }

    info->mode     = v->mode; 
    info->nextents = 0; 

    extents = info->extents;
    for ( x = v->extents; x != NULL; x = x->next )
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
    vbd_t *v; 
    unsigned long sec_off, nr_secs;

    spin_lock(&p->vbd_lock);

    for ( v = p->vbdtab[HSH(pseg->dev)]; v != NULL; v = v->next ) 
        if ( v->vdevice == pseg->dev )
            goto found; 

    if ( unlikely(!IS_PRIV(p)) ) 
        DPRINTK("vbd_translate; domain %d attempted to access "
                "non-existent VBD.\n", p->domain); 

    spin_unlock(&p->vbd_lock);
    return -ENODEV; 

 found:

    if ( ((operation == READ) && !VBD_CAN_READ(v)) ||
         ((operation == WRITE) && !VBD_CAN_WRITE(v)) )
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
    for ( x = v->extents; x != NULL; x = x->next )
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
