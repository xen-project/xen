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


#if 0
#define DPRINTK(_f, _a...) printk( _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif


/* XXX SMH: crappy 'hash function' .. fix when care. */
#define HSH(_x) (((_x) >> 6) & (VBD_HTAB_SZ - 1))

/* 
** Create a new VBD; all this involves is adding an entry to the domain's
** vbd hash table; caller must be privileged. 
*/
long vbd_create(vbd_create_t *create_params) 
{
    struct task_struct *p; 
    vbd_t *new_vbd, *v; 
    int h; 

    if(!IS_PRIV(current))
	return -EPERM; 

    p = find_domain_by_id(create_params->domain);

    if (!p) { 
	printk("vbd_create attempted for non-existent domain %d\n", 
	       create_params->domain); 
	return -EINVAL; 
    }

    new_vbd = kmalloc(sizeof(vbd_t), GFP_KERNEL); 
    new_vbd->vdevice = create_params->vdevice; 
    new_vbd->mode    = create_params->mode; 
    new_vbd->extents = (xen_extent_le_t *)NULL; 
    new_vbd->next    = (vbd_t *)NULL; 

    h = HSH(create_params->vdevice); 
    if(p->vbdtab[h]) { 
	for(v = p->vbdtab[h]; v->next; v = v->next) 
	    ; 
	v->next = new_vbd; 
    } else p->vbdtab[h] = new_vbd; 

    put_task_struct(p);
    
    return 0; 
}

/*
** Add an extent to an existing VBD; fails if the VBD doesn't exist. 
** Doesn't worry about overlapping extents (e.g. merging etc) for now. 
*/
long vbd_add(vbd_add_t *add_params) 
{
    struct task_struct *p; 
    xen_extent_le_t *x, *xele; 
    vbd_t *v; 
    int h; 

    if(!IS_PRIV(current))
	return -EPERM; 

    p = find_domain_by_id(add_params->domain);

    if (!p) { 
	printk("vbd_add attempted for non-existent domain %d\n", 
	       add_params->domain); 
	return -EINVAL; 
    }

    h = HSH(add_params->vdevice); 

    for(v = p->vbdtab[h]; v; v = v->next) 
	if(v->vdevice == add_params->vdevice)
	    break; 

    if(!v) {
	printk("vbd_add; attempted to add extent to non-existent VBD.\n"); 
	return -EINVAL; 
    }

    xele = kmalloc(sizeof(xen_extent_le_t), GFP_KERNEL); 
    xele->extent.device       = add_params->extent.device; 
    xele->extent.start_sector = add_params->extent.start_sector; 
    xele->extent.nr_sectors   = add_params->extent.nr_sectors; 
    xele->next                = (xen_extent_le_t *)NULL; 

    if(!v->extents) {
	v->extents = xele; 
    } else { 
	for(x = v->extents; x->next; x = x->next) 
	    ; 
	x->next = xele; 
    } 

    put_task_struct(p);

    return 0; 
}

long vbd_remove(vbd_remove_t *remove_params) 
{
    if(!IS_PRIV(current))
	return -EPERM; 

    return -ENOSYS; 
}

long vbd_delete(vbd_delete_t *delete_params) 
{
    if(!IS_PRIV(current))
	return -EPERM; 

    return -ENOSYS; 
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
    int i, ret; 

    for(i = 0; i < VBD_HTAB_SZ; i++) { 

	for(v = p->vbdtab[i]; v; v = v->next) { 

	    /* SMH: don't ever expect this to happen, hence verbose printk */
	    if ( xdi->count == xdi->max ) { 
		printk("vbd_probe_devices: out of space for probe.\n"); 
		return -ENOMEM; 
	    }

	    cur_disk.device = v->vdevice; 
	    cur_disk.info   = XD_FLAG_VIRT | XD_TYPE_DISK; 
	    if(!VBD_CAN_WRITE(v))
		cur_disk.info |= XD_FLAG_RO; 
	    cur_disk.capacity = 0 ; 
	    for(x = v->extents; x; x = x->next) 
		cur_disk.capacity += x->extent.nr_sectors; 
	    cur_disk.domain   = p->domain; 

	    /* Now copy into relevant part of user-space buffer */
	    if((ret = copy_to_user(xdi->disks + xdi->count, &cur_disk, 
				   sizeof(xen_disk_t))) < 0) { 
		printk("vbd_probe_devices: copy_to_user failed [rc=%d]\n", 
		       ret); 
		return ret; 
	    } 
	    

	    xdi->count++; 
	}
    } 

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
long vbd_probe(vbd_probe_t *probe_params) 
{
    struct task_struct *p = NULL; 
    short putp = 0; 
    int ret = 0;  

    if(probe_params->domain) { 

	/* we can only probe for ourselves unless we're privileged */
	if(probe_params->domain != current->domain && !IS_PRIV(current))
	    return -EPERM; 

	if(probe_params->domain != VBD_PROBE_ALL) { 

	    p = find_domain_by_id(probe_params->domain);
	    
	    if (!p) { 
		printk("vbd_probe attempted for non-existent domain %d\n", 
		       probe_params->domain); 
		return -EINVAL; 
	    }

	    putp = 1; 
	}

    } else 
	/* default is to probe for ourselves */
	p = current; 


    if(!p || IS_PRIV(p)) { 

	/* privileged domains always get access to the 'real' devices */
	if((ret = ide_probe_devices(&probe_params->xdi))) {
	    printk("vbd_probe: error %d in probing ide devices\n", ret); 
	    goto out; 
	}
	if((ret = scsi_probe_devices(&probe_params->xdi))) { 
	    printk("vbd_probe: error %d in probing scsi devices\n", ret); 
	    goto out; 
	}
    } 
    

    if(!p) { 

        u_long flags;

        read_lock_irqsave (&tasklist_lock, flags);

	p = &idle0_task; 
        while ( (p = p->next_task) != &idle0_task ) {
            if (!is_idle_task(p)) { 
		if((ret = vbd_probe_devices(&probe_params->xdi, p))) { 
		    printk("vbd_probe: error %d in probing virtual devices\n",
			   ret); 
		    read_unlock_irqrestore(&tasklist_lock, flags);
		    goto out; 
		}
	    }
	}

	read_unlock_irqrestore(&tasklist_lock, flags);
		
    } else { 

	/* probe for disks and VBDs for just 'p' */
	if((ret = vbd_probe_devices(&probe_params->xdi, p))) { 
	    printk("vbd_probe: error %d in probing virtual devices\n", ret); 
	    goto out; 
	}

    }

 out: 
    if(putp) 
	put_task_struct(p); 

    return ret; 
}

long vbd_info(vbd_info_t *info_params) 
{
    struct task_struct *p = NULL; 
    xen_extent_le_t *x; 
    xen_extent_t *extents; 
    vbd_t *v; 
    int h, ret = 0;  
   
    if(info_params->domain != current->domain && !IS_PRIV(current))
	return -EPERM; 

    p = find_domain_by_id(info_params->domain);
    
    if (!p) { 
	printk("vbd_info attempted for non-existent domain %d\n", 
	       info_params->domain); 
	return -EINVAL; 
    }

    h = HSH(info_params->vdevice); 

    for(v = p->vbdtab[h]; v; v = v->next) 
	if(v->vdevice == info_params->vdevice)
	    break; 

    if(!v) {
	printk("vbd_info attempted on non-existent VBD.\n"); 
	ret = -EINVAL; 
	goto out; 
    }

    info_params->mode     = v->mode; 
    info_params->nextents = 0; 

    extents = info_params->extents; // convenience 

    for(x = v->extents; x; x = x->next) {
	if((ret = copy_to_user(extents++, &x->extent, 
			       sizeof(xen_extent_t))) < 0) {
	    printk("vbd_info: copy_to_user failed [rc=%d]\n", ret); 
	    goto out; 
	} 
	info_params->nextents++; 
    }

 out: 
    put_task_struct(p); 
    return ret; 
}


int vbd_translate(phys_seg_t * pseg, int *nr_segs, 
		  struct task_struct *p, int operation)
{
    xen_extent_le_t *x; 
    vbd_t *v; 
    int h; 
    long sec; 

    h = HSH(pseg->dev); 

    for(v = p->vbdtab[h]; v; v = v->next) 
	if(v->vdevice == pseg->dev)
	    break; 

    if(!v) {
	if(!IS_PRIV(p)) 
	    printk("vbd_translate; domain %d attempted to access "
		   "non-existent VBD.\n", p->domain); 
	return -ENODEV; 
    }

    if(operation == READ && !VBD_CAN_READ(v)) 
	return -EACCES; 
    
    if(operation == WRITE && !VBD_CAN_WRITE(v))
	return -EACCES; 
    

    /* Now iterate through the list of xen_extents, working out which 
       should be used to perform the translation. */
    sec = pseg->sector_number; 
    for(x = v->extents; x; x = x->next) { 

	if(sec < x->extent.nr_sectors) {

	    /* we've got a match! XXX SMH: should deal with 
	       situation where we span multiple xe's */

	    pseg->dev = x->extent.device; 
	    pseg->sector_number += x->extent.start_sector; 

	    return 0; 

	} 

	sec -= x->extent.nr_sectors; 
    }

    /* No luck -- return no access */
    return -EACCES; 
}






