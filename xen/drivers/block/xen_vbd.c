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


#if 0
#define DPRINTK(_f, _a...) printk( _f , ## _a )
#else
#define DPRINTK(_f, _a...) ((void)0)
#endif


/* XXX SMH: crappy 'hash function' .. fix when care. */
#define HSH(_x) (((_x) >> 6) & (VBD_HTAB_SZ - 1))

/* 
** Create a new VBD; all this involves is adding an entry to the domain's
** vbd hash table. 
*/
long vbd_create(vbd_create_t *create_info) 
{
    struct task_struct *p; 
    vbd_t *new_vbd, *v; 
    int h; 

    p = find_domain_by_id(create_info->domain);

    if (!p) { 
	printk("vbd_create attempted for non-existent domain %d\n", 
	       create_info->domain); 
	return -EINVAL; 
    }

    new_vbd = kmalloc(sizeof(vbd_t), GFP_KERNEL); 
    new_vbd->vdevice = create_info->vdevice; 
    new_vbd->extents = (xen_extent_le_t *)NULL; 
    new_vbd->next    = (vbd_t *)NULL; 

    h = HSH(create_info->vdevice); 
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
long vbd_add(vbd_add_t *add_info) 
{
    struct task_struct *p; 
    xen_extent_le_t *x, *xele; 
    vbd_t *v; 
    int h; 

    p = find_domain_by_id(add_info->domain);

    if (!p) { 
	printk("vbd_add attempted for non-existent domain %d\n", 
	       add_info->domain); 
	return -EINVAL; 
    }

    h = HSH(add_info->vdevice); 

    for(v = p->vbdtab[h]; v; v = v->next) 
	if(v->vdevice == add_info->vdevice)
	    break; 

    if(!v) {
	printk("vbd_add; attempted to add extent to non-existent VBD.\n"); 
	return -EINVAL; 
    }

    xele = kmalloc(sizeof(xen_extent_le_t), GFP_KERNEL); 
    xele->extent.device       = add_info->extent.device; 
    xele->extent.start_sector = add_info->extent.start_sector; 
    xele->extent.nr_sectors   = add_info->extent.nr_sectors; 
    xele->extent.mode         = add_info->extent.mode; 
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

long vbd_remove(vbd_remove_t *remove_info) 
{
    return -ENOSYS; 
}

long vbd_delete(vbd_delete_t *delete_info) 
{
    return -ENOSYS; 
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

    /* Now iterate through the list of xen_extents, working out which 
       should be used to perform the translation. */
    sec = pseg->sector_number; 
    for(x = v->extents; x; x = x->next) { 

	if(sec < x->extent.nr_sectors) {

	    /* we've got a match! XXX SMH: should deal with 
	       situation where we span multiple xe's */

	    if(operation == READ && !(x->extent.mode & PHYSDISK_MODE_R))
		return -EACCES; 

	    if(operation == WRITE && !(x->extent.mode & PHYSDISK_MODE_W))
		return -EACCES; 

	    pseg->dev = x->extent.device; 
	    pseg->sector_number += x->extent.start_sector; 

	    return 0; 

	} 

	sec -= x->extent.nr_sectors; 
    }

    /* No luck -- return no access */
    return -EACCES; 
}


/*
 * vbd_probe_devices: 
 *
 * add the virtual block devices for this domain to a xen_disk_info_t; 
 * we assume xdi->count points to the first unused place in the array. 
 */
void vbd_probe_devices(xen_disk_info_t *xdi, struct task_struct *p)
{
    xen_extent_le_t *x; 
    vbd_t *v; 
    int i; 

    /* XXX SMH: should allow priv domains to probe vbds for other doms XXX */

    for(i = 0; i < VBD_HTAB_SZ; i++) { 
	for(v = p->vbdtab[i]; v; v = v->next) { 
	    xdi->disks[xdi->count].device   = v->vdevice; 
	    xdi->disks[xdi->count].type     = XD_TYPE_DISK; // always :-) 
	    xdi->disks[xdi->count].capacity = 0; 
	    for(x = v->extents; x; x = x->next) 
		xdi->disks[xdi->count].capacity += x->extent.nr_sectors; 
	    xdi->count++; 
	}
    } 

    return; 
}





