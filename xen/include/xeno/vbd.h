/*
** include/xeno/vbd.h: 
** -- xen internal declarations + prototypes for virtual block devices
**
*/
#ifndef __VBD_H__
#define __VBD_H__

#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/vbd.h>

/* an entry in a list of xen_extent's */
typedef struct _xen_extent_le { 
    xen_extent_t           extent;     // an individual extent  
    struct _xen_extent_le *next;       // and a pointer to the next 
} xen_extent_le_t; 


/*
** This is what a vbd looks like from the pov of xen: essentially a list 
** of xen_extents which a given domain refers to by a particular 16bit id. 
** Each domain has a hash table to map from these to the relevant VBD. 
*/
typedef struct _vbd { 
    unsigned short    vdevice;   // what the domain refers to this vbd as 
    xen_extent_le_t  *extents;   // list of xen_extents making up this vbd
    struct _vbd      *next;      // for chaining in the hash table
} vbd_t; 

#define VBD_HTAB_SZ  16       // no. of entries in the vbd hash table. 

void xen_vbd_initialize(void);
void xen_refresh_vbd_list (struct task_struct *p);
long vbd_create(vbd_create_t *create_info); 
long vbd_add(vbd_add_t *add_info); 
long vbd_remove(vbd_remove_t *remove_info);
long vbd_delete(vbd_delete_t *delete_info); 

/* Describes a physical disk extent (part of a block io request) */
typedef struct {
    unsigned short dev;
    unsigned short nr_sects;
    unsigned long  sector_number;
    unsigned long  buffer;
} phys_seg_t;


int vbd_translate(phys_seg_t * pseg, int *nr_segs, 
		  struct task_struct *p, int operation); 


#if 0
void destroy_physdisk_aces(struct task_struct *p);

int xen_physdisk_grant(xp_disk_t *);
int xen_physdisk_probe(struct task_struct *requesting_task,
		       physdisk_probebuf_t *);
int xen_physdisk_access_okay(phys_seg_t *pseg, struct task_struct *p,
			     int operation);
#endif


#endif /* PHYSDISK_ACES__ */
