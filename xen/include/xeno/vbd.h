/*
** include/xeno/vbd.h: 
** -- xen internal declarations + prototypes for virtual block devices
*/

#ifndef __VBD_H__
#define __VBD_H__

#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/vbd.h>

#include <xeno/rbtree.h>

/* An entry in a list of xen_extents. */
typedef struct _xen_extent_le { 
    xen_extent_t extent;               /* an individual extent */
    struct _xen_extent_le *next;       /* and a pointer to the next */ 
} xen_extent_le_t; 

/*
 * This is what a vbd looks like from the p.o.v. of xen: essentially a list of
 * xen_extents which a given domain refers to by a particular 16bit id. Each
 * domain has a lookup structure to map from these to the relevant VBD.
 */
typedef struct _vbd { 
    unsigned short    vdevice;   /* what the domain refers to this vbd as */
    unsigned char     mode;      /* VBD_MODE_{R,W} */
    unsigned char     type;      /* XD_TYPE_xxx */
    xen_extent_le_t  *extents;   /* list of xen_extents making up this vbd */
    rb_node_t         rb;        /* for linking into R-B tree lookup struct */
} vbd_t; 

/*
 * Internal forms of 'vbd_create' and 'vbd_grow. Used when setting up real 
 * physical device access for domain 0.
 */
long __vbd_create(struct task_struct *p,
                  unsigned short vdevice,
                  unsigned char mode,
                  unsigned char type);
long __vbd_grow(struct task_struct *p,
                unsigned short vdevice,
                xen_extent_t *extent);

/* This is the main API, accessible from guest OSes. */
long vbd_create(vbd_create_t *create_params); 
long vbd_grow(vbd_grow_t *grow_params); 
long vbd_shrink(vbd_shrink_t *shrink_params);
long vbd_setextents(vbd_setextents_t *setextents_params);
long vbd_delete(vbd_delete_t *delete_params); 
long vbd_probe(vbd_probe_t *probe_params); 
long vbd_info(vbd_info_t *info_params); 

void destroy_all_vbds(struct task_struct *p);

/* Describes a [partial] disk extent (part of a block io request) */
typedef struct {
    unsigned short dev;
    unsigned short nr_sects;
    unsigned long  buffer;
    xen_sector_t   sector_number;
} phys_seg_t;


int vbd_translate(phys_seg_t *pseg, struct task_struct *p, int operation); 

#endif /* __VBD_H__ */
