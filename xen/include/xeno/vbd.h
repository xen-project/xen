/*
** include/xeno/vbd.h: 
** -- xen internal declarations + prototypes for virtual block devices
**
*/
#ifndef __VBD_H__
#define __VBD_H__

#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/vbd.h>

/* Describes a physical disk extent. */
typedef struct {
    unsigned short dev;
    unsigned short nr_sects;
    unsigned long  sector_number;
    unsigned long  buffer;
} phys_seg_t;

struct task_struct;

void xen_vbd_initialize(void);
void xen_refresh_vbd_list (struct task_struct *p);
int xen_vbd_create(xv_disk_t *xvd);
int xen_vbd_delete(struct task_struct *p, int segnr);
int xen_vbd_map_request(
    phys_seg_t *pseg, struct task_struct *p, int operation,
    unsigned short vbd_number,
    unsigned long sect_nr, unsigned long buffer, unsigned short nr_sects);

typedef struct vbd
{
    int mode;                         /* UNUSED, RO, or RW */
    int domain;
    int vbd_number;               /* vbd number for domain */
    char key[XEN_VBD_KEYSIZE];    /* for the userspace tools in dom0 */
    int num_extents;                  /* number of extents */
    extent_t *extents;
} vbd_t;

#endif

#ifndef PHYSDISK_ACES__
#define PHYSDISK_ACES__

struct task_struct;

void destroy_physdisk_aces(struct task_struct *p);

int xen_physdisk_grant(xp_disk_t *);
int xen_physdisk_probe(struct task_struct *requesting_task,
		       physdisk_probebuf_t *);
int xen_physdisk_access_okay(phys_seg_t *pseg, struct task_struct *p,
			     int operation);

#endif /* PHYSDISK_ACES__ */
