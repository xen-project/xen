#ifndef __SEGMENT_H__
#define __SEGMENT_H__

#include <hypervisor-ifs/block.h>
#include <hypervisor-ifs/segment.h>

/* Describes a physical disk extent. */
typedef struct {
    unsigned short dev;
    unsigned short nr_sects;
    unsigned long  sector_number;
    unsigned long  buffer;
} phys_seg_t;

struct task_struct;

void xen_segment_initialize(void);
void xen_refresh_segment_list (struct task_struct *p);
int xen_segment_create(xv_disk_t *xvd);
int xen_segment_map_request(
    phys_seg_t *pseg, struct task_struct *p, int operation,
    unsigned short segment_number,
    unsigned long sect_nr, unsigned long buffer, unsigned short nr_sects);

/*
 * virtual hard disks
 *
 * each segment is composed of a number of extents
 */

typedef struct extent
{
    int disk;                         /* A XEN_IDE_DEV or a XEN_SCSI_DEV */
    unsigned long offset;             /* offset into disk */
    unsigned long size;               /* size of this extent */
} extent_t;

typedef struct segment
{
    int mode;                         /* UNUSED, RO, or RW */
    int domain;
    int segment_number;               /* segment number for domain */
    char key[XEN_SEGMENT_KEYSIZE];    /* for the userspace tools in dom0 */
    int num_extents;                  /* number of extents */
    extent_t *extents;
} segment_t;

#endif
