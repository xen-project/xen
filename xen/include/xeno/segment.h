#ifndef __SEGMENT_H__
#define __SEGMENT_H__

#include <hypervisor-ifs/block.h>

void xen_segment_initialize(void);
void xen_refresh_segment_list (struct task_struct *p);
int xen_segment_create(xv_disk_t *xvd);
int xen_segment_map_request(
    int *phys_device,                         /* out */
    unsigned long *block_number,              /* out */
    unsigned long *sector_number,             /* out */
    struct task_struct *domain,
    int operation,
    int segment_number,
    int xen_block_number,
    int xen_sector_number);

#define XEN_MAX_SEGMENTS 100     /* total number of segments across all doms */

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

#define XEN_SEGMENT_UNUSED 0          /* bzero default */
#define XEN_SEGMENT_RO XEN_DISK_READ_ONLY
#define XEN_SEGMENT_RW XEN_DISK_READ_WRITE

typedef struct segment
{
    int mode;                         /* UNUSED, RO, or RW */
    int domain;
    int segment_number;               /* segment number for domain */
    int num_extents;                  /* number of extents */
    extent_t *extents;
} segment_t;

#endif
