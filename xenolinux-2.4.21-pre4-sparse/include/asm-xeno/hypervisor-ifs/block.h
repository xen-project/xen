/******************************************************************************
 * block.h
 *
 * Block IO communication rings.
 *
 * These are the ring data structures for buffering messages between 
 * the hypervisor and guestos's.  
 *
 */

#ifndef __BLOCK_H__
#define __BLOCK_H__

#include <linux/kdev_t.h>

/* the first four definitions match fs.h */
#define XEN_BLOCK_READ  0
#define XEN_BLOCK_WRITE 1
#define XEN_BLOCK_READA 2                                /* currently unused */
#define XEN_BLOCK_SPECIAL 4                              /* currently unused */
#define XEN_BLOCK_PROBE 8      /* determine io configuration from hypervisor */
#define XEN_BLOCK_DEBUG 16                                          /* debug */

#define BLK_RING_SIZE        128
#define BLK_RING_MAX_ENTRIES (BLK_RING_SIZE - 2)
#define BLK_RING_INC(_i)     (((_i)+1) & (BLK_RING_SIZE-1))
#define BLK_RING_ADD(_i,_j)  (((_i)+(_j)) & (BLK_RING_SIZE-1))

typedef struct blk_ring_req_entry 
{
    void *          id;                /* for guest os use */
    int             operation;         /* XEN_BLOCK_READ or XEN_BLOCK_WRITE */
    char *          buffer;
    unsigned long   block_number;      /* block number */
    unsigned short  block_size;        /* block size */
    kdev_t          device;
    unsigned long   sector_number;     /* real buffer location on disk */
} blk_ring_req_entry_t;

typedef struct blk_ring_resp_entry
{
    void *id;
    unsigned long status;
} blk_ring_resp_entry_t;

typedef struct blk_ring_st 
{
    unsigned int req_prod;  /* Request producer. Updated by guest OS. */
    unsigned int resp_prod; /* Response producer. Updated by Xen.     */
    union {
        blk_ring_req_entry_t  req;
        blk_ring_resp_entry_t resp;
    } ring[BLK_RING_SIZE];
} blk_ring_t;

#define MAX_XEN_DISK_COUNT 100

#define XEN_DISK_IDE  1
#define XEN_DISK_SCSI 2

typedef struct xen_disk                                     /* physical disk */
{
  int           type;                                           /* disk type */
  unsigned long capacity;
  unsigned char heads;                               /* hdreg.h::hd_geometry */
  unsigned char sectors;                             /* hdreg.h::hd_geometry */
  unsigned int  cylinders;                       /* hdreg.h::hd_big_geometry */
  unsigned long start;                               /* hdreg.h::hd_geometry */
  void *        gendisk;                               /* struct gendisk ptr */
} xen_disk_t;

typedef struct xen_disk_info
{
  int         count; /* number of subsequent xen_disk_t structures to follow */
  xen_disk_t  disks[100];
} xen_disk_info_t;

#endif
