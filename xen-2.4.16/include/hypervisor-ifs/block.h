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

#define XEN_BLOCK_SYNC  2
#define XEN_BLOCK_ASYNC 3

#define XEN_BLOCK_MAX_DOMAINS 32  /* NOTE: FIX THIS. VALUE SHOULD COME FROM? */

#define BLK_REQ_RING_SIZE  64
#define BLK_RESP_RING_SIZE 64

#define BLK_REQ_RING_MAX_ENTRIES  (BLK_REQ_RING_SIZE - 2)
#define BLK_RESP_RING_MAX_ENTRIES (BLK_RESP_RING_SIZE - 2)

#define BLK_REQ_RING_INC(_i)     (((_i)+1) & (BLK_REQ_RING_SIZE-1))
#define BLK_RESP_RING_INC(_i)    (((_i)+1) & (BLK_RESP_RING_SIZE-1))
#define BLK_REQ_RING_ADD(_i,_j)  (((_i)+(_j)) & (BLK_REQ_RING_SIZE-1))
#define BLK_RESP_RING_ADD(_i,_j) (((_i)+(_j)) & (BLK_RESP_RING_SIZE-1))

typedef struct blk_ring_req_entry 
{
    void *          id;                /* for guest os use */
    int             priority;          /* SYNC or ASYNC for now */
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
  unsigned int      req_prod, req_cons;
  unsigned int      resp_prod, resp_cons;
  blk_ring_req_entry_t  req_ring[BLK_REQ_RING_SIZE];
  blk_ring_resp_entry_t resp_ring[BLK_RESP_RING_SIZE];
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
