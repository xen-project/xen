/******************************************************************************
 * block.h
 *
 * shared structures for block IO.
 *
 */

#ifndef __BLOCK_H__
#define __BLOCK_H__

/*
 *
 * These are the ring data structures for buffering messages between 
 * the hypervisor and guestos's.  
 *
 */

/* the first four definitions match fs.h */
#define XEN_BLOCK_READ         0
#define XEN_BLOCK_WRITE        1
#define XEN_BLOCK_READA        2
#define XEN_BLOCK_SPECIAL      4
#define XEN_BLOCK_PROBE        5   /* get config from hypervisor */
#define XEN_BLOCK_DEBUG        6   /* debug */
#define XEN_BLOCK_VBD_CREATE   7   /* create vbd */
#define XEN_BLOCK_VBD_DELETE   8   /* delete vbd */
                                   /* XXX SMH: was 'probe vbd' */
#define XEN_BLOCK_PHYSDEV_GRANT 10 /* grant access to range of disk blocks */
#define XEN_BLOCK_PHYSDEV_PROBE 11 /* probe for a domain's physdev accesses */
                                   /* XXX SMH: was 'probe vbd all' */

/* NB. Ring size must be small enough for sizeof(blk_ring_t) <= PAGE_SIZE. */
#define BLK_RING_SIZE        64
#define BLK_RING_INC(_i)     (((_i)+1) & (BLK_RING_SIZE-1))

/*
 * Maximum scatter/gather segments per request.
 * This is carefully chosen so that sizeof(blk_ring_t) <= PAGE_SIZE.
 */
#define MAX_BLK_SEGS 12

typedef struct blk_ring_req_entry 
{
    unsigned long  id;                     /* private guest os value       */
    unsigned long  sector_number;          /* start sector idx on disk     */
    unsigned short device;                 /* XENDEV_??? + idx             */
    unsigned char  operation;              /* XEN_BLOCK_???                */
    unsigned char  nr_segments;            /* number of segments           */
    /* Least 9 bits is 'nr_sects'. High 23 bits are the address.           */
    unsigned long  buffer_and_sects[MAX_BLK_SEGS];
} blk_ring_req_entry_t;

typedef struct blk_ring_resp_entry
{
    unsigned long   id;                   /* copied from request          */
    unsigned short  operation;            /* copied from request          */
    unsigned long   status;               /* cuurently boolean good/bad   */
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

/*
 *
 * physical disk (xhd) info, used by XEN_BLOCK_PROBE
 *
 */

#define XEN_MAX_DISK_COUNT 100

/* XXX SMH: below types chosen to align with ide_xxx types in ide.h */
#define XD_TYPE_FLOPPY  0x00
#define XD_TYPE_TAPE    0x01
#define XD_TYPE_CDROM   0x05
#define XD_TYPE_OPTICAL 0x07
#define XD_TYPE_DISK    0x20 

typedef struct xen_disk
{
    unsigned short device;       /* device number (see top of file)    */
    unsigned short type;         /* device type, i.e. disk, cdrom, etc */
    unsigned long  capacity;     /* size in terms of #512 byte sectors */
} xen_disk_t;

typedef struct xen_disk_info
{
  int         count;
  xen_disk_t  disks[XEN_MAX_DISK_COUNT];
} xen_disk_info_t;

#endif
