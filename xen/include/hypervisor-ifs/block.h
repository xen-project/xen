/******************************************************************************
 * block.h
 *
 * shared structures for block IO.
 *
 */

#ifndef __BLOCK_H__
#define __BLOCK_H__

/*
 * Command values for block_io_op()
 */

#define BLKOP_PUSH_BUFFERS   0  /* Notify Xen of new requests on the ring. */
#define BLKOP_FLUSH_BUFFERS  1  /* Flush all pending request buffers.      */


/*
 * Device numbers
 */

#define XENDEV_TYPE_MASK      0xf000
#define XENDEV_IDX_MASK       0x0fff
#define XENDEV_TYPE_SHIFT     12
#define XENDEV_IDX_SHIFT      0

#define XENDEV_IDE            (1 << XENDEV_TYPE_SHIFT)
#define XENDEV_SCSI           (2 << XENDEV_TYPE_SHIFT)
#define XENDEV_VIRTUAL        (3 << XENDEV_TYPE_SHIFT)

#define IS_IDE_XENDEV(_d)     (((_d) & XENDEV_TYPE_MASK) == XENDEV_IDE)
#define IS_SCSI_XENDEV(_d)    (((_d) & XENDEV_TYPE_MASK) == XENDEV_SCSI)
#define IS_VIRTUAL_XENDEV(_d) (((_d) & XENDEV_TYPE_MASK) == XENDEV_VIRTUAL)

#define MK_IDE_XENDEV(_i)     ((_i) | XENDEV_IDE)
#define MK_SCSI_XENDEV(_i)    ((_i) | XENDEV_SCSI)
#define MK_VIRTUAL_XENDEV(_i) ((_i) | XENDEV_VIRTUAL)


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
#define XEN_BLOCK_PROBE_BLK    5  /* get xhd config from hypervisor */
#define XEN_BLOCK_DEBUG        6  /* debug */
#define XEN_BLOCK_SEG_CREATE   7  /* create segment (vhd) */
#define XEN_BLOCK_SEG_DELETE   8  /* delete segment (vhd) */
#define XEN_BLOCK_PROBE_SEG    9  /* get vhd config from hypervisor */
#define XEN_BLOCK_PHYSDEV_GRANT 10 /* grant access to range of disk blocks */
#define XEN_BLOCK_PHYSDEV_PROBE 11 /* probe for a domain's physdev
				      accesses */
#define XEN_BLOCK_PROBE_SEG_ALL 12 /* prove for every domain's segments,
				      not just ours. */

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

/*
 *
 * virtual disk (vhd) structures, used by XEN_BLOCK_SEG_{CREATE, DELETE}
 *
 */

#define XEN_DISK_READ_WRITE  1
#define XEN_DISK_READ_ONLY   2

typedef struct xv_extent
{
  int disk;                                          /* physical disk number */
  unsigned long offset;               /* offset in blocks into physical disk */
  unsigned long size;                                      /* size in blocks */
} xv_extent_t;

#define XEN_SEGMENT_KEYSIZE 10

typedef struct xv_disk
{
  int mode;                     /* XEN_DISK_READ_WRITE or XEN_DISK_READ_ONLY */
  int domain;                                                      /* domain */
  int segment;                                             /* segment number */
  char key[XEN_SEGMENT_KEYSIZE];        /* key for benefit of dom0 userspace */
  int ext_count;                          /* number of xv_extent_t to follow */
  xv_extent_t extents[XEN_MAX_DISK_COUNT];    /* arbitrary reuse of constant */
} xv_disk_t;

#define PHYSDISK_MODE_R 1
#define PHYSDISK_MODE_W 2
typedef struct xp_disk
{
  int mode; /* 0 -> revoke existing access, otherwise bitmask of
	       PHYSDISK_MODE_? constants */
  int domain;
  unsigned short device; /* XENDEV_??? + idx */
  unsigned short partition; /* partition number */
  unsigned long start_sect;
  unsigned long n_sectors;
} xp_disk_t;

#define PHYSDISK_MAX_ACES_PER_REQUEST 254 /* Make it fit in one page */
typedef struct {
  int n_aces;
  int domain;
  int start_ind;
  struct {
    unsigned short device; /* XENDEV_??? + idx */
    unsigned short partition; /* partition number */
    unsigned long start_sect;
    unsigned long n_sectors;
    unsigned mode;
  } entries[PHYSDISK_MAX_ACES_PER_REQUEST];
} physdisk_probebuf_t;

#endif
