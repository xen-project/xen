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
#define XEN_BLOCK_DEBUG        5   /* debug */

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
 * Information about the real and virtual disks we have; used during 
 * guest device probing. 
 */ 

/* XXX SMH: below types chosen to align with ide_xxx types in ide.h */
#define XD_TYPE_FLOPPY  0x00
#define XD_TYPE_TAPE    0x01
#define XD_TYPE_CDROM   0x05
#define XD_TYPE_OPTICAL 0x07
#define XD_TYPE_DISK    0x20 

#define XD_TYPE_MASK    0x3F
#define XD_TYPE(_x)     ((_x) & XD_TYPE_MASK) 

/* The top two bits of the type field encode various flags */
#define XD_FLAG_RO      0x40
#define XD_FLAG_VIRT    0x80
#define XD_READONLY(_x) ((_x) & XD_FLAG_RO)
#define XD_VIRTUAL(_x)  ((_x) & XD_FLAG_VIRT) 

typedef struct xen_disk
{
    unsigned short device;       /* device number (opaque 16 bit val)  */
    unsigned short info;         /* device type and flags              */
    unsigned long  capacity;     /* size in terms of #512 byte sectors */
    unsigned int   domain;       /* if a VBD, domain this 'belongs to' */
} xen_disk_t;

typedef struct xen_disk_info
{
    /* IN variables  */
    int         max;             // maximumum number of disks to report
    xen_disk_t *disks;           // pointer to array of disk info 
    /* OUT variables */
    int         count;           // how many disks we have info about 
} xen_disk_info_t;

#endif
