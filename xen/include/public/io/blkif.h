/******************************************************************************
 * blkif.h
 * 
 * Unified block-device I/O interface for Xen guest OSes.
 * 
 * Copyright (c) 2003-2004, Keir Fraser
 */

#ifndef __XEN_PUBLIC_IO_BLKIF_H__
#define __XEN_PUBLIC_IO_BLKIF_H__

#include "ring.h"

#ifndef blkif_vdev_t
#define blkif_vdev_t   uint16_t
#endif
#define blkif_sector_t uint64_t

#define BLKIF_OP_READ      0
#define BLKIF_OP_WRITE     1

/* NB. Ring size must be small enough for sizeof(blkif_ring_t) <= PAGE_SIZE. */
#define BLKIF_RING_SIZE        64

/*
 * Maximum scatter/gather segments per request.
 * This is carefully chosen so that sizeof(blkif_ring_t) <= PAGE_SIZE.
 * NB. This could be 12 if the ring indexes weren't stored in the same page.
 */
#define BLKIF_MAX_SEGMENTS_PER_REQUEST 11

typedef struct blkif_request {
    uint8_t        operation;    /* BLKIF_OP_???                         */
    uint8_t        nr_segments;  /* number of segments                   */
    blkif_vdev_t   handle;       /* only for read/write requests         */
    unsigned long  id;           /* private guest value, echoed in resp  */
    blkif_sector_t sector_number;/* start sector idx on disk (r/w only)  */
    /* @f_a_s[4:0]=last_sect ; @f_a_s[9:5]=first_sect                        */
    /* @f_a_s[:16]= grant reference (16 bits)                                */
    /* @first_sect: first sector in frame to transfer (inclusive).           */
    /* @last_sect: last sector in frame to transfer (inclusive).             */
    unsigned long  frame_and_sects[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} blkif_request_t;

#define blkif_fas(_addr, _fs, _ls) ((_addr)|((_fs)<<5)|(_ls))
#define blkif_first_sect(_fas) (((_fas)>>5)&31)
#define blkif_last_sect(_fas)  ((_fas)&31)

#define blkif_fas_from_gref(_gref, _fs, _ls) (((_gref)<<16)|((_fs)<<5)|(_ls))
#define blkif_gref_from_fas(_fas) ((_fas)>>16)

typedef struct blkif_response {
    unsigned long   id;              /* copied from request */
    uint8_t         operation;       /* copied from request */
    int16_t         status;          /* BLKIF_RSP_???       */
} blkif_response_t;

#define BLKIF_RSP_ERROR  -1 /* non-specific 'error' */
#define BLKIF_RSP_OKAY    0 /* non-specific 'okay'  */

#define BLKIF_MAJOR(dev) ((dev)>>8)
#define BLKIF_MINOR(dev) ((dev) & 0xff)

/*
 * Generate blkif ring structures and types.
 */

DEFINE_RING_TYPES(blkif, blkif_request_t, blkif_response_t);

#define VDISK_CDROM        0x1
#define VDISK_REMOVABLE    0x2
#define VDISK_READONLY     0x4

#endif /* __XEN_PUBLIC_IO_BLKIF_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
