/*
 * blkint.h
 * 
 * Interfaces for the Xen block interposition driver.
 * 
 * (c) 2004, Andrew Warfield, University of Cambridge
 * 
 */

#ifndef __BLKINT_H__

//#include "blkif.h"


#if 0
/* Types of ring. */
#define BLKIF_REQ_RING_TYPE 1
#define BLKIF_RSP_RING_TYPE 2

/* generic ring struct. */
typedef struct blkif_generic_ring_struct {
    int type;
} blkif_generic_ring_t;

/* A requestor's view of a ring. */
typedef struct blkif_req_ring_struct {

    int type;                    /* Will be BLKIF_REQ_RING_TYPE        */
    BLKIF_RING_IDX req_prod;     /* PRIVATE req_prod index             */
    BLKIF_RING_IDX rsp_cons;     /* Response consumer index            */
    blkif_ring_t *ring;          /* Pointer to shared ring struct      */

} blkif_req_ring_t;

#define BLKIF_REQ_RING_INIT { BLKIF_REQ_RING_TYPE, 0, 0, 0 }

/* A responder's view of a ring. */
typedef struct blkif_rsp_ring_struct {

    int type;                    /* Will be BLKIF_REQ_RING_TYPE        */
    BLKIF_RING_IDX rsp_prod;     /* PRIVATE rsp_prod index             */
    BLKIF_RING_IDX req_cons;     /* Request consumer index             */
    blkif_ring_t *ring;          /* Pointer to shared ring struct      */

} blkif_rsp_ring_t;

#define BLKIF_RSP_RING_INIT { BLKIF_RSP_RING_TYPE, 0, 0, 0 }

#define RING(a) (blkif_generic_ring_t *)(a)
inline int BLKTAP_RING_FULL(blkif_generic_ring_t *ring);
#endif

/* -------[ interposition -> character device interface ]------------- */

/* /dev/xen/blktap resides at device number major=10, minor=202        */ 
#define BLKTAP_MINOR 202

/* size of the extra VMA area to map in attached pages. */
#define BLKTAP_VMA_PAGES BLKIF_RING_SIZE

/* blktap IOCTLs:                                                      */
#define BLKTAP_IOCTL_KICK_FE         1
#define BLKTAP_IOCTL_KICK_BE         2
#define BLKTAP_IOCTL_SETMODE         3
#define BLKTAP_IOCTL_PRINT_IDXS      100   

/* blktap switching modes: (Set with BLKTAP_IOCTL_SETMODE)             */
#define BLKTAP_MODE_PASSTHROUGH      0x00000000  /* default            */
#define BLKTAP_MODE_INTERCEPT_FE     0x00000001
#define BLKTAP_MODE_INTERCEPT_BE     0x00000002
#define BLKTAP_MODE_COPY_FE          0x00000004
#define BLKTAP_MODE_COPY_BE          0x00000008
#define BLKTAP_MODE_COPY_FE_PAGES    0x00000010
#define BLKTAP_MODE_COPY_BE_PAGES    0x00000020

#define BLKTAP_MODE_INTERPOSE \
           (BLKTAP_MODE_INTERCEPT_FE | BLKTAP_MODE_INTERCEPT_BE)

#define BLKTAP_MODE_COPY_BOTH \
           (BLKTAP_MODE_COPY_FE | BLKTAP_MODE_COPY_BE)

#define BLKTAP_MODE_COPY_BOTH_PAGES \
           (BLKTAP_MODE_COPY_FE_PAGES | BLKTAP_MODE_COPY_BE_PAGES)

static inline int BLKTAP_MODE_VALID(unsigned long arg)
{
    return (
        ( arg == BLKTAP_MODE_PASSTHROUGH  ) ||
        ( arg == BLKTAP_MODE_INTERCEPT_FE ) ||
        ( arg == BLKTAP_MODE_INTERCEPT_BE ) ||
        ( arg == BLKTAP_MODE_INTERPOSE    ) ||
        ( (arg & ~BLKTAP_MODE_COPY_FE_PAGES) == BLKTAP_MODE_COPY_FE ) ||
        ( (arg & ~BLKTAP_MODE_COPY_BE_PAGES) == BLKTAP_MODE_COPY_BE ) ||
        ( (arg & ~BLKTAP_MODE_COPY_BOTH_PAGES) == BLKTAP_MODE_COPY_BOTH )
        );
}







#define __BLKINT_H__
#endif
