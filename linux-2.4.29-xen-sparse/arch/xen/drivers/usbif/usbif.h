/******************************************************************************
 * usbif.h
 * 
 * Unified block-device I/O interface for Xen guest OSes.
 * 
 * Copyright (c) 2003-2004, Keir Fraser
 */

#ifndef __SHARED_USBIF_H__
#define __SHARED_USBIF_H__

#define usbif_vdev_t   u16
#define usbif_sector_t u64

#define USBIF_OP_IO      0
#define USBIF_OP_PROBE   1 /* Is there a device on this port? */
#define USBIF_OP_RESET   2 /* Reset a virtual USB port.       */

/* NB. Ring size must be small enough for sizeof(usbif_ring_t) <= PAGE_SIZE. */
#define USBIF_RING_SIZE        64

/* XXX this does not want to be here!  it really ought to be dynamic but it can
 * live here for now */
#define NUM_PORTS 1

typedef struct {
    unsigned long  id;           /*  0: private guest value, echoed in resp  */
    u8             operation;    /*  4: USBIF_OP_???                         */
    u8  __pad1;
    usbif_vdev_t   port;         /* 6 : guest virtual USB port               */
    unsigned long  devnum :7;    /* 8 : Device address, as seen by the guest.*/
    unsigned long  endpoint :4;  /* Device endpoint.                         */
    unsigned long  direction :1; /* Pipe direction.                          */
    unsigned long  speed :1;     /* Pipe speed.                              */
    unsigned long  pipe_type :2; /* Pipe type (iso, bulk, int, ctrl)         */
    unsigned long  __pad2 :18;
    unsigned long  transfer_buffer; /* 12: Machine address */
    unsigned long  length;          /* 16: Buffer length */
    unsigned long  transfer_flags;  /* 20: For now just pass Linux transfer
                                     * flags - this may change. */
    unsigned char setup[8];         /* 22 Embed setup packets directly. */
    unsigned long  iso_schedule;    /* 30 Machine address of transfer sched (iso
                                     * only) */
    unsigned long num_iso;        /* 34 : length of iso schedule */
    unsigned long timeout;        /* 38: timeout in ms */
} PACKED usbif_request_t; /* 42 */
/* Data we need to pass:
 * - Transparently handle short packets or complain at us?
 */

typedef struct {
    unsigned long   id;              /* 0: copied from request         */
    u8              operation;       /* 4: copied from request         */
    u8              data;            /* 5: Small chunk of in-band data */
    s16             status;          /* 6: USBIF_RSP_???               */
    unsigned long   transfer_mutex;  /* Used for cancelling requests atomically. */
    unsigned long    length;          /* 8: How much data we really got */
} PACKED usbif_response_t;

#define USBIF_RSP_ERROR  -1 /* non-specific 'error' */
#define USBIF_RSP_OKAY    0 /* non-specific 'okay'  */

/*
 * We use a special capitalised type name because it is _essential_ that all 
 * arithmetic on indexes is done on an integer type of the correct size.
 */
typedef u32 USBIF_RING_IDX;

/*
 * Ring indexes are 'free running'. That is, they are not stored modulo the
 * size of the ring buffer. The following macro converts a free-running counter
 * into a value that can directly index a ring-buffer array.
 */
#define MASK_USBIF_IDX(_i) ((_i)&(USBIF_RING_SIZE-1))

typedef struct {
    USBIF_RING_IDX req_prod;  /*  0: Request producer. Updated by front-end. */
    USBIF_RING_IDX resp_prod; /*  4: Response producer. Updated by back-end. */

    union {                   /*  8 */
        usbif_request_t  req;
        usbif_response_t resp;
    } PACKED ring[USBIF_RING_SIZE];
} PACKED usbif_t;



/*
 * USBIF_OP_PROBE:
 * The request format for a probe request is constrained as follows:
 *  @operation   == USBIF_OP_PROBE
 *  @nr_segments == size of probe buffer in pages
 *  @device      == unused (zero)
 *  @id          == any value (echoed in response message)
 *  @sector_num  == unused (zero)
 *  @frame_and_sects == list of page-sized buffers.
 *                       (i.e., @first_sect == 0, @last_sect == 7).
 * 
 * The response is a list of vdisk_t elements copied into the out-of-band
 * probe buffer. On success the response status field contains the number
 * of vdisk_t elements.
 */

typedef struct {
    unsigned long length; /* IN = expected, OUT = actual */
    unsigned long buffer_offset;  /* IN offset in buffer specified in main
                                     packet */
    unsigned long status; /* OUT Status for this packet. */
} usbif_iso_t;

#endif /* __SHARED_USBIF_H__ */
