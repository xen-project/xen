/******************************************************************************
 * domain_controller.h
 * 
 * Interface to server controller (e.g., 'xend'). This header file defines the 
 * interface that is shared with guest OSes.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __DOMAIN_CONTROLLER_H__
#define __DOMAIN_CONTROLLER_H__


#ifndef BASIC_START_INFO
#error "Xen header file hypervisor-if.h must already be included here."
#endif


/*
 * EXTENDED BOOTSTRAP STRUCTURE FOR NEW DOMAINS.
 */

typedef struct {
    BASIC_START_INFO;
    unsigned int domain_controller_evtchn;
} extended_start_info_t;


/*
 * CONTROLLER MESSAGING INTERFACE.
 */

typedef struct {
    u8 type;     /* echoed in response */
    u8 subtype;  /* echoed in response */
    u8 id;       /* echoed in response */
    u8 length;   /* number of bytes in 'msg' */
    unsigned char msg[60]; /* type-specific message data */
} control_msg_t;

#define CONTROL_RING_SIZE 8
typedef unsigned int CONTROL_RING_IDX;
#define MASK_CONTROL_IDX(_i) ((_i)&(CONTROL_RING_SIZE-1))

typedef struct {
    control_msg_t tx_ring[CONTROL_RING_SIZE]; /* guest-OS -> controller */
    control_msg_t rx_ring[CONTROL_RING_SIZE]; /* controller -> guest-OS */
    CONTROL_RING_IDX tx_req_prod, tx_resp_prod;
    CONTROL_RING_IDX rx_req_prod, rx_resp_prod;
} control_if_t;

/*
 * Top-level command types.
 */
#define CMSG_CONSOLE            0  /* Console               */
#define CMSG_BLKIF_BE           1  /* Block-device backend  */
#define CMSG_BLKIF_FE           2  /* Block-device frontend */

/*
 * Subtypes for console messages.
 */
#define CMSG_CONSOLE_DATA       0

/*
 * Subtypes for block-device messages.
 */
#define CMSG_BLKIF_BE_CREATE      0  /* Create a new block-device interface. */
#define CMSG_BLKIF_BE_DESTROY     1  /* Destroy a block-device interface.    */
#define CMSG_BLKIF_BE_VBD_CREATE  2  /* Create a new VBD for an interface.   */
#define CMSG_BLKIF_BE_VBD_DESTROY 3  /* Delete a VBD from an interface.      */
#define CMSG_BLKIF_BE_VBD_GROW    4  /* Append an extent to a given VBD.     */
#define CMSG_BLKIF_BE_VBD_SHRINK  5  /* Remove last extent from a given VBD. */

/*
 * Message request/response defintions for block-device messages.
 */

#define blkif_vdev_t   u16
#define blkif_pdev_t   u16
#define blkif_sector_t u64

typedef struct {
    blkif_pdev_t   device;
    blkif_sector_t sector_start;
    blkif_sector_t sector_length;
} blkif_extent_t;

/* Non-specific 'okay' return. */
#define BLKIF_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define BLKIF_STATUS_ERROR               1
/* The following are specific error returns. */
#define BLKIF_STATUS_INTERFACE_EXISTS    2
#define BLKIF_STATUS_INTERFACE_NOT_FOUND 3

/* This macro can be used to create an array of descriptive error strings. */
#define BLKIF_STATUS_ERRORS {    \
    "Okay",                      \
    "Non-specific error",        \
    "Interface already exists",  \
    "Interface not found" }

/* CMSG_BLKIF_CREATE */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   blkif_handle;      /* Domain-specific interface handle.   */
    unsigned int   evtchn;            /* Event channel for notifications.    */
    unsigned long  shmem_frame;       /* Page cont. shared comms window.     */
    /* OUT */
    unsigned int   status;
} blkif_create_t; 

/* CMSG_BLKIF_DESTROY */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify interface to be destroyed. */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    /* OUT */
    unsigned int   status;
} blkif_destroy_t; 

/* CMSG_BLKIF_VBD_CREATE */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id for this VBD. */
    int            readonly;          /* Non-zero -> VBD isn't writeable.    */
    /* OUT */
    unsigned int   status;
} blkif_vbd_create_t; 

/* CMSG_BLKIF_VBD_DESTROY */
typedef struct {
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id of the VBD.   */
    /* OUT */
    unsigned int   status;
} blkif_vbd_destroy_t; 

/* CMSG_BLKIF_VBD_GROW */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id of the VBD.   */
    blkif_extent_t extent;            /* Physical extent to append to VBD.   */
    /* OUT */
    unsigned int   status;
} blkif_vbd_grow_t; 

/* CMSG_BLKIF_VBD_SHRINK */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id of the VBD.   */
    /* OUT */
    unsigned int   status;
} blkif_vbd_shrink_t; 

#endif /* __DOMAIN_CONTROLLER_H__ */
