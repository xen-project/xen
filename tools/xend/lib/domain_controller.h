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
#define CMSG_CONSOLE        0  /* Console                 */
#define CMSG_BLKIF_BE       1  /* Block-device backend    */
#define CMSG_BLKIF_FE       2  /* Block-device frontend   */
#define CMSG_NETIF_BE       3  /* Network-device backend  */
#define CMSG_NETIF_FE       4  /* Network-device frontend */


/******************************************************************************
 * CONSOLE DEFINITIONS
 */

/*
 * Subtypes for console messages.
 */
#define CMSG_CONSOLE_DATA       0


/******************************************************************************
 * BLOCK-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED   0

/* Messages from guest to domain controller. */
#define CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED     32
#define CMSG_BLKIF_FE_INTERFACE_CONNECT         33
#define CMSG_BLKIF_FE_INTERFACE_DISCONNECT      34

/* These are used by both front-end and back-end drivers. */
#define blkif_vdev_t   u16
#define blkif_pdev_t   u16
#define blkif_sector_t u64

/*
 * CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED:
 *  Notify a guest about a status change on one of its block interfaces.
 *  If the interface is DESTROYED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messgaes pending on the interface were dropped.
 */
#define BLKIF_INTERFACE_STATUS_DESTROYED    0 /* Interface doesn't exist.    */
#define BLKIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define BLKIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
typedef struct {
    unsigned int handle;
    unsigned int status;
    unsigned int evtchn; /* status == BLKIF_INTERFACE_STATUS_CONNECTED */
} blkif_fe_interface_status_changed_t;

/*
 * CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications. When the driver comes UP then the controller
 *  will send a notification for each interface that currently exists.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 */
#define BLKIF_DRIVER_STATUS_DOWN   0
#define BLKIF_DRIVER_STATUS_UP     1
typedef struct {
    /* IN */
    unsigned int status; /* BLKIF_DRIVER_STATUS_??? */
    /* OUT */
    /*
     * Tells driver how many interfaces it should expect to immediately
     * receive notifications about.
     */
    unsigned int nr_interfaces;
} blkif_fe_driver_status_changed_t;

/*
 * CMSG_BLKIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct {
    unsigned int  handle;
    unsigned long shmem_frame;
} blkif_fe_interface_connect_t;

/*
 * CMSG_BLKIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct {
    unsigned int handle;
} blkif_fe_interface_disconnect_t;


/******************************************************************************
 * BLOCK-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_BLKIF_BE_CREATE      0  /* Create a new block-device interface. */
#define CMSG_BLKIF_BE_DESTROY     1  /* Destroy a block-device interface.    */
#define CMSG_BLKIF_BE_CONNECT     2  /* Connect i/f to remote driver.        */
#define CMSG_BLKIF_BE_DISCONNECT  3  /* Disconnect i/f from remote driver.   */
#define CMSG_BLKIF_BE_VBD_CREATE  4  /* Create a new VBD for an interface.   */
#define CMSG_BLKIF_BE_VBD_DESTROY 5  /* Delete a VBD from an interface.      */
#define CMSG_BLKIF_BE_VBD_GROW    6  /* Append an extent to a given VBD.     */
#define CMSG_BLKIF_BE_VBD_SHRINK  7  /* Remove last extent from a given VBD. */

/* Messages to domain controller. */
#define CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED 32

/*
 * Message request/response definitions for block-device messages.
 */

typedef struct {
    blkif_pdev_t   device;
    blkif_sector_t sector_start;
    blkif_sector_t sector_length;
} blkif_extent_t;

/* Non-specific 'okay' return. */
#define BLKIF_BE_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define BLKIF_BE_STATUS_ERROR               1
/* The following are specific error returns. */
#define BLKIF_BE_STATUS_INTERFACE_EXISTS    2
#define BLKIF_BE_STATUS_INTERFACE_NOT_FOUND 3
#define BLKIF_BE_STATUS_INTERFACE_CONNECTED 4
#define BLKIF_BE_STATUS_VBD_EXISTS          5
#define BLKIF_BE_STATUS_VBD_NOT_FOUND       6
#define BLKIF_BE_STATUS_OUT_OF_MEMORY       7
#define BLKIF_BE_STATUS_EXTENT_NOT_FOUND    8
#define BLKIF_BE_STATUS_MAPPING_ERROR       9

/* This macro can be used to create an array of descriptive error strings. */
#define BLKIF_BE_STATUS_ERRORS {    \
    "Okay",                         \
    "Non-specific error",           \
    "Interface already exists",     \
    "Interface not found",          \
    "Interface is still connected", \
    "VBD already exists",           \
    "VBD not found",                \
    "Out of memory",                \
    "Extent not found for VBD",     \
    "Could not map domain memory" }

/*
 * CMSG_BLKIF_BE_CREATE:
 *  When the driver sends a successful response then the interface is fully
 *  created. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   blkif_handle;      /* Domain-specific interface handle.   */
    /* OUT */
    unsigned int   status;
} blkif_be_create_t; 

/*
 * CMSG_BLKIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify interface to be destroyed. */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    /* OUT */
    unsigned int   status;
} blkif_be_destroy_t; 

/*
 * CMSG_BLKIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   blkif_handle;      /* Domain-specific interface handle.   */
    unsigned int   evtchn;            /* Event channel for notifications.    */
    unsigned long  shmem_frame;       /* Page cont. shared comms window.     */
    /* OUT */
    unsigned int   status;
} blkif_be_connect_t; 

/*
 * CMSG_BLKIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   blkif_handle;      /* Domain-specific interface handle.   */
    /* OUT */
    unsigned int   status;
} blkif_be_disconnect_t; 

/* CMSG_BLKIF_BE_VBD_CREATE */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id for this VBD. */
    int            readonly;          /* Non-zero -> VBD isn't writeable.    */
    /* OUT */
    unsigned int   status;
} blkif_be_vbd_create_t; 

/* CMSG_BLKIF_BE_VBD_DESTROY */
typedef struct {
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id of the VBD.   */
    /* OUT */
    unsigned int   status;
} blkif_be_vbd_destroy_t; 

/* CMSG_BLKIF_BE_VBD_GROW */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id of the VBD.   */
    blkif_extent_t extent;            /* Physical extent to append to VBD.   */
    /* OUT */
    unsigned int   status;
} blkif_be_vbd_grow_t; 

/* CMSG_BLKIF_BE_VBD_SHRINK */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify blkdev interface.          */
    unsigned int   blkif_handle;      /* ...ditto...                         */
    blkif_vdev_t   vdevice;           /* Interface-specific id of the VBD.   */
    /* OUT */
    unsigned int   status;
} blkif_be_vbd_shrink_t; 

/*
 * CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically send DOWN notifications.
 */
typedef struct {
    /* IN */
    unsigned int status; /* BLKIF_DRIVER_STATUS_??? */
    /* OUT */
    /*
     * Tells driver how many interfaces it should expect to immediately
     * receive notifications about.
     */
    unsigned int nr_interfaces;
} blkif_be_driver_status_changed_t;


/******************************************************************************
 * NETWORK-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED   0

/* Messages from guest to domain controller. */
#define CMSG_NETIF_FE_DRIVER_STATUS_CHANGED     32
#define CMSG_NETIF_FE_INTERFACE_CONNECT         33
#define CMSG_NETIF_FE_INTERFACE_DISCONNECT      34

/*
 * CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED:
 *  Notify a guest about a status change on one of its network interfaces.
 *  If the interface is DESTROYED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messgaes pending on the interface were dropped.
 */
#define NETIF_INTERFACE_STATUS_DESTROYED    0 /* Interface doesn't exist.    */
#define NETIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define NETIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
typedef struct {
    unsigned int handle;
    unsigned int status;
    unsigned int evtchn; /* status == NETIF_INTERFACE_STATUS_CONNECTED */
    u8           mac[6]; /* status == NETIF_INTERFACE_STATUS_CONNECTED */
} netif_fe_interface_status_changed_t;

/*
 * CMSG_NETIF_FE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications. When the driver comes UP then the controller
 *  will send a notification for each interface that currently exists.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 */
#define NETIF_DRIVER_STATUS_DOWN   0
#define NETIF_DRIVER_STATUS_UP     1
typedef struct {
    /* IN */
    unsigned int status; /* NETIF_DRIVER_STATUS_??? */
    /* OUT */
    /*
     * Tells driver how many interfaces it should expect to immediately
     * receive notifications about.
     */
    unsigned int nr_interfaces;
} netif_fe_driver_status_changed_t;

/*
 * CMSG_NETIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct {
    unsigned int  handle;
    unsigned long tx_shmem_frame;
    unsigned long rx_shmem_frame;
} netif_fe_interface_connect_t;

/*
 * CMSG_NETIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct {
    unsigned int handle;
} netif_fe_interface_disconnect_t;


/******************************************************************************
 * NETWORK-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_NETIF_BE_CREATE      0  /* Create a new net-device interface. */
#define CMSG_NETIF_BE_DESTROY     1  /* Destroy a net-device interface.    */
#define CMSG_NETIF_BE_CONNECT     2  /* Connect i/f to remote driver.        */
#define CMSG_NETIF_BE_DISCONNECT  3  /* Disconnect i/f from remote driver.   */

/* Messages to domain controller. */
#define CMSG_NETIF_BE_DRIVER_STATUS_CHANGED 32

/*
 * Message request/response definitions for net-device messages.
 */

/* Non-specific 'okay' return. */
#define NETIF_BE_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define NETIF_BE_STATUS_ERROR               1
/* The following are specific error returns. */
#define NETIF_BE_STATUS_INTERFACE_EXISTS    2
#define NETIF_BE_STATUS_INTERFACE_NOT_FOUND 3
#define NETIF_BE_STATUS_INTERFACE_CONNECTED 4
#define NETIF_BE_STATUS_OUT_OF_MEMORY       5
#define NETIF_BE_STATUS_MAPPING_ERROR       6

/* This macro can be used to create an array of descriptive error strings. */
#define NETIF_BE_STATUS_ERRORS {    \
    "Okay",                         \
    "Non-specific error",           \
    "Interface already exists",     \
    "Interface not found",          \
    "Interface is still connected", \
    "Out of memory",                \
    "Could not map domain memory" }

/*
 * CMSG_NETIF_BE_CREATE:
 *  When the driver sends a successful response then the interface is fully
 *  created. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   netif_handle;      /* Domain-specific interface handle.   */
    u8             mac[6];
    /* OUT */
    unsigned int   status;
} netif_be_create_t; 

/*
 * CMSG_NETIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Identify interface to be destroyed. */
    unsigned int   netif_handle;      /* ...ditto...                         */
    /* OUT */
    unsigned int   status;
} netif_be_destroy_t; 

/*
 * CMSG_NETIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   netif_handle;      /* Domain-specific interface handle.   */
    unsigned int   evtchn;            /* Event channel for notifications.    */
    unsigned long  tx_shmem_frame;    /* Page cont. tx shared comms window.  */
    unsigned long  rx_shmem_frame;    /* Page cont. rx shared comms window.  */
    unsigned long  shmem_frame;       
    /* OUT */
    unsigned int   status;
} netif_be_connect_t; 

/*
 * CMSG_NETIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct { 
    /* IN */
    domid_t        domid;             /* Domain attached to new interface.   */
    unsigned int   netif_handle;      /* Domain-specific interface handle.   */
    /* OUT */
    unsigned int   status;
} netif_be_disconnect_t; 

/*
 * CMSG_NETIF_BE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically send DOWN notifications.
 */
typedef struct {
    /* IN */
    unsigned int status; /* NETIF_DRIVER_STATUS_??? */
    /* OUT */
    /*
     * Tells driver how many interfaces it should expect to immediately
     * receive notifications about.
     */
    unsigned int nr_interfaces;
} netif_be_driver_status_changed_t;

#endif /* __DOMAIN_CONTROLLER_H__ */
