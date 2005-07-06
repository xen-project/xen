/******************************************************************************
 * domain_controller.h
 * 
 * Interface to server controller (e.g., 'xend'). This header file defines the 
 * interface that is shared with guest OSes.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __XEN_PUBLIC_IO_DOMAIN_CONTROLLER_H__
#define __XEN_PUBLIC_IO_DOMAIN_CONTROLLER_H__

#include "ring.h"

/*
 * CONTROLLER MESSAGING INTERFACE.
 */

typedef struct control_msg {
    u8 type;     /*  0: echoed in response */
    u8 subtype;  /*  1: echoed in response */
    u8 id;       /*  2: echoed in response */
    u8 length;   /*  3: number of bytes in 'msg' */
    u8 msg[60];  /*  4: type-specific message data */
} control_msg_t; /* 64 bytes */

/* These are used by the control message deferred ring. */
#define CONTROL_RING_SIZE 8
typedef u32 CONTROL_RING_IDX;
#define MASK_CONTROL_IDX(_i) ((_i)&(CONTROL_RING_SIZE-1))

/*
 * Generate control ring structures and types.
 *
 * CONTROL_RING_MEM is currently an 8-slot ring of ctrl_msg_t structs and
 * two 32-bit counters:  (64 * 8) + (2 * 4) = 520
 */
#define CONTROL_RING_MEM 520
DEFINE_RING_TYPES(ctrl, control_msg_t, control_msg_t);

typedef struct control_if {
    union {
        ctrl_sring_t tx_ring; /* guest -> controller  */
        char __x[CONTROL_RING_MEM];
    };
    union {
        ctrl_sring_t rx_ring; /* controller -> guest  */
        char __y[CONTROL_RING_MEM];
    };
} control_if_t;

/*
 * Top-level command types.
 */
#define CMSG_CONSOLE        0  /* Console                 */
#define CMSG_BLKIF_BE       1  /* Block-device backend    */
#define CMSG_BLKIF_FE       2  /* Block-device frontend   */
#define CMSG_NETIF_BE       3  /* Network-device backend  */
#define CMSG_NETIF_FE       4  /* Network-device frontend */
#define CMSG_SHUTDOWN       6  /* Shutdown messages       */
#define CMSG_MEM_REQUEST    7  /* Memory reservation reqs */
#define CMSG_USBIF_BE       8  /* USB controller backend  */
#define CMSG_USBIF_FE       9  /* USB controller frontend */
#define CMSG_VCPU_HOTPLUG  10  /* Hotplug VCPU messages   */
#define CMSG_DEBUG         11  /* PDB backend             */

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
#define CMSG_BLKIF_FE_INTERFACE_STATUS           0

/* Messages from guest to domain controller. */
#define CMSG_BLKIF_FE_DRIVER_STATUS             32
#define CMSG_BLKIF_FE_INTERFACE_CONNECT         33
#define CMSG_BLKIF_FE_INTERFACE_DISCONNECT      34
#define CMSG_BLKIF_FE_INTERFACE_QUERY           35

#ifndef blkif_vdev_t
#define blkif_vdev_t   u16
#endif
#define blkif_pdev_t   u32

/*
 * CMSG_BLKIF_FE_INTERFACE_STATUS:
 *  Notify a guest about a status change on one of its block interfaces.
 *  If the interface is DESTROYED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messages pending on the interface were dropped.
 */
#define BLKIF_INTERFACE_STATUS_CLOSED       0 /* Interface doesn't exist.    */
#define BLKIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define BLKIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
#define BLKIF_INTERFACE_STATUS_CHANGED      3 /* A device has been added or removed. */
typedef struct blkif_fe_interface_status {
    u32 handle;
    u32 status;
    u16 evtchn;    /* (only if status == BLKIF_INTERFACE_STATUS_CONNECTED). */
    domid_t domid; /* status != BLKIF_INTERFACE_STATUS_DESTROYED */
} blkif_fe_interface_status_t;

/*
 * CMSG_BLKIF_FE_DRIVER_STATUS:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 * 
 *  NB. The controller should not send an INTERFACE_STATUS_CHANGED message
 *  for interfaces that are active when it receives an UP notification. We
 *  expect that the frontend driver will query those interfaces itself.
 */
#define BLKIF_DRIVER_STATUS_DOWN   0
#define BLKIF_DRIVER_STATUS_UP     1
typedef struct blkif_fe_driver_status {
    /* IN */
    u32 status;        /* BLKIF_DRIVER_STATUS_??? */
    /* OUT */
    /* Driver should query interfaces [0..max_handle]. */
    u32 max_handle;
} blkif_fe_driver_status_t;

/*
 * CMSG_BLKIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct blkif_fe_interface_connect {
    u32      handle;
    memory_t shmem_frame;
    int      shmem_ref;
} blkif_fe_interface_connect_t;

/*
 * CMSG_BLKIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct blkif_fe_interface_disconnect {
    u32 handle;
} blkif_fe_interface_disconnect_t;

/*
 * CMSG_BLKIF_FE_INTERFACE_QUERY:
 */
typedef struct blkif_fe_interface_query {
    /* IN */
    u32 handle;
    /* OUT */
    u32 status;
    u16 evtchn;    /* (only if status == BLKIF_INTERFACE_STATUS_CONNECTED). */
    domid_t domid; /* status != BLKIF_INTERFACE_STATUS_DESTROYED */
} blkif_fe_interface_query_t;


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

/* Messages to domain controller. */
#define CMSG_BLKIF_BE_DRIVER_STATUS 32

/*
 * Message request/response definitions for block-device messages.
 */

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
#define BLKIF_BE_STATUS_PHYSDEV_NOT_FOUND   8
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
typedef struct blkif_be_create { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    u32        blkif_handle;  /* Domain-specific interface handle.   */
    /* OUT */
    u32        status;
} blkif_be_create_t;

/*
 * CMSG_BLKIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct blkif_be_destroy { 
    /* IN */
    domid_t    domid;         /* Identify interface to be destroyed. */
    u32        blkif_handle;  /* ...ditto...                         */
    /* OUT */
    u32        status;
} blkif_be_destroy_t;

/*
 * CMSG_BLKIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct blkif_be_connect {
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    u32        blkif_handle;  /* Domain-specific interface handle.   */
    memory_t   shmem_frame;   /* Page cont. shared comms window.     */
    int        shmem_ref;     /* Grant table reference.              */
    u32        evtchn;        /* Event channel for notifications.    */
    /* OUT */
    u32        status;
} blkif_be_connect_t;

/*
 * CMSG_BLKIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct blkif_be_disconnect { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    u32        blkif_handle;  /* Domain-specific interface handle.   */
    /* OUT */
    u32        status;
} blkif_be_disconnect_t;

/* CMSG_BLKIF_BE_VBD_CREATE */
typedef struct blkif_be_vbd_create {
    /* IN */
    domid_t    domid;         /* Identify blkdev interface.          */
    u32        blkif_handle;  /* ...ditto...                         */
    blkif_pdev_t pdevice;
    u32        dev_handle;    /* Extended device id field.           */
    blkif_vdev_t vdevice;     /* Interface-specific id for this VBD. */
    u16        readonly;      /* Non-zero -> VBD isn't writable.     */
    /* OUT */
    u32        status;
} blkif_be_vbd_create_t;

/* CMSG_BLKIF_BE_VBD_DESTROY */
typedef struct blkif_be_vbd_destroy {
    /* IN */
    domid_t    domid;         /* Identify blkdev interface.          */
    u32        blkif_handle;  /* ...ditto...                         */
    blkif_vdev_t vdevice;     /* Interface-specific id of the VBD.   */
    /* OUT */
    u32        status;
} blkif_be_vbd_destroy_t;

/*
 * CMSG_BLKIF_BE_DRIVER_STATUS:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the controller
 *  will automatically send DOWN notifications.
 */
typedef struct blkif_be_driver_status {
    u32        status;        /* BLKIF_DRIVER_STATUS_??? */
} blkif_be_driver_status_t;


/******************************************************************************
 * NETWORK-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_NETIF_FE_INTERFACE_STATUS   0

/* Messages from guest to domain controller. */
#define CMSG_NETIF_FE_DRIVER_STATUS             32
#define CMSG_NETIF_FE_INTERFACE_CONNECT         33
#define CMSG_NETIF_FE_INTERFACE_DISCONNECT      34
#define CMSG_NETIF_FE_INTERFACE_QUERY           35

/*
 * CMSG_NETIF_FE_INTERFACE_STATUS:
 *  Notify a guest about a status change on one of its network interfaces.
 *  If the interface is CLOSED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messgaes pending on the interface were dropped.
 */
#define NETIF_INTERFACE_STATUS_CLOSED       0 /* Interface doesn't exist.    */
#define NETIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define NETIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
#define NETIF_INTERFACE_STATUS_CHANGED      3 /* A device has been added or removed. */
typedef struct netif_fe_interface_status {
    u32        handle;
    u32        status;
    u16        evtchn; /* status == NETIF_INTERFACE_STATUS_CONNECTED */
    u8         mac[6]; /* status == NETIF_INTERFACE_STATUS_CONNECTED */
    domid_t    domid;  /* status != NETIF_INTERFACE_STATUS_DESTROYED */
} netif_fe_interface_status_t;

/*
 * CMSG_NETIF_FE_DRIVER_STATUS:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 * 
 *  NB. The controller should not send an INTERFACE_STATUS message
 *  for interfaces that are active when it receives an UP notification. We
 *  expect that the frontend driver will query those interfaces itself.
 */
#define NETIF_DRIVER_STATUS_DOWN   0
#define NETIF_DRIVER_STATUS_UP     1
typedef struct netif_fe_driver_status {
    /* IN */
    u32        status;        /* NETIF_DRIVER_STATUS_??? */
    /* OUT */
    /* Driver should query interfaces [0..max_handle]. */
    u32        max_handle;
} netif_fe_driver_status_t;

/*
 * CMSG_NETIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct netif_fe_interface_connect {
    u32        handle;
    memory_t   tx_shmem_frame;
    memory_t   rx_shmem_frame;
} netif_fe_interface_connect_t;

/*
 * CMSG_NETIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct netif_fe_interface_disconnect {
    u32        handle;
} netif_fe_interface_disconnect_t;

/*
 * CMSG_NETIF_FE_INTERFACE_QUERY:
 */
typedef struct netif_fe_interface_query {
    /* IN */
    u32        handle;
    /* OUT */
    u32        status;
    u16        evtchn; /* status == NETIF_INTERFACE_STATUS_CONNECTED */
    u8         mac[6]; /* status == NETIF_INTERFACE_STATUS_CONNECTED */
    domid_t    domid;  /* status != NETIF_INTERFACE_STATUS_DESTROYED */
} netif_fe_interface_query_t;


/******************************************************************************
 * NETWORK-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_NETIF_BE_CREATE      0  /* Create a new net-device interface. */
#define CMSG_NETIF_BE_DESTROY     1  /* Destroy a net-device interface.    */
#define CMSG_NETIF_BE_CONNECT     2  /* Connect i/f to remote driver.        */
#define CMSG_NETIF_BE_DISCONNECT  3  /* Disconnect i/f from remote driver.   */
#define CMSG_NETIF_BE_CREDITLIMIT 4  /* Limit i/f to a given credit limit. */

/* Messages to domain controller. */
#define CMSG_NETIF_BE_DRIVER_STATUS 32

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
typedef struct netif_be_create { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    u32        netif_handle;  /* Domain-specific interface handle.   */
    u8         mac[6];
    u8         be_mac[6];
    /* OUT */
    u32        status;
} netif_be_create_t;

/*
 * CMSG_NETIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct netif_be_destroy { 
    /* IN */
    domid_t    domid;         /* Identify interface to be destroyed. */
    u32        netif_handle;  /* ...ditto...                         */
    /* OUT */
    u32   status;
} netif_be_destroy_t;

/*
 * CMSG_NETIF_BE_CREDITLIMIT:
 *  Limit a virtual interface to "credit_bytes" bytes per "period_usec" 
 *  microseconds.  
 */
typedef struct netif_be_creditlimit { 
    /* IN */
    domid_t    domid;          /* Domain attached to new interface.   */
    u32        netif_handle;   /* Domain-specific interface handle.   */
    u32        credit_bytes;   /* Vifs credit of bytes per period.    */
    u32        period_usec;    /* Credit replenishment period.        */
    /* OUT */
    u32        status;
} netif_be_creditlimit_t;

/*
 * CMSG_NETIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct netif_be_connect { 
    /* IN */
    domid_t    domid;          /* Domain attached to new interface.   */
    u32        netif_handle;   /* Domain-specific interface handle.   */
    memory_t   tx_shmem_frame; /* Page cont. tx shared comms window.  */
    memory_t   rx_shmem_frame; /* Page cont. rx shared comms window.  */
    u16        evtchn;         /* Event channel for notifications.    */
    /* OUT */
    u32        status;
} netif_be_connect_t;

/*
 * CMSG_NETIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct netif_be_disconnect { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    u32        netif_handle;  /* Domain-specific interface handle.   */
    /* OUT */
    u32        status;
} netif_be_disconnect_t;

/*
 * CMSG_NETIF_BE_DRIVER_STATUS:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically send DOWN notifications.
 */
typedef struct netif_be_driver_status {
    u32        status;        /* NETIF_DRIVER_STATUS_??? */
} netif_be_driver_status_t;



/******************************************************************************
 * USB-INTERFACE FRONTEND DEFINITIONS
 */

/* Messages from domain controller to guest. */
#define CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED   0

/* Messages from guest to domain controller. */
#define CMSG_USBIF_FE_DRIVER_STATUS_CHANGED     32
#define CMSG_USBIF_FE_INTERFACE_CONNECT         33
#define CMSG_USBIF_FE_INTERFACE_DISCONNECT      34
/*
 * CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED:
 *  Notify a guest about a status change on one of its block interfaces.
 *  If the interface is DESTROYED or DOWN then the interface is disconnected:
 *   1. The shared-memory frame is available for reuse.
 *   2. Any unacknowledged messages pending on the interface were dropped.
 */
#define USBIF_INTERFACE_STATUS_DESTROYED    0 /* Interface doesn't exist.    */
#define USBIF_INTERFACE_STATUS_DISCONNECTED 1 /* Exists but is disconnected. */
#define USBIF_INTERFACE_STATUS_CONNECTED    2 /* Exists and is connected.    */
typedef struct usbif_fe_interface_status_changed {
    u32 status;
    u16 evtchn;    /* (only if status == BLKIF_INTERFACE_STATUS_CONNECTED). */
    domid_t domid; /* status != BLKIF_INTERFACE_STATUS_DESTROYED */
    u32 bandwidth;
    u32 num_ports;
} usbif_fe_interface_status_changed_t;

/*
 * CMSG_USBIF_FE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the front-end driver is DOWN or UP.
 *  When the driver goes DOWN then the controller will send no more
 *  status-change notifications.
 *  If the driver goes DOWN while interfaces are still UP, the domain
 *  will automatically take the interfaces DOWN.
 * 
 *  NB. The controller should not send an INTERFACE_STATUS_CHANGED message
 *  for interfaces that are active when it receives an UP notification. We
 *  expect that the frontend driver will query those interfaces itself.
 */
#define USBIF_DRIVER_STATUS_DOWN   0
#define USBIF_DRIVER_STATUS_UP     1
typedef struct usbif_fe_driver_status_changed {
    /* IN */
    u32 status;        /* USBIF_DRIVER_STATUS_??? */
} usbif_fe_driver_status_changed_t;

/*
 * CMSG_USBIF_FE_INTERFACE_CONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_CONNECTED message.
 */
typedef struct usbif_fe_interface_connect {
    memory_t shmem_frame;
} usbif_fe_interface_connect_t;

/*
 * CMSG_BLKIF_FE_INTERFACE_DISCONNECT:
 *  If successful, the domain controller will acknowledge with a
 *  STATUS_DISCONNECTED message.
 */
typedef struct usbif_fe_interface_disconnect {
} usbif_fe_interface_disconnect_t;


/******************************************************************************
 * USB-INTERFACE BACKEND DEFINITIONS
 */

/* Messages from domain controller. */
#define CMSG_USBIF_BE_CREATE       0  /* Create a new block-device interface. */
#define CMSG_USBIF_BE_DESTROY      1  /* Destroy a block-device interface.    */
#define CMSG_USBIF_BE_CONNECT      2  /* Connect i/f to remote driver.        */
#define CMSG_USBIF_BE_DISCONNECT   3  /* Disconnect i/f from remote driver.   */
#define CMSG_USBIF_BE_CLAIM_PORT   4  /* Claim host port for a domain.        */
#define CMSG_USBIF_BE_RELEASE_PORT 5  /* Release host port.                   */
/* Messages to domain controller. */
#define CMSG_USBIF_BE_DRIVER_STATUS_CHANGED 32

/* Non-specific 'okay' return. */
#define USBIF_BE_STATUS_OKAY                0
/* Non-specific 'error' return. */
#define USBIF_BE_STATUS_ERROR               1
/* The following are specific error returns. */
#define USBIF_BE_STATUS_INTERFACE_EXISTS    2
#define USBIF_BE_STATUS_INTERFACE_NOT_FOUND 3
#define USBIF_BE_STATUS_INTERFACE_CONNECTED 4
#define USBIF_BE_STATUS_OUT_OF_MEMORY       7
#define USBIF_BE_STATUS_MAPPING_ERROR       9

/* This macro can be used to create an array of descriptive error strings. */
#define USBIF_BE_STATUS_ERRORS {    \
    "Okay",                         \
    "Non-specific error",           \
    "Interface already exists",     \
    "Interface not found",          \
    "Interface is still connected", \
    "Out of memory",                \
    "Could not map domain memory" }

/*
 * CMSG_USBIF_BE_CREATE:
 *  When the driver sends a successful response then the interface is fully
 *  created. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct usbif_be_create { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    /* OUT */
    u32        status;
} usbif_be_create_t;

/*
 * CMSG_USBIF_BE_DESTROY:
 *  When the driver sends a successful response then the interface is fully
 *  torn down. The controller will send a DESTROYED notification to the
 *  front-end driver.
 */
typedef struct usbif_be_destroy { 
    /* IN */
    domid_t    domid;         /* Identify interface to be destroyed. */
    /* OUT */
    u32        status;
} usbif_be_destroy_t;

/*
 * CMSG_USBIF_BE_CONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  connected. The controller will send a CONNECTED notification to the
 *  front-end driver.
 */
typedef struct usbif_be_connect { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    memory_t   shmem_frame;   /* Page cont. shared comms window.     */
    u32        evtchn;        /* Event channel for notifications.    */
    u32        bandwidth;     /* Bandwidth allocated for isoch / int - us
                               * per 1ms frame (ie between 0 and 900 or 800
                               * depending on USB version). */
    /* OUT */
    u32        status;
} usbif_be_connect_t;

/*
 * CMSG_USBIF_BE_DISCONNECT:
 *  When the driver sends a successful response then the interface is fully
 *  disconnected. The controller will send a DOWN notification to the front-end
 *  driver.
 */
typedef struct usbif_be_disconnect { 
    /* IN */
    domid_t    domid;         /* Domain attached to new interface.   */
    /* OUT */
    u32        status;
} usbif_be_disconnect_t;

/*
 * CMSG_USBIF_BE_DRIVER_STATUS_CHANGED:
 *  Notify the domain controller that the back-end driver is DOWN or UP.
 *  If the driver goes DOWN while interfaces are still UP, the controller
 *  will automatically send DOWN notifications.
 */
typedef struct usbif_be_driver_status_changed {
    u32        status;        /* USBIF_DRIVER_STATUS_??? */
} usbif_be_driver_status_changed_t;

#define USB_PATH_LEN 16

/*
 * CMSG_USBIF_BE_CLAIM_PORT:
 * Instruct the backend driver to claim any device plugged into the specified
 * host port and to allow the specified domain to control that port.
 */
typedef struct usbif_be_claim_port {
    /* IN */
    domid_t  domid;        /* which domain                 */
    u32      usbif_port;   /* port on the virtual root hub */
    u32      status;       /* status of operation          */
    char path[USB_PATH_LEN]; /* Currently specified in the Linux style - may need to be
                    * converted to some OS-independent format at some stage. */
} usbif_be_claim_port_t;

/*
 * CMSG_USBIF_BE_RELEASE_PORT: 
 * Instruct the backend driver to release any device plugged into the specified
 * host port.
 */
typedef struct usbif_be_release_port {
    char     path[USB_PATH_LEN];
} usbif_be_release_port_t;

/******************************************************************************
 * SHUTDOWN DEFINITIONS
 */

/*
 * Subtypes for shutdown messages.
 */
#define CMSG_SHUTDOWN_POWEROFF  0   /* Clean shutdown (SHUTDOWN_poweroff).   */
#define CMSG_SHUTDOWN_REBOOT    1   /* Clean shutdown (SHUTDOWN_reboot).     */
#define CMSG_SHUTDOWN_SUSPEND   2   /* Create suspend info, then             */
                                    /* SHUTDOWN_suspend.                     */
#define CMSG_SHUTDOWN_SYSRQ     3

typedef struct shutdown_sysrq {
    char key;      /* sysrq key */
} shutdown_sysrq_t;

/******************************************************************************
 * VCPU HOTPLUG CONTROLS
 */

/*
 * Subtypes for shutdown messages.
 */
#define CMSG_VCPU_HOTPLUG_OFF   0   /* turn vcpu off */
#define CMSG_VCPU_HOTPLUG_ON    1   /* turn vcpu on  */

/*
 * CMSG_VCPU_HOTPLUG:
 *  Indicate which vcpu's state should change
 */
typedef struct vcpu_hotplug {
    u32 vcpu;         /* VCPU's whose state will change */
    u32 status;       /* Return code indicates success or failure. */
} vcpu_hotplug_t;

/******************************************************************************
 * MEMORY CONTROLS
 */

#define CMSG_MEM_REQUEST_SET 0 /* Request a domain to set its mem footprint. */

/*
 * CMSG_MEM_REQUEST:
 *  Request that the domain change its memory reservation.
 */
typedef struct mem_request {
    /* OUT */
    u32 target;       /* Target memory reservation in pages.       */
    /* IN  */
    u32 status;       /* Return code indicates success or failure. */
} mem_request_t;


/******************************************************************************
 * PDB INTERFACE DEFINITIONS
 */

#define CMSG_DEBUG_CONNECTION_STATUS 0
typedef struct pdb_Connection {
#define PDB_CONNECTION_STATUS_UP   1
#define PDB_CONNECTION_STATUS_DOWN 2
    u32      status;
    memory_t ring;       /* status: UP */
    u32      evtchn;     /* status: UP */
} pdb_connection_t, *pdb_connection_p;

#endif /* __XEN_PUBLIC_IO_DOMAIN_CONTROLLER_H__ */
