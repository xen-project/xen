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

#define CMSG_CONSOLE      0
#define CMSG_CONSOLE_DATA 0


#endif /* __DOMAIN_CONTROLLER_H__ */
