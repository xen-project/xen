/******************************************************************************
 * control_if.h
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __CONTROL_IF_H__
#define __CONTROL_IF_H__

typedef struct {
    u8 cmd_type;     /* echoed in response */
    u8 cmd_subtype;  /* echoed in response */
    u8 id;           /* echoed in response */
    u8 length;       /* number of bytes in 'msg' */
    unsigned char msg[60]; /* command-specific message data */
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

#define CMD_CONSOLE      0
#define CMD_CONSOLE_DATA 0

#endif /* __CONTROL_IF_H__ */
