/******************************************************************************
 * netif.h
 * 
 * Unified network-device I/O interface for Xen guest OSes.
 * 
 * Copyright (c) 2003-2004, Keir Fraser
 */

#ifndef __XEN_PUBLIC_IO_NETIF_H__
#define __XEN_PUBLIC_IO_NETIF_H__

#include "ring.h"

typedef struct netif_tx_request {
    grant_ref_t gref;      /* Reference to buffer page */
    uint16_t offset:15;    /* Offset within buffer page */
    uint16_t csum_blank:1; /* Proto csum field blank?   */
    uint16_t id;           /* Echoed in response message. */
    uint16_t size;         /* Packet size in bytes.       */
} netif_tx_request_t;

typedef struct netif_tx_response {
    uint16_t id;
    int8_t   status;
} netif_tx_response_t;

typedef struct {
    uint16_t    id;        /* Echoed in response message.        */
    grant_ref_t gref;      /* Reference to incoming granted frame */
} netif_rx_request_t;

typedef struct {
    uint16_t offset;     /* Offset in page of start of received packet  */
    uint16_t csum_valid; /* Protocol checksum is validated?       */
    uint16_t id;
    int16_t  status;     /* -ve: BLKIF_RSP_* ; +ve: Rx'ed pkt size. */
} netif_rx_response_t;

/*
 * Generate netif ring structures and types.
 */

DEFINE_RING_TYPES(netif_tx, netif_tx_request_t, netif_tx_response_t);
DEFINE_RING_TYPES(netif_rx, netif_rx_request_t, netif_rx_response_t);

#define NETIF_RSP_DROPPED         -2
#define NETIF_RSP_ERROR           -1
#define NETIF_RSP_OKAY             0

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
