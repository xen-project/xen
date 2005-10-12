/******************************************************************************
 * netif.h
 * 
 * Unified network-device I/O interface for Xen guest OSes.
 * 
 * Copyright (c) 2003-2004, Keir Fraser
 */

#ifndef __XEN_PUBLIC_IO_NETIF_H__
#define __XEN_PUBLIC_IO_NETIF_H__

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
 * We use a special capitalised type name because it is _essential_ that all 
 * arithmetic on indexes is done on an integer type of the correct size.
 */
typedef uint32_t NETIF_RING_IDX;

/*
 * Ring indexes are 'free running'. That is, they are not stored modulo the
 * size of the ring buffer. The following macros convert a free-running counter
 * into a value that can directly index a ring-buffer array.
 */
#define MASK_NETIF_RX_IDX(_i) ((_i)&(NETIF_RX_RING_SIZE-1))
#define MASK_NETIF_TX_IDX(_i) ((_i)&(NETIF_TX_RING_SIZE-1))

#define NETIF_TX_RING_SIZE 256
#define NETIF_RX_RING_SIZE 256

/* This structure must fit in a memory page. */
typedef struct netif_tx_interface {
    /*
     * Frontend places packets into ring at tx_req_prod.
     * Frontend receives event when tx_resp_prod passes tx_event.
     * 'req_cons' is a shadow of the backend's request consumer -- the frontend
     * may use it to determine if all queued packets have been seen by the
     * backend.
     */
    NETIF_RING_IDX req_prod;
    NETIF_RING_IDX req_cons;
    NETIF_RING_IDX resp_prod;
    NETIF_RING_IDX event;
    union {
        netif_tx_request_t  req;
        netif_tx_response_t resp;
    } ring[NETIF_TX_RING_SIZE];
} netif_tx_interface_t;

/* This structure must fit in a memory page. */
typedef struct netif_rx_interface {
    /*
     * Frontend places empty buffers into ring at rx_req_prod.
     * Frontend receives event when rx_resp_prod passes rx_event.
     */
    NETIF_RING_IDX req_prod;
    NETIF_RING_IDX resp_prod;
    NETIF_RING_IDX event;
    union {
        netif_rx_request_t  req;
        netif_rx_response_t resp;
    } ring[NETIF_RX_RING_SIZE];
} netif_rx_interface_t;

/* Descriptor status values */
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
