/******************************************************************************
 * network.h
 *
 * ring data structures for buffering messages between hypervisor and
 * guestos's.  As it stands this is only used for network buffer exchange.
 *
 * This file also contains structures and interfaces for the per-domain
 * routing/filtering tables in the hypervisor.
 *
 */

#ifndef __RING_H__
#define __RING_H__

#include <linux/types.h>


typedef struct tx_req_entry_st
{
    unsigned long  id;
    unsigned long  addr;   /* machine address of packet */
    unsigned short size;   /* packet size in bytes */
} tx_req_entry_t;

typedef struct tx_resp_entry_st
{
    unsigned long  id;
    unsigned char  status;
} tx_resp_entry_t;

typedef union tx_entry_st
{
    tx_req_entry_t  req;
    tx_resp_entry_t resp;
} tx_entry_t;


typedef struct rx_req_entry_st
{
    unsigned long  id;
    unsigned long  addr;   /* machine address of PTE to swizzle */
} rx_req_entry_t;

typedef struct rx_resp_entry_st
{
    unsigned long  id;
    unsigned short size;   /* received packet size in bytes */
    unsigned char  status; /* per descriptor status */
    unsigned char  offset; /* offset in page of received pkt */
} rx_resp_entry_t;

typedef union rx_entry_st
{
    rx_req_entry_t  req;
    rx_resp_entry_t resp;
} rx_entry_t;


#define TX_RING_SIZE 256
#define RX_RING_SIZE 256

typedef struct net_ring_st
{
    /*
     * Guest OS places packets into ring at tx_req_prod.
     * Guest OS receives DOMAIN_EVENT_NET_TX when tx_resp_prod passes tx_event.
     */
    tx_entry_t	*tx_ring;
    unsigned int tx_req_prod, tx_resp_prod, tx_event;

    /*
     * Guest OS places empty buffers into ring at rx_req_prod.
     * Guest OS receives DOMAIN_EVENT_NET_RX when rx_rssp_prod passes rx_event.
     */
    rx_entry_t	*rx_ring;
    unsigned int rx_req_prod, rx_resp_prod, rx_event;
} net_ring_t;

/*
 * Packet routing/filtering code follows:
 */

#define NETWORK_ACTION_ACCEPT   0
#define NETWORK_ACTION_COUNT    1

#define NETWORK_PROTO_ANY       0
#define NETWORK_PROTO_IP        1
#define NETWORK_PROTO_TCP       2
#define NETWORK_PROTO_UDP       3
#define NETWORK_PROTO_ARP       4

typedef struct net_rule_st 
{
    u32  src_addr;
    u32  dst_addr;
    u16  src_port;
    u16  dst_port;
    u32  src_addr_mask;
    u32  dst_addr_mask;
    u16  src_port_mask;
    u16  dst_port_mask;
    u16  proto;
    
    int  src_interface;
    int  dst_interface;
    u16  action;
} net_rule_t;

typedef struct vif_query_st
{
    unsigned int    domain;
    char            *buf;   /* reply buffer -- guest virtual address */
} vif_query_t;

/* Network trap operations and associated structure. 
 * This presently just handles rule insertion and deletion, but will
 * evenually have code to add and remove interfaces.
 */

#define NETWORK_OP_ADDRULE      0
#define NETWORK_OP_DELETERULE   1
#define NETWORK_OP_GETRULELIST  2
#define NETWORK_OP_VIFQUERY     3

typedef struct network_op_st 
{
    unsigned long cmd;
    union
    {
        net_rule_t net_rule;
        vif_query_t vif_query;
    }
    u;
} network_op_t;

typedef struct net_rule_ent_st
{
    net_rule_t r;
    struct net_rule_ent_st *next;
} net_rule_ent_t;

/* Drop a new rule down to the network tables. */
int add_net_rule(net_rule_t *rule);

/* Descriptor status values */
#define RING_STATUS_OK               0  /* Everything is gravy. */
#define RING_STATUS_ERR_CFU          1  /* Copy from user problems. */
#define RING_STATUS_BAD_PAGE         2  /* What they gave us was pure evil */

#endif
