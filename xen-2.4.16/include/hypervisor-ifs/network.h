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

typedef struct tx_entry_st {
	unsigned long addr;   /* virtual address */
	unsigned long size;   /* in bytes */
        int           status; /* per descriptor status. */
} tx_entry_t;

typedef struct rx_entry_st {
	unsigned long addr;   /* virtual address */
	unsigned long size;   /* in bytes */
        int           status; /* per descriptor status. */
} rx_entry_t;

#define TX_RING_SIZE 256
#define RX_RING_SIZE 256
typedef struct net_ring_st {
    /*
     * Guest OS places packets into ring at tx_prod.
     * Hypervisor removes at tx_cons.
     * Ring is empty when tx_prod == tx_cons.
     * Guest OS receives a DOMAIN_EVENT_NET_TX when tx_cons passes tx_event.
     * Hypervisor may be prodded whenever tx_prod is updated, but this is
     * only necessary when tx_cons == old_tx_prod (ie. transmitter stalled).
     */
    tx_entry_t	*tx_ring;
    unsigned int tx_prod, tx_cons, tx_event;

    /*
     * Guest OS places empty buffers into ring at rx_prod.
     * Hypervisor fills buffers as rx_cons.
     * Ring is empty when rx_prod == rx_cons.
     * Guest OS receives a DOMAIN_EVENT_NET_RX when rx_cons passes rx_event.
     * Hypervisor may be prodded whenever rx_prod is updated, but this is
     * only necessary when rx_cons == old_rx_prod (ie. receiver stalled).
     */
    rx_entry_t	*rx_ring;
    unsigned int rx_prod, rx_cons, rx_event;
} net_ring_t;

/* Specify base of per-domain array. Get returned free slot in the array. */
/*net_ring_t *create_net_vif(int domain);*/

/* Packet routing/filtering code follows:
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
    char            *buf;   // where to put the reply -- guest virtual address
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


/* Descriptor status values:
 */

#define RING_STATUS_OK               0  // Everything is gravy.
#define RING_STATUS_ERR_CFU         -1  // Copy from user problems.
#define RING_STATUS_BAD_PAGE        -2  // What they gave us was pure evil.

#endif
