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
	unsigned long addr; /* virtual address */
	unsigned long size; /* in bytes */
} tx_entry_t;

typedef struct rx_entry_st {
	unsigned long addr; /* virtual address */
	unsigned long size; /* in bytes */
} rx_entry_t;

#define TX_RING_SIZE 1024
#define RX_RING_SIZE 1024
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
    unsigned int tx_ring_size;
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
    unsigned int rx_ring_size;
} net_ring_t;

/* net_vif_st is the larger struct that describes a virtual network interface
 * it contains a pointer to the net_ring_t structure that needs to be on a 
 * shared page between the hypervisor and guest.  The vif struct is private 
 * to the hypervisor and is used primarily as a container to allow routing 
 * and interface administration.  This define should eventually be moved to 
 * a non-shared interface file, as it is of no relevance to the guest.
 */

typedef struct net_vif_st {
    net_ring_t  *net_ring;
    int          id;
    // rules table goes here in next revision.
} net_vif_t;

/* VIF-related defines. */
#define MAX_GUEST_VIFS    2 // each VIF is a small overhead in task_struct
#define MAX_SYSTEM_VIFS 256 // trying to avoid dynamic allocation 

/* vif globals */
extern int sys_vif_count;

/* This is here for consideration:  Having a global lookup for vifs
 * may make the guest /proc stuff more straight forward, and could 
 * be used in the routing code.  I don't know if it warrants the 
 * overhead yet.
 */

/* net_vif_t sys_vif_list[MAX_SYSTEM_VIFS]; */

/* Specify base of per-domain array. Get returned free slot in the array. */
net_ring_t *create_net_vif(int domain);

/* Packet routing/filtering code follows:
 */

#define NETWORK_ACTION_DROP 0
#define NETWORK_ACTION_PASS 1

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

    int  src_interface;
    int  dst_interface;
    int  action;
} net_rule_t;

/* Network trap operations and associated structure. 
 * This presently just handles rule insertion and deletion, but will
 * evenually have code to add and remove interfaces.
 */

#define NETWORK_OP_ADDRULE      0
#define NETWORK_OP_DELETERULE   1

typedef struct network_op_st 
{
    unsigned long cmd;
    union
    {
        net_rule_t net_rule;
    }
    u;
} network_op_t;
    
/* Drop a new rule down to the network tables. */
int add_net_rule(net_rule_t *rule);

#endif
