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

/*
 * Command values for block_io_op()
 */

#define NETOP_PUSH_BUFFERS    0  /* Notify Xen of new buffers on the rings. */
#define NETOP_FLUSH_BUFFERS   1  /* Flush all pending request buffers.      */
#define NETOP_RESET_RINGS     2  /* Reset ring indexes on a quiescent vif.  */
#define NETOP_GET_VIF_INFO    3  /* Query information for this vif.         */
typedef struct netop_st {
    unsigned int cmd; /* NETOP_xxx */
    unsigned int vif; /* VIF index */
    union {
        struct {
            unsigned long ring_mfn; /* Page frame containing net_ring_t. */
            unsigned char vmac[6];  /* Virtual Ethernet MAC address.     */
        } get_vif_info;
    } u;
} netop_t;


typedef struct tx_req_entry_st
{
    unsigned short id;
    unsigned short size;   /* packet size in bytes */
    unsigned long  addr;   /* machine address of packet */
} tx_req_entry_t;

typedef struct tx_resp_entry_st
{
    unsigned short id;
    unsigned char  status;
} tx_resp_entry_t;

typedef union tx_entry_st
{
    tx_req_entry_t  req;
    tx_resp_entry_t resp;
} tx_entry_t;


typedef struct rx_req_entry_st
{
    unsigned short id;
    unsigned long  addr;   /* machine address of PTE to swizzle */
} rx_req_entry_t;

typedef struct rx_resp_entry_st
{
    unsigned short id;
    unsigned short size;   /* received packet size in bytes */
    unsigned char  status; /* per descriptor status */
    unsigned char  offset; /* offset in page of received pkt */
} rx_resp_entry_t;

typedef union rx_entry_st
{
    rx_req_entry_t  req;
    rx_resp_entry_t resp;
} rx_entry_t;


#define XENNET_TX_RING_SIZE 256
#define XENNET_RX_RING_SIZE 256

#define MAX_DOMAIN_VIFS 8

/* This structure must fit in a memory page. */
typedef struct net_ring_st
{
    tx_entry_t tx_ring[XENNET_TX_RING_SIZE];
    rx_entry_t rx_ring[XENNET_RX_RING_SIZE];
} net_ring_t;

/*
 * We use a special capitalised type name because it is _essential_ that all 
 * arithmetic on indexes is done on an integer type of the correct size.
 */
typedef unsigned int NET_RING_IDX;

/*
 * Ring indexes are 'free running'. That is, they are not stored modulo the
 * size of the ring buffer. The following macros convert a free-running counter
 * into a value that can directly index a ring-buffer array.
 */
#define MASK_NET_RX_IDX(_i) ((_i)&(XENNET_RX_RING_SIZE-1))
#define MASK_NET_TX_IDX(_i) ((_i)&(XENNET_TX_RING_SIZE-1))

typedef struct net_idx_st
{
    /*
     * Guest OS places packets into ring at tx_req_prod.
     * Guest OS receives EVENT_NET when tx_resp_prod passes tx_event.
     * Guest OS places empty buffers into ring at rx_req_prod.
     * Guest OS receives EVENT_NET when rx_rssp_prod passes rx_event.
     */
    NET_RING_IDX tx_req_prod, tx_resp_prod, tx_event;
    NET_RING_IDX rx_req_prod, rx_resp_prod, rx_event;
} net_idx_t;

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
    domid_t      src_dom, dst_dom;
    unsigned int src_idx, dst_idx;
    u16  action;
} net_rule_t;

/* These are specified in the 'idx' if the 'dom' is SPECIAL. */
#define VIF_SPECIAL             (~0ULL)
#define VIF_UNKNOWN_INTERFACE   0
#define VIF_PHYSICAL_INTERFACE  1
#define VIF_ANY_INTERFACE       2

typedef struct vif_query_st
{
    domid_t          domain;
    int             *buf;   /* reply buffer -- guest virtual address */
} vif_query_t;

typedef struct vif_getinfo_st
{
    domid_t             domain;
    unsigned int        vif;

    /* domain & vif are supplied by dom0, the rest are response fields */
    long long           total_bytes_sent;
    long long           total_bytes_received;
    long long           total_packets_sent;
    long long           total_packets_received;

    /* Current scheduling parameters */
    unsigned long credit_bytes;
    unsigned long credit_usec;
} vif_getinfo_t;

/*
 * Set parameters associated with a VIF. Currently this is only scheduling
 * parameters --- permit 'credit_bytes' to be transmitted every 'credit_usec'.
 */
typedef struct vif_setparams_st
{
    domid_t             domain;
    unsigned int        vif;
    unsigned long       credit_bytes;
    unsigned long       credit_usec;
} vif_setparams_t;

/* Network trap operations and associated structure. 
 * This presently just handles rule insertion and deletion, but will
 * evenually have code to add and remove interfaces.
 */

#define NETWORK_OP_ADDRULE      0
#define NETWORK_OP_DELETERULE   1
#define NETWORK_OP_GETRULELIST  2
#define NETWORK_OP_VIFQUERY     3
#define NETWORK_OP_VIFGETINFO   4
#define NETWORK_OP_VIFSETPARAMS 5

typedef struct network_op_st 
{
    unsigned long cmd;
    union
    {
        net_rule_t net_rule;
        vif_query_t vif_query;
        vif_getinfo_t vif_getinfo;
        vif_setparams_t vif_setparams;
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
#define RING_STATUS_BAD_PAGE         1  /* What they gave us was pure evil */
#define RING_STATUS_DROPPED          2  /* Unrouteable packet */

#endif
