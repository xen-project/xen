/* vif.h
 * 
 * This is the hypervisor end of the network code.  The net_ring structure
 * stored in each vif is placed on a shared page to interact with the guest VM.
 *
 * Copyright (c) 2002-2003, A K Warfield and K A Fraser
 */

#ifndef __XEN_VIF_H__
#define __XEN_VIF_H__

/* virtual network interface struct and associated defines. */
/* net_vif_st is the larger struct that describes a virtual network interface
 * it contains a pointer to the net_ring_t structure that needs to be on a 
 * shared page between the hypervisor and guest.  The vif struct is private 
 * to the hypervisor and is used primarily as a container to allow routing 
 * and interface administration.  This define should eventually be moved to 
 * a non-shared interface file, as it is of no relevance to the guest.
 */

#include <hypervisor-ifs/network.h>

#include <xen/if_ether.h>

extern struct net_device *the_dev;

/*
 * shadow ring structures are used to protect the descriptors from tampering 
 * after they have been passed to the hypervisor.
 * 
 * XENNET_TX_RING_SIZE and XENNET_RX_RING_SIZE are defined in the shared
 * network.h. 
 */

typedef struct rx_shadow_entry_st 
{
    unsigned short id;
    unsigned short _pad;
    unsigned long  pte_ptr;
    unsigned long  buf_pfn;
} rx_shadow_entry_t;

typedef struct tx_shadow_entry_st 
{
    unsigned short id;
    unsigned short size;
    void          *header;
    unsigned long  payload;
} tx_shadow_entry_t;

typedef struct net_vif_st {
    /* The shared rings and indexes. */
    net_ring_t         *shared_rings;
    net_idx_t          *shared_idxs;

    /* The private rings and indexes. */
    rx_shadow_entry_t rx_shadow_ring[XENNET_RX_RING_SIZE];
    NET_RING_IDX rx_prod;  /* More buffers for filling go here. */
    NET_RING_IDX rx_cons;  /* Next buffer to fill is here. */
    tx_shadow_entry_t tx_shadow_ring[XENNET_TX_RING_SIZE];
    NET_RING_IDX tx_prod;  /* More packets for sending go here. */
    NET_RING_IDX tx_cons;  /* Next packet to send is here. */

    /* Private indexes into shared ring. */
    NET_RING_IDX rx_req_cons;
    NET_RING_IDX rx_resp_prod; /* private version of shared variable */
    NET_RING_IDX tx_req_cons;
    NET_RING_IDX tx_resp_prod; /* private version of shared variable */

    /* Usage accounting */
    long long total_bytes_sent;
    long long total_bytes_received;
    long long total_packets_sent;
    long long total_packets_received;

    /* Trasnmit shaping: allow 'credit_bytes' everu 'credit_usec'. */
    unsigned long   credit_bytes;
    unsigned long   credit_usec;
    unsigned long   remaining_credit;
    struct ac_timer credit_timeout;

    /* Miscellaneous private stuff. */
    struct task_struct *domain;
    unsigned int idx; /* index within domain */
    struct list_head    list;     /* scheduling list */
    atomic_t            refcnt;
    spinlock_t          rx_lock, tx_lock;
    unsigned char       vmac[ETH_ALEN];
} net_vif_t;

#define get_vif(_v) (atomic_inc(&(_v)->refcnt))
#define put_vif(_v)                                                \
do {                                                               \
    if ( atomic_dec_and_test(&(_v)->refcnt) ) destroy_net_vif(_v); \
} while (0)                                                        \

/* vif prototypes */
#ifdef OLD_DRIVERS
net_vif_t *create_net_vif(domid_t dom);
void destroy_net_vif(net_vif_t *vif);
void unlink_net_vif(net_vif_t *vif);
net_vif_t *net_get_target_vif(u8 *data, unsigned int len, net_vif_t *src_vif);
net_vif_t *find_net_vif(domid_t dom, unsigned int idx);
void delete_all_domain_vfr_rules(struct task_struct *p);
#else
#define create_net_vif(_d) ((void)0)
#define destroy_net_vif(_v) ((void)0)
#define unlink_net_vif(_v) ((void)0)
#define delete_all_domain_vfr_rules(_p) ((void)0)
#endif

/*
 * Return values from net_get_target_vif:
 *  VIF_PHYS -- Send to physical NIC
 *  VIF_DROP -- Drop this packet
 *  others   -- Send to specified VIF (reference held on return)
 */
#define VIF_PHYS  ((net_vif_t *)0)
#define VIF_DROP  ((net_vif_t *)1)
#define VIF_LOCAL(_vif) ((unsigned long)(_vif) > 1)

#endif /* __XEN_VIF_H__ */

