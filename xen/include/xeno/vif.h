/* vif.h
 * 
 * This is the hypervisor end of the network code.  The net_ring structure
 * stored in each vif is placed on a shared page to interact with the guest VM.
 *
 * Copyright (c) 2002-2003, A K Warfield and K A Fraser
 */

/* virtual network interface struct and associated defines. */
/* net_vif_st is the larger struct that describes a virtual network interface
 * it contains a pointer to the net_ring_t structure that needs to be on a 
 * shared page between the hypervisor and guest.  The vif struct is private 
 * to the hypervisor and is used primarily as a container to allow routing 
 * and interface administration.  This define should eventually be moved to 
 * a non-shared interface file, as it is of no relevance to the guest.
 */

#include <hypervisor-ifs/network.h>
#include <xeno/skbuff.h>

/* 
 * shadow ring structures are used to protect the descriptors from
 * tampering after they have been passed to the hypervisor.
 *
 * TX_RING_SIZE and RX_RING_SIZE are defined in the shared network.h.
 */

typedef struct rx_shadow_entry_st 
{
    unsigned long  id;
    /* IN vars */
    unsigned long  addr;
    /* OUT vars */
    unsigned short size;
    unsigned char  status;
    unsigned char  offset;
    /* PRIVATE vars */
    unsigned long  flush_count;
} rx_shadow_entry_t;

typedef struct tx_shadow_entry_st 
{
    unsigned long  id;
    /* IN vars */
    void          *header;
    unsigned long  payload;
    unsigned short size;
    /* OUT vars */
    unsigned char  status;
} tx_shadow_entry_t;

typedef struct net_shadow_ring_st {
    rx_shadow_entry_t *rx_ring;
    unsigned int rx_prod;  /* More buffers for filling go here. */
    unsigned int rx_idx;   /* Next buffer to fill is here. */
    unsigned int rx_cons;  /* Next buffer to create response for is here. */

    tx_shadow_entry_t *tx_ring;
    /*
     * These cannot be derived from shared variables, as not all packets
     * will end up on the shadow ring (eg. locally delivered packets).
     */
    unsigned int tx_prod;  /* More packets for sending go here. */
    unsigned int tx_idx;   /* Next packet to send is here. */
    unsigned int tx_transmitted_prod; /* Next packet to finish transmission. */
    unsigned int tx_cons;  /* Next packet to create response for is here. */

    /* Indexes into shared ring. */
    unsigned int rx_req_cons;
    unsigned int rx_resp_prod; /* private version of shared variable */
    unsigned int tx_req_cons;
    unsigned int tx_resp_prod; /* private version of shared variable */
} net_shadow_ring_t;

typedef struct net_vif_st {
    net_ring_t         *net_ring;
    net_shadow_ring_t  *shadow_ring;
    int                 id;
    struct task_struct *domain;
    struct list_head    list;     /* scheduling list */
    struct list_head    dom_list; /* domain list     */
    atomic_t            refcnt;
} net_vif_t;

#define get_vif(_v) (atomic_inc(&(_v)->refcnt))
#define put_vif(_v)                                                \
do {                                                               \
    if ( atomic_dec_and_test(&(_v)->refcnt) ) destroy_net_vif(_v); \
} while (0)                                                        \

/* VIF-related defines. */
#define MAX_GUEST_VIFS    2 // each VIF is a small overhead in task_struct
#define MAX_SYSTEM_VIFS 256  

/* vif globals */
extern int sys_vif_count;
extern net_vif_t *sys_vif_list[];
extern rwlock_t sys_vif_lock; /* protects the sys_vif_list */

/* vif prototypes */
net_vif_t *create_net_vif(int domain);
void destroy_net_vif(net_vif_t *vif);
void unlink_net_vif(net_vif_t *vif);
void add_default_net_rule(int vif_id, u32 ipaddr);
int __net_get_target_vif(u8 *data, unsigned int len, int src_vif);
void add_default_net_rule(int vif_id, u32 ipaddr);

#define net_get_target_vif(skb) __net_get_target_vif(skb->data, skb->len, skb->src_vif)
/* status fields per-descriptor:
 */


