/* vif.h
 * 
 * This is the hypervisor end of the network code.  The net_ring structure
 * stored in each vif is placed on a shared page to interact with the guest VM.
 *
 * Copyright (c) 2002, A K Warfield and K A Fraser
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

typedef struct rx_shadow_entry_st {
    unsigned long addr;
    unsigned long size;
    int           status;
    unsigned long flush_count;
} rx_shadow_entry_t;

typedef struct tx_shadow_entry_st {
    unsigned long addr;
    unsigned long size;
    int           status;
} tx_shadow_entry_t;

typedef struct net_shadow_ring_st {
    rx_shadow_entry_t *rx_ring;
    tx_shadow_entry_t *tx_ring;
    unsigned int rx_prod, rx_cons, rx_idx;
    unsigned int tx_prod, tx_cons, tx_idx;
} net_shadow_ring_t;

typedef struct net_vif_st {
    net_ring_t          *net_ring;
    net_shadow_ring_t   *shadow_ring;
    int                 id;
    struct sk_buff_head skb_list;
    unsigned int domain;
    // rules table goes here in next revision.
} net_vif_t;

/* VIF-related defines. */
#define MAX_GUEST_VIFS    2 // each VIF is a small overhead in task_struct
#define MAX_SYSTEM_VIFS 256  

/* vif globals */
extern int sys_vif_count;
extern net_vif_t *sys_vif_list[];

/* vif prototypes */
net_vif_t *create_net_vif(int domain);
void destroy_net_vif(struct task_struct *p);
void add_default_net_rule(int vif_id, u32 ipaddr);
int __net_get_target_vif(u8 *data, unsigned int len, int src_vif);
void add_default_net_rule(int vif_id, u32 ipaddr);

#define net_get_target_vif(skb) __net_get_target_vif(skb->data, skb->len, skb->src_vif)
/* status fields per-descriptor:
 */


