/* vif.h
 * 
 * this is the hypervisor end of the network code.  The net_ring structure
 * stored in each vif is placed on a shared page to interact with the guest VM.
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

typedef struct net_vif_st {
    net_ring_t  *net_ring;
    int          id;
    struct sk_buff_head skb_list;
    // rules table goes here in next revision.
} net_vif_t;

/* VIF-related defines. */
#define MAX_GUEST_VIFS    2 // each VIF is a small overhead in task_struct
#define MAX_SYSTEM_VIFS 256 // trying to avoid dynamic allocation 

/* vif globals */
extern int sys_vif_count;

/* vif prototypes */
net_ring_t *create_net_vif(int domain);
void destroy_net_vif(struct task_struct *p);

