/* network.c
 *
 * Network virtualization for Xen.  Lower-level network interactions are in 
 * net/dev.c and in the drivers.  This file contains routines to interact 
 * with the virtual interfaces (vifs) and the virtual firewall/router through
 * the use of rules.
 *
 * Copyright (c) 2002, A K Warfield and K A Fraser
 */

#include <hypervisor-ifs/network.h>
#include <xeno/sched.h>
#include <xeno/errno.h>
#include <xeno/init.h>
#include <xeno/slab.h>
#include <xeno/spinlock.h>
#include <xeno/if_ether.h>
#include <linux/skbuff.h>
#include <xeno/netdevice.h>
#include <xeno/in.h>
#include <asm/domain_page.h>
#include <asm/io.h>

/* vif globals 
 * sys_vif_list is a lookup table for vifs, used in packet forwarding.
 * it will be replaced later by something a little more flexible.
 */

int sys_vif_count;                                  /* global vif count */
net_vif_t *sys_vif_list[MAX_SYSTEM_VIFS];           /* global vif array */
net_rule_ent_t *net_rule_list;                      /* global list of rules */
kmem_cache_t *net_vif_cache;                        
kmem_cache_t *net_rule_cache;
static rwlock_t net_rule_lock = RW_LOCK_UNLOCKED;   /* rule mutex */

rwlock_t sys_vif_lock = RW_LOCK_UNLOCKED;    /* vif mutex */

void print_net_rule_list();


/* ----[ VIF Functions ]----------------------------------------------------*/

/* create_net_vif - Create a new vif and append it to the specified domain.
 * 
 * the domain is examined to determine how many vifs currently are allocated
 * and the newly allocated vif is appended.  The vif is also added to the
 * global list.
 * 
 */

net_vif_t *create_net_vif(int domain)
{
    net_vif_t *new_vif;
    net_ring_t *new_ring;
    net_shadow_ring_t *shadow_ring;
    struct task_struct *dom_task;
    unsigned long flags;

    if ( !(dom_task = find_domain_by_id(domain)) )
        return NULL;
    
    if ( (new_vif = kmem_cache_alloc(net_vif_cache, GFP_KERNEL)) == NULL )
        return NULL;
    
    new_ring = dom_task->net_ring_base + dom_task->num_net_vifs;
    memset(new_ring, 0, sizeof(net_ring_t));

    shadow_ring = kmalloc(sizeof(net_shadow_ring_t), GFP_KERNEL);
    if ( shadow_ring == NULL ) goto fail;
    
    shadow_ring->rx_ring = kmalloc(RX_RING_SIZE
                    * sizeof(rx_shadow_entry_t), GFP_KERNEL);
    shadow_ring->tx_ring = kmalloc(TX_RING_SIZE
                    * sizeof(tx_shadow_entry_t), GFP_KERNEL);
    if ( (shadow_ring->rx_ring == NULL) || (shadow_ring->tx_ring == NULL) )
            goto fail;

    shadow_ring->rx_prod = shadow_ring->rx_cons = shadow_ring->rx_idx = 0;
    shadow_ring->tx_prod = shadow_ring->tx_cons = shadow_ring->tx_idx = 0;
    
    /*
     * Fill in the new vif struct. Note that, while the vif's refcnt is
     * non-zero, we hold a reference to the task structure.
     */
    atomic_set(&new_vif->refcnt, 1);
    new_vif->net_ring    = new_ring;
    new_vif->shadow_ring = shadow_ring;
    new_vif->domain      = dom_task;
    new_vif->list.next   = NULL;

    list_add(&new_vif->dom_list, &dom_task->net_vifs);
    dom_task->num_net_vifs++;

    write_lock_irqsave(&sys_vif_lock, flags);
    new_vif->id = sys_vif_count;
    sys_vif_list[sys_vif_count++] = new_vif;
    write_unlock_irqrestore(&sys_vif_lock, flags);
    
    return new_vif;
    
fail:
    kmem_cache_free(net_vif_cache, new_vif);
    if ( shadow_ring != NULL )
    {
        if ( shadow_ring->rx_ring ) kfree(shadow_ring->rx_ring);
        if ( shadow_ring->tx_ring ) kfree(shadow_ring->tx_ring);
        kfree(shadow_ring);
    }

    free_task_struct(dom_task);
    return NULL;
}

void destroy_net_vif(net_vif_t *vif)
{
    int i;
    unsigned long *pte, flags;
    struct pfn_info *page;
    struct task_struct *p = vif->domain;

    /* Return any outstanding receive buffers to the guest OS. */
    spin_lock_irqsave(&p->page_lock, flags);
    for ( i  = vif->shadow_ring->rx_idx; 
          i != vif->shadow_ring->rx_prod; 
          i  = ((i+1) & (RX_RING_SIZE-1)) )
    {
        rx_shadow_entry_t *rx = vif->shadow_ring->rx_ring + i;
        if ( rx->status != RING_STATUS_OK ) continue;
        pte  = map_domain_mem(rx->addr);
        *pte |= _PAGE_PRESENT;
        page = frame_table + (*pte >> PAGE_SHIFT);
        page->flags &= ~PG_type_mask;
        if ( (*pte & _PAGE_RW) ) 
            page->flags |= PGT_writeable_page | PG_need_flush;
        unmap_domain_mem(pte);
    }
    spin_unlock_irqrestore(&p->page_lock, flags);

    kfree(vif->shadow_ring->tx_ring);
    kfree(vif->shadow_ring->rx_ring);
    kfree(vif->shadow_ring);
    kmem_cache_free(net_vif_cache, vif);
    free_task_struct(p);
}

void unlink_net_vif(net_vif_t *vif)
{
    unsigned long flags;
    list_del(&vif->dom_list);
    vif->domain->num_net_vifs--;
    write_lock_irqsave(&sys_vif_lock, flags);
    sys_vif_list[vif->id] = NULL;
    write_unlock_irqrestore(&sys_vif_lock, flags);
    put_vif(vif);
}


/* vif_query - Call from the proc file system to get a list of vifs 
 * assigned to a particular domain.
 */

void vif_query(vif_query_t *vq)
{
    net_vif_t *vif;
    struct task_struct *p;
    unsigned long flags;
    char buf[128];
    int i;

    if ( !(p = find_domain_by_id(vq->domain)) ) 
        return;

    *buf = '\0';

    read_lock_irqsave(&sys_vif_lock, flags);
    for ( i = 0; i < MAX_SYSTEM_VIFS; i++ )
    {
        vif = sys_vif_list[i];
        if ( (vif == NULL) || (vif->domain != p) ) continue;
        sprintf(buf + strlen(buf), "%d\n", vif->id);
    }
    read_unlock_irqrestore(&sys_vif_lock, flags);

    copy_to_user(vq->buf, buf, strlen(buf) + 1);
    
    free_task_struct(p);
}
        
/* ----[ Net Rule Functions ]-----------------------------------------------*/

/* add_net_rule - Add a new network filter rule.
 */

int add_net_rule(net_rule_t *rule)
{
    net_rule_ent_t *new_ent;
    
    if ( (new_ent = kmem_cache_alloc(net_rule_cache, GFP_KERNEL)) == NULL )
    {
        return -ENOMEM;
    }

    memcpy(&new_ent->r, rule, sizeof(net_rule_t));

    write_lock(&net_rule_lock);
    new_ent->next = net_rule_list;
    net_rule_list = new_ent;
    write_unlock(&net_rule_lock);

    return 0;
}

/* delete_net_rule - Delete an existing network rule.
 */

int delete_net_rule(net_rule_t *rule)
{
    net_rule_ent_t *ent = net_rule_list, *prev = NULL;
    while ( (ent) && ((memcmp(rule, &ent->r, sizeof(net_rule_t))) != 0) )
    {
        prev = ent;
        ent = ent->next;
    }

    if (ent != NULL)
    {
        write_lock(&net_rule_lock);
        if (prev != NULL)
        {
            prev->next = ent->next;
        }
        else
        {
            net_rule_list = ent->next;
        }
        kmem_cache_free(net_rule_cache, ent);
        write_unlock(&net_rule_lock);
    }
    return 0;
}
 
/* add_default_net_rule - Set up default network path (ie for dom0).
 * 
 * this is a utility function to route all traffic with the specified
 * ip address to the specified vif.  It's used to set up domain zero.
 */

void add_default_net_rule(int vif_id, u32 ipaddr)
{
    net_rule_t new_rule;

    //outbound rule.
    memset(&new_rule, 0, sizeof(net_rule_t));
    new_rule.src_addr = ipaddr;
    new_rule.src_addr_mask = 0xffffffff;
    new_rule.src_interface = vif_id;
    new_rule.dst_interface = VIF_PHYSICAL_INTERFACE;
    new_rule.action = NETWORK_ACTION_ACCEPT;
    new_rule.proto = NETWORK_PROTO_ANY;
    add_net_rule(&new_rule);

    //inbound rule;
    memset(&new_rule, 0, sizeof(net_rule_t));
    new_rule.dst_addr = ipaddr;
    new_rule.dst_addr_mask = 0xffffffff;
    new_rule.src_interface = VIF_PHYSICAL_INTERFACE;
    new_rule.dst_interface = vif_id;
    new_rule.action = NETWORK_ACTION_ACCEPT;
    new_rule.proto = NETWORK_PROTO_ANY;
    add_net_rule(&new_rule);

}

/* print_net_rule - Print a single net rule.
 */

void print_net_rule(net_rule_t *r)
{
    printk("===] NET RULE:\n");
    printk("=] src_addr         : %lu\n", (unsigned long) r->src_addr);
    printk("=] src_addr_mask    : %lu\n", (unsigned long) r->src_addr_mask);   
    printk("=] dst_addr         : %lu\n", (unsigned long) r->dst_addr);
    printk("=] dst_addr_mask    : %lu\n", (unsigned long) r->dst_addr_mask);
    printk("=] src_port         : %u\n", r->src_port);
    printk("=] src_port_mask    : %u\n", r->src_port_mask);
    printk("=] dst_port         : %u\n", r->dst_port);
    printk("=] dst_port_mask    : %u\n", r->dst_port_mask);
    printk("=] dst_proto        : %u\n", r->proto);
    printk("=] src_interface    : %d\n", r->src_interface);
    printk("=] dst_interface    : %d\n", r->dst_interface);
    printk("=] action           : %u\n", r->action);
}

/* print_net_rule_list - Print the global rule table.
 */

void print_net_rule_list()
{
    net_rule_ent_t *ent;
    int count = 0;
    
    read_lock(&net_rule_lock);

    ent = net_rule_list;
    
    while (ent) 
    {
        print_net_rule(&ent->r);
        ent = ent->next;
        count++;
    }
    printk("\nTotal of %d rules.\n", count);

    read_unlock(&net_rule_lock);
}

/* net_find_rule - Find the destination vif according to the current rules.
 *
 * Apply the rules to this skbuff and return the vif id that it is bound for.
 * If there is no match, VIF_DROP is returned.
 */

int net_find_rule(u8 nproto, u8 tproto, u32 src_addr, u32 dst_addr, u16 src_port, u16 dst_port, 
                  int src_vif)
{
    net_rule_ent_t *ent;
    int dest = VIF_DROP;
    
    read_lock(&net_rule_lock);
    
    ent = net_rule_list;
    
    while (ent)
    {
        if ( ((ent->r.src_interface == src_vif)
              || (ent->r.src_interface == VIF_ANY_INTERFACE)) &&

             (!((ent->r.src_addr ^ src_addr) & ent->r.src_addr_mask )) &&
             (!((ent->r.dst_addr ^ dst_addr) & ent->r.dst_addr_mask )) &&
             (!((ent->r.src_port ^ src_port) & ent->r.src_port_mask )) &&
             (!((ent->r.dst_port ^ dst_port) & ent->r.dst_port_mask )) &&
             
             ((ent->r.proto == NETWORK_PROTO_ANY) ||
              ((ent->r.proto == NETWORK_PROTO_IP)  &&
               (nproto == (u8)ETH_P_IP)) ||
              ((ent->r.proto == NETWORK_PROTO_ARP) &&
               (nproto == (u8)ETH_P_ARP)) ||
              ((ent->r.proto == NETWORK_PROTO_TCP) &&
               (tproto == IPPROTO_TCP)) ||
              ((ent->r.proto == NETWORK_PROTO_UDP) &&
               (tproto == IPPROTO_UDP)))
           )
        {
            break;
        }
        ent = ent->next;
    }

    if (ent) (dest = ent->r.dst_interface);
    read_unlock(&net_rule_lock);
    return dest;
}

/* net_get_target_vif - Find the vif that the given sk_buff is bound for.
 *
 * This is intended to be the main interface to the VFR rules, where 
 * net_find_rule (above) is a private aspect of the current matching 
 * implementation.  All in-hypervisor routing should use this function only
 * to ensure that this can be rewritten later.
 *
 * Currently, network rules are stored in a global linked list.  New rules are
 * added to the front of this list, and (at present) the first matching rule
 * determines the vif that a packet is sent to.  This is obviously not ideal,
 * it might be more advisable to have chains, or at lest most-specific 
 * matching, and moreover routing latency increases linearly (for old rules)
 * as new rules are added.  
 *
 * net_get_target_vif examines the sk_buff and pulls out the relevant fields
 * based on the packet type.  it then calls net_find_rule to scan the rule 
 * list.
 */

#define net_get_target_vif(skb) __net_get_target_vif(skb->data, skb->len, skb->src_vif)

int __net_get_target_vif(u8 *data, unsigned int len, int src_vif)
{
    int target = VIF_DROP;
    u8 *h_raw, *nh_raw;
    
    if ( len < ETH_HLEN ) goto drop;

    nh_raw = data + ETH_HLEN;
    switch ( ntohs(*(unsigned short *)(data + 12)) )
    {
    case ETH_P_ARP:
        if ( len < (ETH_HLEN + 28) ) goto drop;
        target = net_find_rule((u8)ETH_P_ARP, 0, ntohl(*(u32 *)(nh_raw + 14)),
                               ntohl(*(u32 *)(nh_raw + 24)), 0, 0, 
                               src_vif);
        break;

    case ETH_P_IP:
        if ( len < (ETH_HLEN + 20) ) goto drop;
        h_raw =  data + ((*(unsigned char *)(nh_raw)) & 0x0f) * 4;
        
        /* XXX For now, we ignore ports. */
#if 0
        target = net_find_rule((u8)ETH_P_IP,  *(u8 *)(nh_raw + 9),
                               ntohl(*(u32 *)(nh_raw + 12)),
                               ntohl(*(u32 *)(nh_raw + 16)),
                               ntohs(*(u16 *)(h_raw)),
                               ntohs(*(u16 *)(h_raw + 2)), 
                               src_vif);
#else
        target = net_find_rule((u8)ETH_P_IP,  *(u8 *)(data + 9),
                               ntohl(*(u32 *)(nh_raw + 12)),
                               ntohl(*(u32 *)(nh_raw + 16)),
                               0,
                               0, 
                               src_vif);
#endif
    }
    return target;
    
 drop:
    return VIF_DROP;
}

/* ----[ Syscall Interface ]------------------------------------------------*/

/* 
 * This is the hook function to handle guest-invoked traps requesting 
 * changes to the network system.
 */

long do_network_op(network_op_t *u_network_op)
{
    long ret=0;
    network_op_t op;
    
    if ( current->domain != 0 )
        return -EPERM;

    if ( copy_from_user(&op, u_network_op, sizeof(op)) )
        return -EFAULT;
    switch ( op.cmd )
    {

    case NETWORK_OP_ADDRULE:
    {
        add_net_rule(&op.u.net_rule);
    }
    break;

    case NETWORK_OP_DELETERULE:
    {
        delete_net_rule(&op.u.net_rule);
    }
    break;

    case NETWORK_OP_GETRULELIST:
    {
        // This should eventually ship a rule list up to the VM
        // to be printed in its procfs.  For now, we just print the rules.
        
        print_net_rule_list();
    }
    break;

    case NETWORK_OP_VIFQUERY:
    {
        vif_query(&op.u.vif_query);
    }
    
    default:
        ret = -ENOSYS;
    }

    return ret;
}

void __init net_init (void)
{
    sys_vif_count = 0;
    memset(sys_vif_list, 0, sizeof(sys_vif_list));
    net_rule_list = NULL;
    net_vif_cache = kmem_cache_create("net_vif_cache", sizeof(net_vif_t),
                                    0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    net_rule_cache = kmem_cache_create("net_rule_cache", sizeof(net_rule_ent_t),
                                    0, SLAB_HWCACHE_ALIGN, NULL, NULL);
}
