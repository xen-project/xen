/* network.c
 *
 * Network virtualization for Xen.  Lower-level network interactions are in 
 * net/dev.c and in the drivers.  This file contains routines to interact 
 * with the virtual interfaces (vifs) and the virtual firewall/router through
 * the use of rules.
 *
 * Copyright (c) 2002-2003, A K Warfield and K A Fraser
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

net_rule_ent_t *net_rule_list;                      /* global list of rules */
kmem_cache_t *net_vif_cache;                        
kmem_cache_t *net_rule_cache;
static rwlock_t net_rule_lock = RW_LOCK_UNLOCKED;   /* rule mutex */

void print_net_rule_list();


/* ----[ VIF Functions ]----------------------------------------------------*/


net_vif_t *find_vif_by_id(unsigned long id)
{
    struct task_struct *p;
    net_vif_t *vif = NULL;
    unsigned long flags, dom = id>>VIF_DOMAIN_SHIFT;

    read_lock_irqsave(&tasklist_lock, flags);
    p = task_hash[TASK_HASH(dom)];
    while ( p != NULL )
    {
        if ( p->domain == dom )
        {
            vif = p->net_vif_list[id&VIF_INDEX_MASK];
            if ( vif != NULL ) get_vif(vif);
            break;
        }
        p = p->next_hash;
    }
    read_unlock_irqrestore(&tasklist_lock, flags);

    return vif;
}


/* create_net_vif - Create a new vif and append it to the specified domain.
 * 
 * the domain is examined to determine how many vifs currently are allocated
 * and the newly allocated vif is appended.  The vif is also added to the
 * global list.
 * 
 */
net_vif_t *create_net_vif(int domain)
{
    int dom_vif_idx;
    net_vif_t *new_vif = NULL;
    net_ring_t *new_ring = NULL;
    struct task_struct *p = NULL;
    unsigned long flags;

    if ( !(p = find_domain_by_id(domain)) )
        return NULL;
    
    write_lock_irqsave(&tasklist_lock, flags);

    for ( dom_vif_idx = 0; dom_vif_idx < MAX_DOMAIN_VIFS; dom_vif_idx++ )
        if ( p->net_vif_list[dom_vif_idx] == NULL ) break;
    if ( dom_vif_idx == MAX_DOMAIN_VIFS )
        goto fail;

    if ( (new_vif = kmem_cache_alloc(net_vif_cache, GFP_KERNEL)) == NULL )
        goto fail;

    memset(new_vif, 0, sizeof(*new_vif));
    
    if ( sizeof(net_ring_t) > PAGE_SIZE ) BUG();
    new_ring = (net_ring_t *)get_free_page(GFP_KERNEL);
    clear_page(new_ring);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(new_ring), domain);

    /*
     * Fill in the new vif struct. Note that, while the vif's refcnt is
     * non-zero, we hold a reference to the task structure.
     */
    atomic_set(&new_vif->refcnt, 1);
    new_vif->shared_rings = new_ring;
    new_vif->shared_idxs  = &p->shared_info->net_idx[dom_vif_idx];
    new_vif->domain       = p;
    new_vif->idx          = dom_vif_idx;
    new_vif->list.next    = NULL;
    spin_lock_init(&new_vif->rx_lock);
    spin_lock_init(&new_vif->tx_lock);

    p->net_vif_list[dom_vif_idx] = new_vif;
    
    write_unlock_irqrestore(&tasklist_lock, flags);
    return new_vif;
    
 fail:
    write_unlock_irqrestore(&tasklist_lock, flags);
    if ( new_vif != NULL )
        kmem_cache_free(net_vif_cache, new_vif);
    if ( p != NULL )
        free_task_struct(p);
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
    for ( i = vif->rx_cons; i != vif->rx_prod; i = ((i+1) & (RX_RING_SIZE-1)) )
    {
        rx_shadow_entry_t *rx = vif->rx_shadow_ring + i;

        /* Release the page-table page. */
        page = frame_table + (rx->pte_ptr >> PAGE_SHIFT);
        put_page_type(page);
        put_page_tot(page);

        /* Give the buffer page back to the domain. */
        page = frame_table + rx->buf_pfn;
        list_add(&page->list, &p->pg_head);
        page->flags = vif->domain->domain;

        /* Patch up the PTE if it hasn't changed under our feet. */
        pte = map_domain_mem(rx->pte_ptr);
        if ( !(*pte & _PAGE_PRESENT) )
        {
            *pte = (rx->buf_pfn<<PAGE_SHIFT) | (*pte & ~PAGE_MASK) | 
                _PAGE_RW | _PAGE_PRESENT;
            page->flags |= PGT_writeable_page | PG_need_flush;
            page->type_count = page->tot_count = 1;
        }
        unmap_domain_mem(pte);
    }
    spin_unlock_irqrestore(&p->page_lock, flags);

    kmem_cache_free(net_vif_cache, vif);
    free_task_struct(p);
}

void unlink_net_vif(net_vif_t *vif)
{
    unsigned long flags;

    if ( vif == NULL )
        return;

    write_lock_irqsave(&tasklist_lock, flags);
    vif->domain->net_vif_list[vif->idx] = NULL;
    write_unlock_irqrestore(&tasklist_lock, flags);

    put_vif(vif);
}


/* vif_query - Call from the proc file system to get a list of indexes
 * in use by a particular domain.
 */
void vif_query(vif_query_t *vq)
{
    net_vif_t *vif;
    struct task_struct *p;
    char buf[128];
    int i;

    if ( !(p = find_domain_by_id(vq->domain)) ) 
        return;

    *buf = '\0';

    for ( i = 0; i < MAX_DOMAIN_VIFS; i++ )
    {
        vif = p->net_vif_list[i];
        if ( vif == NULL ) continue;
        sprintf(buf + strlen(buf), "%d\n", i);
    }

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
        return -ENOMEM;

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

void add_default_net_rule(unsigned long vif_id, u32 ipaddr)
{
    net_rule_t new_rule;

    //outbound rule.
    memset(&new_rule, 0, sizeof(net_rule_t));
    new_rule.src_addr = ipaddr;
    new_rule.src_addr_mask = 0xffffffff;
    new_rule.src_vif = vif_id;
    new_rule.dst_vif = VIF_PHYSICAL_INTERFACE;
    new_rule.action = NETWORK_ACTION_ACCEPT;
    new_rule.proto = NETWORK_PROTO_ANY;
    add_net_rule(&new_rule);

    //inbound rule;
    memset(&new_rule, 0, sizeof(net_rule_t));
    new_rule.dst_addr = ipaddr;
    new_rule.dst_addr_mask = 0xffffffff;
    new_rule.src_vif = VIF_ANY_INTERFACE;
    new_rule.dst_vif = vif_id;
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
    switch ( r->src_vif )
    {
    case VIF_PHYSICAL_INTERFACE:
        printk("=] src_dom/idx      : PHYSICAL\n"); 
        break;
    case VIF_ANY_INTERFACE:
        printk("=] src_dom/idx      : ANY\n"); 
        break;
    default:
        printk("=] src_dom/idx      : %lu/%lu\n", 
               r->src_vif>>VIF_DOMAIN_SHIFT, r->src_vif&VIF_INDEX_MASK);
        break;
    }
    switch ( r->dst_vif )
    {
    case VIF_PHYSICAL_INTERFACE:
        printk("=] dst_dom/idx      : PHYSICAL\n"); 
        break;
    case VIF_ANY_INTERFACE:
        printk("=] dst_dom/idx      : ANY\n"); 
        break;
    default:
        printk("=] dst_dom/idx      : %lu/%lu\n", 
               r->dst_vif>>VIF_DOMAIN_SHIFT, r->dst_vif&VIF_INDEX_MASK);
        break;
    }
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
static net_vif_t *net_find_rule(u8 nproto, u8 tproto, u32 src_addr, 
                                u32 dst_addr, u16 src_port, 
                                u16 dst_port, unsigned long src_vif)
{
    net_rule_ent_t *ent;
    unsigned long dest = VIF_UNKNOWN_INTERFACE;

    read_lock(&net_rule_lock);
    
    ent = net_rule_list;
    
    while ( ent != NULL )
    {
        if ( ((ent->r.src_vif == src_vif)
              || (ent->r.src_vif == VIF_ANY_INTERFACE)) &&

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
            /*
             * XXX FFS! We keep going to find the "best" rule. Where best 
             * corresponds to vaguely sane routing of a packet. We need a less 
             * shafted model for our "virtual firewall/router" methinks!
             */
            if ( (dest & VIF_DOMAIN_MASK) == VIF_SPECIAL )
                dest = ent->r.dst_vif;
            if ( (dest & VIF_DOMAIN_MASK) != VIF_SPECIAL )
                break;
        }
        ent = ent->next;
    }

    read_unlock(&net_rule_lock);

    if ( dest == VIF_PHYSICAL_INTERFACE )
        return VIF_PHYS;
    else if ( (dest & VIF_DOMAIN_MASK) == VIF_SPECIAL )
        return VIF_DROP;
    else
        return find_vif_by_id(dest);
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
net_vif_t *net_get_target_vif(u8 *data, unsigned int len, net_vif_t *src_vif)
{
    net_vif_t *target = VIF_DROP;
    u8 *h_raw, *nh_raw;
    unsigned long src_vif_val = VIF_PHYSICAL_INTERFACE;

    if ( src_vif != VIF_PHYS )
        src_vif_val = (src_vif->domain->domain<<VIF_DOMAIN_SHIFT) | 
            src_vif->idx;

    if ( len < ETH_HLEN ) goto drop;

    nh_raw = data + ETH_HLEN;
    switch ( ntohs(*(unsigned short *)(data + 12)) )
    {
    case ETH_P_ARP:
        if ( len < (ETH_HLEN + 28) ) goto drop;
        target = net_find_rule((u8)ETH_P_ARP, 0, ntohl(*(u32 *)(nh_raw + 14)),
                               ntohl(*(u32 *)(nh_raw + 24)), 0, 0, 
                               src_vif_val);
        break;

    case ETH_P_IP:
        if ( len < (ETH_HLEN + 20) ) goto drop;
        h_raw =  data + ((*(unsigned char *)(nh_raw)) & 0x0f) * 4;
        /* NB. For now we ignore ports. */
        target = net_find_rule((u8)ETH_P_IP,  *(u8 *)(data + 9),
                               ntohl(*(u32 *)(nh_raw + 12)),
                               ntohl(*(u32 *)(nh_raw + 16)),
                               0,
                               0, 
                               src_vif_val);
        break;
    }
    return target;
    
 drop:
    printk("VIF%lu/%lu: pkt to drop!\n", 
           src_vif_val>>VIF_DOMAIN_SHIFT, src_vif_val&VIF_INDEX_MASK);
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
    net_rule_list = NULL;
    net_vif_cache = kmem_cache_create("net_vif_cache", sizeof(net_vif_t),
                                    0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    net_rule_cache = kmem_cache_create("net_rule_cache", sizeof(net_rule_ent_t),
                                    0, SLAB_HWCACHE_ALIGN, NULL, NULL);
}
