/******************************************************************************
 * network.c
 *
 * Network virtualization for Xen.  Lower-level network interactions are in 
 * net/dev.c and in the drivers.  This file contains routines to interact 
 * with the virtual interfaces (vifs) and the virtual firewall/router through
 * the use of rules.
 *
 * Copyright (c) 2002-2003, A K Warfield and K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/slab.h>
#include <xen/spinlock.h>
#include <xen/if_ether.h>
#include <xen/skbuff.h>
#include <xen/netdevice.h>
#include <xen/in.h>
#include <asm/domain_page.h>
#include <asm/io.h>
#include <hypervisor-ifs/network.h>

net_rule_ent_t *net_rule_list;                      /* global list of rules */
kmem_cache_t *net_vif_cache;                        
kmem_cache_t *net_rule_cache;
static rwlock_t net_rule_lock = RW_LOCK_UNLOCKED;   /* rule mutex */

void print_net_rule_list();


/* ----[ VIF Functions ]----------------------------------------------------*/


net_vif_t *find_net_vif(domid_t dom, unsigned int idx)
{
    struct task_struct *p;
    net_vif_t *vif = NULL;
    unsigned long flags;

    read_lock_irqsave(&tasklist_lock, flags);
    p = task_hash[TASK_HASH(dom)];
    while ( p != NULL )
    {
        if ( p->domain == dom )
        {
            vif = p->net_vif_list[idx];
            if ( vif != NULL )
                get_vif(vif);
            break;
        }
        p = p->next_hash;
    }
    read_unlock_irqrestore(&tasklist_lock, flags);

    return vif;
}


/*
 * create_net_vif - Create a new vif and append it to the specified domain.
 * 
 * The domain is examined to determine how many vifs currently are allocated
 * and the newly allocated vif is appended.  The vif is also added to the
 * global list.
 * 
 */
net_vif_t *create_net_vif(domid_t dom)
{
    unsigned int idx;
    net_vif_t *new_vif = NULL;
    net_ring_t *new_ring = NULL;
    struct task_struct *p = NULL;
    unsigned long flags, vmac_hash;
    unsigned char vmac_key[ETH_ALEN + 2 + MAX_DOMAIN_NAME];

    if ( (p = find_domain_by_id(dom)) == NULL )
        return NULL;
    
    write_lock_irqsave(&tasklist_lock, flags);

    for ( idx = 0; idx < MAX_DOMAIN_VIFS; idx++ )
        if ( p->net_vif_list[idx] == NULL )
            break;
    if ( idx == MAX_DOMAIN_VIFS )
        goto fail;

    if ( (new_vif = kmem_cache_alloc(net_vif_cache, GFP_KERNEL)) == NULL )
        goto fail;

    memset(new_vif, 0, sizeof(*new_vif));
    
    if ( sizeof(net_ring_t) > PAGE_SIZE )
        BUG();
    new_ring = (net_ring_t *)get_free_page(GFP_KERNEL);
    clear_page(new_ring);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(new_ring), p);

    /*
     * Fill in the new vif struct. Note that, while the vif's refcnt is
     * non-zero, we hold a reference to the task structure.
     */
    atomic_set(&new_vif->refcnt, 1);
    new_vif->shared_rings = new_ring;
    new_vif->shared_idxs  = &p->shared_info->net_idx[idx];
    new_vif->domain       = p;
    new_vif->idx          = idx;
    new_vif->list.next    = NULL;
    spin_lock_init(&new_vif->rx_lock);
    spin_lock_init(&new_vif->tx_lock);

    new_vif->credit_bytes = new_vif->remaining_credit = ~0UL;
    new_vif->credit_usec  = 0UL;
    init_ac_timer(&new_vif->credit_timeout);

    if ( (p->domain == 0) && (idx == 0) )
    {
        /*
         * DOM0/VIF0 gets the real physical MAC address, so that users can
         * easily get a Xen-based machine up and running by using an existing
         * DHCP entry.
         */
        memcpy(new_vif->vmac, the_dev->dev_addr, ETH_ALEN);
    }
    else
    {
        /*
         * Most VIFs get a random MAC address with a "special" vendor id.
         * We try to get MAC addresses to be unique across multiple servers
         * by including the physical MAC address in the hash. The hash also
         * includes the vif index and the domain's name.
         * 
         * NB. The vendor is currently an "obsolete" one that used to belong
         * to DEC (AA-00-00). Using it is probably a bit rude :-)
         * 
         * NB2. The first bit of the first random octet is set to zero for
         * all dynamic MAC addresses. This may allow us to manually specify
         * MAC addresses for some VIFs with no fear of clashes.
         */
        memcpy(&vmac_key[0], the_dev->dev_addr, ETH_ALEN);
        *(__u16 *)(&vmac_key[ETH_ALEN]) = htons(idx);
        strcpy(&vmac_key[ETH_ALEN+2], p->name);
        vmac_hash = hash(vmac_key, ETH_ALEN + 2 + strlen(p->name));
        memcpy(new_vif->vmac, "\xaa\x00\x00", 3);
        new_vif->vmac[3] = (vmac_hash >> 16) & 0xef; /* First bit is zero. */
        new_vif->vmac[4] = (vmac_hash >>  8) & 0xff;
        new_vif->vmac[5] = (vmac_hash >>  0) & 0xff;
    }

    p->net_vif_list[idx] = new_vif;
    
    write_unlock_irqrestore(&tasklist_lock, flags);
    return new_vif;
    
 fail:
    write_unlock_irqrestore(&tasklist_lock, flags);
    if ( new_vif != NULL )
        kmem_cache_free(net_vif_cache, new_vif);
    if ( p != NULL )
        put_task_struct(p);
    return NULL;
}

void destroy_net_vif(net_vif_t *vif)
{
    extern long flush_bufs_for_vif(net_vif_t *vif);
    struct task_struct *p = vif->domain;
    (void)flush_bufs_for_vif(vif);
    UNSHARE_PFN(virt_to_page(vif->shared_rings));
    kmem_cache_free(net_vif_cache, vif);
    put_task_struct(p);
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


int vif_query(vif_query_t *vq)
{
    net_vif_t *vif;
    struct task_struct *p;
    int buf[32];
    int i;
    int count = 0;

    if ( (p = find_domain_by_id(vq->domain)) == NULL )
    {
        buf[0] = -1;
        copy_to_user(vq->buf, buf, sizeof(int));
        return -ESRCH;
    }

    for ( i = 0; i < MAX_DOMAIN_VIFS; i++ )
    {
        vif = p->net_vif_list[i];
        if ( vif == NULL ) continue;
        buf[++count] = i;
    }

    buf[0] = count;

    copy_to_user(vq->buf, buf, (buf[0] + 1) * sizeof(int));
    
    put_task_struct(p);

    return 0;
}

int vif_getinfo(vif_getinfo_t *info)
{
    net_vif_t *vif;

    if ( (vif = find_net_vif(info->domain, info->vif)) == NULL )
        return -ESRCH;

    info->total_bytes_sent              = vif->total_bytes_sent;
    info->total_bytes_received          = vif->total_bytes_received;
    info->total_packets_sent            = vif->total_packets_sent;
    info->total_packets_received        = vif->total_packets_received;

    info->credit_bytes = vif->credit_bytes;
    info->credit_usec  = vif->credit_usec;

    put_vif(vif);

    return 0;
}


int vif_setparams(vif_setparams_t *params)
{
    net_vif_t *vif;

    if ( (vif = find_net_vif(params->domain, params->vif)) == NULL )
        return -ESRCH;

    /* Turning off rate limiting? */
    if ( params->credit_usec == 0 )
        params->credit_bytes = ~0UL;

    vif->credit_bytes = vif->remaining_credit = params->credit_bytes;
    vif->credit_usec  = params->credit_usec;

    put_vif(vif);

    return 0;    
}

        
/* ----[ Net Rule Functions ]-----------------------------------------------*/

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

int delete_net_rule(net_rule_t *rule)
{
    net_rule_ent_t **pent, *ent;

    write_lock(&net_rule_lock);

    for ( pent = &net_rule_list; (ent = *pent) != NULL; pent = &ent->next )
    {
        if ( memcmp(rule, &ent->r, sizeof(net_rule_t)) == 0 )
        {
            *pent = ent->next;
            kmem_cache_free(net_rule_cache, ent);
            break;
        }
    }

    write_unlock(&net_rule_lock);
    return 0;
}

void delete_all_domain_vfr_rules(struct task_struct *p)
{
    net_rule_ent_t **pent, *ent;

    write_lock(&net_rule_lock);

    for ( pent = &net_rule_list; (ent = *pent) != NULL; )
    {
        if ( (ent->r.src_dom == p->domain) || (ent->r.dst_dom == p->domain) )
        {
            *pent = ent->next;
            kmem_cache_free(net_rule_cache, ent);
            continue;
        }

        pent = &ent->next;
    }

    write_unlock(&net_rule_lock);
}
 
static char *idx_to_name(unsigned int idx)
{
    if ( idx == VIF_PHYSICAL_INTERFACE )
        return "PHYSICAL";
    if ( idx ==  VIF_ANY_INTERFACE )
        return "ANY";
    return "UNKNOWN";
}

static char *print_ip_addr(char *buf, unsigned long addr)
{
    sprintf(buf, "%lu.%lu.%lu.%lu", 
            (addr>>24)&255, (addr>>16)&255, (addr>>8)&255, addr&255);
    return buf;
}

void print_net_rule(net_rule_t *r)
{
    char buf[20];

    printk("===] NET RULE:\n");
    printk("=] src_addr         : %s\n", print_ip_addr(buf, r->src_addr));
    printk("=] src_addr_mask    : %s\n", print_ip_addr(buf, r->src_addr_mask));
    printk("=] dst_addr         : %s\n", print_ip_addr(buf, r->dst_addr));
    printk("=] dst_addr_mask    : %s\n", print_ip_addr(buf, r->dst_addr_mask));
    printk("=] src_port         : %u\n", r->src_port);
    printk("=] src_port_mask    : %u\n", r->src_port_mask);
    printk("=] dst_port         : %u\n", r->dst_port);
    printk("=] dst_port_mask    : %u\n", r->dst_port_mask);
    printk("=] dst_proto        : %u\n", r->proto);

    if ( r->src_dom == VIF_SPECIAL )
        printk("=] src_dom/idx      : %s\n", idx_to_name(r->src_idx));
    else
        printk("=] src_dom/idx      : %llu/%u\n", r->src_dom, r->src_idx);

    if ( r->dst_dom == VIF_SPECIAL )
        printk("=] dst_dom/idx      : %s\n", idx_to_name(r->dst_idx));
    else
        printk("=] dst_dom/idx      : %llu/%u\n", r->dst_dom, r->dst_idx);

    printk("=] action           : %u\n", r->action);
}

void print_net_rule_list(void)
{
    net_rule_ent_t *ent;
    int count = 0;
    
    read_lock(&net_rule_lock);

    ent = net_rule_list;
    
    while ( ent != NULL )
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
                                u16 dst_port, 
                                domid_t src_dom, unsigned int src_idx)
{
    net_rule_ent_t *ent;
    domid_t dst_dom = VIF_SPECIAL;
    unsigned int dst_idx = VIF_UNKNOWN_INTERFACE;

    read_lock(&net_rule_lock);
    
    ent = net_rule_list;
    
    while ( ent != NULL )
    {
        if ( (((ent->r.src_dom == src_dom) && 
               (ent->r.src_idx == src_idx)) ||
              ((ent->r.src_dom == VIF_SPECIAL) && 
               (ent->r.src_idx == VIF_ANY_INTERFACE))) &&

             ((src_dom != ent->r.dst_dom) ||
              (src_idx != ent->r.dst_idx)) &&

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
            dst_dom = ent->r.dst_dom;
            dst_idx = ent->r.dst_idx;
            /*
             * XXX FFS! We keep going to find the "best" rule. Where best 
             * corresponds to vaguely sane routing of a packet. We need a less 
             * shafted model for our "virtual firewall/router" methinks!
             */
            if ( dst_dom != VIF_SPECIAL )
                break;
        }
        ent = ent->next;
    }

    read_unlock(&net_rule_lock);

    if ( dst_dom == VIF_SPECIAL ) 
    {
        if ( dst_idx == VIF_PHYSICAL_INTERFACE )
            return VIF_PHYS;
        return VIF_DROP;
    }

    return find_net_vif(dst_dom, dst_idx);
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
    domid_t src_dom = VIF_SPECIAL;
    unsigned int src_idx = VIF_PHYSICAL_INTERFACE;

    if ( src_vif != VIF_PHYS )
    {
        src_dom = src_vif->domain->domain;
        src_idx = src_vif->idx;
    }

    if ( len < ETH_HLEN )
        goto drop;

    nh_raw = data + ETH_HLEN;
    switch ( ntohs(*(unsigned short *)(data + 12)) )
    {
    case ETH_P_ARP:
        if ( len < (ETH_HLEN + 28) ) goto drop;
        target = net_find_rule((u8)ETH_P_ARP, 0, ntohl(*(u32 *)(nh_raw + 14)),
                               ntohl(*(u32 *)(nh_raw + 24)), 0, 0, 
                               src_dom, src_idx);
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
                               src_dom, src_idx);
        break;
    }
    return target;
    
 drop:
    printk("VIF%llu/%u: pkt to drop!\n", 
           src_dom, src_idx);
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
        /*
         * This should ship a rule list up to the guest OS. For now
         * we just dump the rules to our own console.
         */
        print_net_rule_list();
    }
    break;

    case NETWORK_OP_VIFGETINFO:
    {
        ret = vif_getinfo(&op.u.vif_getinfo);
        copy_to_user(u_network_op, &op, sizeof(op));
    }
    break;

    case NETWORK_OP_VIFQUERY:
    {
        ret = vif_query(&op.u.vif_query);
    }
    break;
    
    case NETWORK_OP_VIFSETPARAMS:
    {
        ret = vif_setparams(&op.u.vif_setparams);
    }
    break;
    
    default:
        ret = -ENOSYS;
    }

    return ret;
}

void __init net_init (void)
{
    net_rule_list = NULL;
    net_vif_cache = kmem_cache_create("net_vif_cache", 
                                      sizeof(net_vif_t),
                                      0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    net_rule_cache = kmem_cache_create("net_rule_cache", 
                                       sizeof(net_rule_ent_t),
                                       0, SLAB_HWCACHE_ALIGN, NULL, NULL);
}
