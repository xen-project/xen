/* net_ring.c
 *
 * ring data structures for buffering messages between hypervisor and
 * guestos's.  As it stands this is only used for network buffer exchange.
 *
 */

#include <hypervisor-ifs/network.h>
#include <xeno/sched.h>
#include <xeno/errno.h>
#include <xeno/init.h>
#include <xeno/slab.h>
#include <xeno/spinlock.h>

/* vif globals 
 * sys_vif_list is a lookup table for vifs, used in packet forwarding.
 * it should be replaced later by something a little more flexible.
 */

int sys_vif_count;
net_vif_t *sys_vif_list[MAX_SYSTEM_VIFS];
net_rule_ent_t *net_rule_list;
kmem_cache_t *net_vif_cache;
kmem_cache_t *net_rule_cache;
static rwlock_t net_rule_lock = RW_LOCK_UNLOCKED;

net_ring_t *create_net_vif(int domain)
{
    net_vif_t *new_vif;
    net_ring_t *new_ring;
    struct task_struct *dom_task;
    
    if ( !(dom_task = find_domain_by_id(domain)) ) 
    {
            return NULL;
    }
    
    if ( (new_vif = kmem_cache_alloc(net_vif_cache, GFP_KERNEL)) == NULL )
    {
            return NULL;
    }
    dom_task->net_vif_list[dom_task->num_net_vifs] = new_vif;
    
    new_ring = dom_task->net_ring_base + dom_task->num_net_vifs;
    memset(new_ring, 0, sizeof(net_ring_t));

    dom_task->net_vif_list[dom_task->num_net_vifs]->net_ring = new_ring;
    skb_queue_head_init(
                    &dom_task->net_vif_list[dom_task->num_net_vifs]->skb_list);
    dom_task->net_vif_list[dom_task->num_net_vifs]->id = sys_vif_count++;
    dom_task->num_net_vifs++;

    return new_ring;
}

/* delete the last vif in the given domain. There doesn't seem to be any reason
 * (yet) to be able to axe an arbitrary vif, by vif id. 
 */
void destroy_net_vif(struct task_struct *p)
{
    struct sk_buff *skb;
    int i;

    if ( p->num_net_vifs <= 0 ) return; // nothing to do.
    
    i = --p->num_net_vifs;
    while ( (skb = skb_dequeue(&p->net_vif_list[i]->skb_list)) != NULL )
    {
        kfree_skb(skb);
    }
    kmem_cache_free(net_vif_cache, p->net_vif_list[i]);
}


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

int delete_net_rule(net_rule_t *rule)
{
    net_rule_ent_t *ent = net_rule_list, *prev = NULL;

    while ( (ent) && (!(memcmp(rule, &ent->r, sizeof(net_rule_t)))) )
    {
        prev = ent;
        ent = ent->next;
    }

    if (ent)
    {
        write_lock(&net_rule_lock);
        if (prev)
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
    printk("=] src_interface    : %u\n", r->src_interface);
    printk("=] dst_interface    : %u\n", r->dst_interface);
    printk("=] action           : %u\n", r->action);
}

void print_net_rule_list()
{
    net_rule_ent_t *ent = net_rule_list;
    int count = 0;
    
    while (ent) 
    {
        print_net_rule(&ent->r);
        ent = ent->next;
        count++;
    }
    printk("\nTotal of %d rules.\n", count);
}

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
    
    default:
        ret = -ENOSYS;
    }

    return ret;
}

void __init net_init (void)
{
    sys_vif_count = 0;
    net_rule_list = NULL;
    net_vif_cache = kmem_cache_create("net_vif_cache", sizeof(net_vif_t),
                                    0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    net_rule_cache = kmem_cache_create("net_rule_cache", sizeof(net_rule_ent_t),
                                    0, SLAB_HWCACHE_ALIGN, NULL, NULL);
}
