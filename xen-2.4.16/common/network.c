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

/* vif globals */
int sys_vif_count;
kmem_cache_t *net_vif_cache;

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
        printk("received addrule request from guestos!\n");
    }
    break;

    case NETWORK_OP_DELETERULE:
    {
        printk("received deleterule request from guestos!\n");
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
    net_vif_cache = kmem_cache_create("net_vif_cache", sizeof(net_vif_t),
                                      0, SLAB_HWCACHE_ALIGN, NULL, NULL);
}
