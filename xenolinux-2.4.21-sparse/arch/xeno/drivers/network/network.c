/******************************************************************************
 * network.c
 * 
 * Virtual network driver for XenoLinux.
 * 
 * Copyright (c) 2002-2003, K A Fraser
 */

#include <linux/config.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>

#include <asm/io.h>
#include <net/sock.h>
#include <net/pkt_sched.h>

#define NET_IRQ _EVENT_NET

#define TX_MAX_ENTRIES (TX_RING_SIZE - 2)
#define RX_MAX_ENTRIES (RX_RING_SIZE - 2)

#define TX_RING_INC(_i)    (((_i)+1) & (TX_RING_SIZE-1))
#define RX_RING_INC(_i)    (((_i)+1) & (RX_RING_SIZE-1))
#define TX_RING_ADD(_i,_j) (((_i)+(_j)) & (TX_RING_SIZE-1))
#define RX_RING_ADD(_i,_j) (((_i)+(_j)) & (RX_RING_SIZE-1))

#define RX_BUF_SIZE ((PAGE_SIZE/2)+1) /* Fool the slab allocator :-) */

static void network_interrupt(int irq, void *dev_id, struct pt_regs *ptregs);
static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);
static void network_free_rx_buffers(struct net_device *dev);
static void cleanup_module(void);

static struct list_head dev_list;

/*
 * Needed because network_close() is not properly implemented yet. So
 * an open after a close needs to do much less than the initial open.
 */
static int opened_once_already = 0;

struct net_private
{
    struct list_head list;
    struct net_device *dev;

    struct net_device_stats stats;
    atomic_t tx_entries;
    unsigned int rx_resp_cons, tx_resp_cons, tx_full;
    net_ring_t *net_ring;
    net_idx_t  *net_idx;
    spinlock_t tx_lock;
    unsigned int idx; /* Domain-specific index of this VIF. */

    unsigned int rx_bufs_to_notify;

    /*
     * {tx,rx}_skbs store outstanding skbuffs. The first entry in each
     * array is an index into a chain of free entries.
     */
    struct sk_buff *tx_skbs[TX_RING_SIZE];
    struct sk_buff *rx_skbs[RX_RING_SIZE];
};

/* Access macros for acquiring freeing slots in {tx,rx}_skbs[]. */
#define ADD_ID_TO_FREELIST(_list, _id)             \
    (_list)[(_id)] = (_list)[0];                   \
    (_list)[0]     = (void *)(unsigned long)(_id);
#define GET_ID_FROM_FREELIST(_list)                \
 ({ unsigned long _id = (unsigned long)(_list)[0]; \
    (_list)[0]  = (_list)[_id];                    \
    _id; })


static void dbg_network_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    struct net_device *dev = (struct net_device *)dev_id;
    struct net_private *np = dev->priv;
    printk(KERN_ALERT "tx_full = %d, tx_entries = %d, tx_resp_cons = %d,"
           " tx_req_prod = %d, tx_resp_prod = %d, tx_event = %d, state=%d\n",
           np->tx_full, atomic_read(&np->tx_entries), np->tx_resp_cons, 
           np->net_idx->tx_req_prod, np->net_idx->tx_resp_prod, 
           np->net_idx->tx_event,
           test_bit(__LINK_STATE_XOFF, &dev->state));
    printk(KERN_ALERT "rx_resp_cons = %d,"
           " rx_req_prod = %d, rx_resp_prod = %d, rx_event = %d\n",
           np->rx_resp_cons, np->net_idx->rx_req_prod,
           np->net_idx->rx_resp_prod, np->net_idx->rx_event);
}


static int network_open(struct net_device *dev)
{
    struct net_private *np = dev->priv;
    int i, error = 0;

    if ( opened_once_already )
    {
        memset(&np->stats, 0, sizeof(np->stats));
        netif_start_queue(dev);
        return 0;
    }

    np->rx_bufs_to_notify = 0;
    np->rx_resp_cons = np->tx_resp_cons = np->tx_full = 0;
    memset(&np->stats, 0, sizeof(np->stats));
    spin_lock_init(&np->tx_lock);
    atomic_set(&np->tx_entries, 0);
    memset(np->net_ring, 0, sizeof(*np->net_ring));
    memset(np->net_idx, 0, sizeof(*np->net_idx));

    /* Initialise {tx,rx}_skbs to be a free chain containing every entry. */
    for ( i = 0; i < TX_RING_SIZE; i++ )
        np->tx_skbs[i] = (void *)(i+1);
    for ( i = 0; i < RX_RING_SIZE; i++ )
        np->rx_skbs[i] = (void *)(i+1);

    network_alloc_rx_buffers(dev);

    error = request_irq(NET_IRQ, network_interrupt, 
                        SA_SAMPLE_RANDOM, "network", dev);
    if ( error )
    {
        printk(KERN_WARNING "%s: Could not allocate network interrupt\n",
               dev->name);
        network_free_rx_buffers(dev);
        goto fail;
    }

    error = request_irq(_EVENT_DEBUG, dbg_network_int, SA_SHIRQ,
                        "debug", dev);
    if ( error )
    {
        printk(KERN_WARNING "%s: Non-fatal error -- no debug interrupt\n",
               dev->name);
    }

    printk("XenoLinux Virtual Network Driver installed as %s\n", dev->name);

    netif_start_queue(dev);

    MOD_INC_USE_COUNT;

    opened_once_already = 1;

    return 0;

 fail:
    kfree(np);
    return error;
}


static void network_tx_buf_gc(struct net_device *dev)
{
    unsigned int i;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    unsigned int prod;
    tx_entry_t *tx_ring = np->net_ring->tx_ring;

    do {
        prod = np->net_idx->tx_resp_prod;

        for ( i = np->tx_resp_cons; i != prod; i = TX_RING_INC(i) )
        {
            skb = np->tx_skbs[tx_ring[i].resp.id];
            ADD_ID_TO_FREELIST(np->tx_skbs, tx_ring[i].resp.id);
            dev_kfree_skb_any(skb);
            atomic_dec(&np->tx_entries);
        }
        
        np->tx_resp_cons = prod;
        
        /* Set a new event, then check for race with update of tx_cons. */
        np->net_idx->tx_event =
            TX_RING_ADD(prod, (atomic_read(&np->tx_entries)>>1) + 1);
        smp_mb();
    }
    while ( prod != np->net_idx->tx_resp_prod );

    if ( np->tx_full && (atomic_read(&np->tx_entries) < TX_MAX_ENTRIES) )
    {
        np->tx_full = 0;
        netif_wake_queue(dev);
    }
}


static inline pte_t *get_ppte(void *addr)
{
    pgd_t *pgd; pmd_t *pmd; pte_t *pte;
    pgd = pgd_offset_k(   (unsigned long)addr);
    pmd = pmd_offset(pgd, (unsigned long)addr);
    pte = pte_offset(pmd, (unsigned long)addr);
    return pte;
}


static void network_alloc_rx_buffers(struct net_device *dev)
{
    unsigned int i, id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    unsigned int end = RX_RING_ADD(np->rx_resp_cons, RX_MAX_ENTRIES);    

    if ( (i = np->net_idx->rx_req_prod) == end )
        return;

    do {
        skb = dev_alloc_skb(RX_BUF_SIZE);
        if ( skb == NULL ) break;
        skb->dev = dev;

        id = GET_ID_FROM_FREELIST(np->rx_skbs);
        np->rx_skbs[id] = skb;

        np->net_ring->rx_ring[i].req.id   = (unsigned short)id;
        np->net_ring->rx_ring[i].req.addr = 
            virt_to_machine(get_ppte(skb->head));

        np->rx_bufs_to_notify++;
    }
    while ( (i = RX_RING_INC(i)) != end );

    /*
     * We may have allocated buffers which have entries outstanding in the page
     * update queue -- make sure we flush those first!
     */
    flush_page_update_queue();

    np->net_idx->rx_req_prod = i;
    np->net_idx->rx_event    = RX_RING_INC(np->rx_resp_cons);
        
    /* Batch Xen notifications. */
    if ( np->rx_bufs_to_notify > (RX_MAX_ENTRIES/4) )
    {
        HYPERVISOR_net_update();
        np->rx_bufs_to_notify = 0;
    }
}


static void network_free_rx_buffers(struct net_device *dev)
{
    unsigned int i;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;    

    for ( i  = np->rx_resp_cons; 
          i != np->net_idx->rx_req_prod; 
          i  = RX_RING_INC(i) )
    {
        skb = np->rx_skbs[np->net_ring->rx_ring[i].req.id];
        dev_kfree_skb_any(skb);
    }
}

static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned int i, id;
    struct net_private *np = (struct net_private *)dev->priv;

    if ( np->tx_full )
    {
        printk(KERN_ALERT "%s: full queue wasn't stopped!\n", dev->name);
        netif_stop_queue(dev);
        return -ENOBUFS;
    }

    if ( (((unsigned long)skb->data & ~PAGE_MASK) + skb->len) >= PAGE_SIZE )
    {
        struct sk_buff *new_skb = dev_alloc_skb(RX_BUF_SIZE);
        if ( new_skb == NULL ) return 1;
        skb_put(new_skb, skb->len);
        memcpy(new_skb->data, skb->data, skb->len);
        dev_kfree_skb(skb);
        skb = new_skb;
    }   
    
    spin_lock_irq(&np->tx_lock);

    i = np->net_idx->tx_req_prod;

    id = GET_ID_FROM_FREELIST(np->tx_skbs);
    np->tx_skbs[id] = skb;

    np->net_ring->tx_ring[i].req.id   = (unsigned short)id;
    np->net_ring->tx_ring[i].req.addr =
        phys_to_machine(virt_to_phys(skb->data));
    np->net_ring->tx_ring[i].req.size = skb->len;
    np->net_idx->tx_req_prod = TX_RING_INC(i);
    atomic_inc(&np->tx_entries);

    network_tx_buf_gc(dev);

    if ( atomic_read(&np->tx_entries) >= TX_MAX_ENTRIES )
    {
        np->tx_full = 1;
        netif_stop_queue(dev);
    }

    spin_unlock_irq(&np->tx_lock);

    np->stats.tx_bytes += skb->len;
    np->stats.tx_packets++;

    /* Only notify Xen if there are no outstanding responses. */
    smp_wmb();
    if ( np->net_idx->tx_resp_prod == i )
        HYPERVISOR_net_update();

    return 0;
}


static void network_interrupt(int irq, void *dev_id, struct pt_regs *ptregs)
{
    unsigned int i;
    unsigned long flags;
    struct net_device *dev = (struct net_device *)dev_id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    rx_resp_entry_t *rx;
    
    spin_lock_irqsave(&np->tx_lock, flags);
    network_tx_buf_gc(dev);
    spin_unlock_irqrestore(&np->tx_lock, flags);

 again:
    for ( i  = np->rx_resp_cons; 
          i != np->net_idx->rx_resp_prod; 
          i  = RX_RING_INC(i) )
    {
        rx  = &np->net_ring->rx_ring[i].resp;

        skb = np->rx_skbs[rx->id];
        ADD_ID_TO_FREELIST(np->rx_skbs, rx->id);

        if ( rx->status != RING_STATUS_OK )
        {
            printk(KERN_ALERT "bad buffer on RX ring!(%d)\n", rx->status);
            dev_kfree_skb_any(skb);
            continue;
        }

        /*
         * Set up shinfo -- from alloc_skb This was particularily nasty:  the
         * shared info is hidden at the back of the data area (presumably so it
         * can be shared), but on page flip it gets very spunked.
         */
        atomic_set(&(skb_shinfo(skb)->dataref), 1);
        skb_shinfo(skb)->nr_frags = 0;
        skb_shinfo(skb)->frag_list = NULL;
                                
        phys_to_machine_mapping[virt_to_phys(skb->head) >> PAGE_SHIFT] =
            (*(unsigned long *)get_ppte(skb->head)) >> PAGE_SHIFT;

        if ( rx->offset < 16 )
        {
            printk(KERN_ALERT "need pkt offset >= 16 (got %d)\n", rx->offset);
            dev_kfree_skb_any(skb);
            continue;
        }
        
        skb_reserve(skb, rx->offset - 16);

        skb_put(skb, rx->size);
        skb->protocol = eth_type_trans(skb, dev);

        np->stats.rx_packets++;

        np->stats.rx_bytes += rx->size;
        netif_rx(skb);
        dev->last_rx = jiffies;
    }

    np->rx_resp_cons = i;

    network_alloc_rx_buffers(dev);
    
    /* Deal with hypervisor racing our resetting of rx_event. */
    smp_mb();
    if ( np->net_idx->rx_resp_prod != i ) goto again;
}


int network_close(struct net_device *dev)
{
    netif_stop_queue(dev);

    /*
     * XXXX This cannot be done safely until be have a proper interface
     * for setting up and tearing down virtual interfaces on the fly.
     * Currently the receive buffers are locked down by Xen and we have
     * no sensible way of retrieving them.
     */
#if 0
    free_irq(NET_IRQ, dev);

    network_free_rx_buffers(dev);
    kfree(np->net_ring->rx_ring);
    kfree(np->net_ring->tx_ring);

    MOD_DEC_USE_COUNT;
#endif

    return 0;
}


static struct net_device_stats *network_get_stats(struct net_device *dev)
{
    struct net_private *np = (struct net_private *)dev->priv;
    return &np->stats;
}


/*
 * This notifier is installed for domain 0 only.
 * All other domains have VFR rules installed on their behalf by domain 0
 * when they are created. For bootstrap, Xen creates wildcard rules for
 * domain 0 -- this notifier is used to detect when we find our proper
 * IP address, so we can poke down proper rules and remove the wildcards.
 */
static int inetdev_notify(struct notifier_block *this, 
                          unsigned long event, 
                          void *ptr)
{
    struct in_ifaddr  *ifa  = (struct in_ifaddr *)ptr; 
    struct net_device *dev = ifa->ifa_dev->dev;
    struct list_head  *ent;
    struct net_private *np;
    int idx = -1;
    network_op_t op;

    list_for_each ( ent, &dev_list )
    {
        np = list_entry(dev_list.next, struct net_private, list);
        if ( np->dev == dev )
            idx = np->idx;
    }

    if ( idx == -1 )
        goto out;
    
    memset(&op, 0, sizeof(op));
    op.u.net_rule.proto         = NETWORK_PROTO_ANY;
    op.u.net_rule.action        = NETWORK_ACTION_ACCEPT;

    if ( event == NETDEV_UP )
        op.cmd = NETWORK_OP_ADDRULE;
    else if ( event == NETDEV_DOWN )
        op.cmd = NETWORK_OP_DELETERULE;
    else
        goto out;

    op.u.net_rule.src_vif       = idx;
    op.u.net_rule.dst_vif       = VIF_PHYSICAL_INTERFACE;
    op.u.net_rule.src_addr      = ntohl(ifa->ifa_address);
    op.u.net_rule.src_addr_mask = ~0UL;
    op.u.net_rule.dst_addr      = 0;
    op.u.net_rule.dst_addr_mask = 0;
    (void)HYPERVISOR_network_op(&op);
    
    op.u.net_rule.src_vif       = VIF_ANY_INTERFACE;
    op.u.net_rule.dst_vif       = idx;
    op.u.net_rule.src_addr      = 0;
    op.u.net_rule.src_addr_mask = 0;    
    op.u.net_rule.dst_addr      = ntohl(ifa->ifa_address);
    op.u.net_rule.dst_addr_mask = ~0UL;
    (void)HYPERVISOR_network_op(&op);
    
 out:
    return NOTIFY_DONE;
}

static struct notifier_block notifier_inetdev = {
    .notifier_call  = inetdev_notify,
    .next           = NULL,
    .priority       = 0
};


int __init init_module(void)
{
    int i, fixmap_idx=-1, err;
    struct net_device *dev;
    struct net_private *np;

    INIT_LIST_HEAD(&dev_list);

    /*
     * Domain 0 must poke its own network rules as it discovers its IP
     * addresses. All other domains have a privileged "parent" to do this for
     * them at start of day.
     */
    if ( start_info.dom_id == 0 )
        (void)register_inetaddr_notifier(&notifier_inetdev);

    for ( i = 0; i < MAX_DOMAIN_VIFS; i++ )
    {
        if ( start_info.net_rings[i] == 0 )
            continue;

        /* We actually only support up to 4 vifs right now. */
        if ( ++fixmap_idx == 4 )
            break;

        dev = alloc_etherdev(sizeof(struct net_private));
        if ( dev == NULL )
        {
            err = -ENOMEM;
            goto fail;
        }

        set_fixmap(FIX_NETRING0_BASE+fixmap_idx, start_info.net_rings[i]);

        np = dev->priv;
        np->net_ring = (net_ring_t *)fix_to_virt(FIX_NETRING0_BASE+fixmap_idx);
        np->net_idx  = &HYPERVISOR_shared_info->net_idx[i];
        np->idx      = i;

        SET_MODULE_OWNER(dev);
        dev->open            = network_open;
        dev->hard_start_xmit = network_start_xmit;
        dev->stop            = network_close;
        dev->get_stats       = network_get_stats;

        memcpy(dev->dev_addr, start_info.net_vmac[i], ETH_ALEN);

        if ( (err = register_netdev(dev)) != 0 )
        {
            kfree(dev);
            goto fail;
        }

        np->dev = dev;
        list_add(&np->list, &dev_list);
    }

    return 0;

 fail:
    cleanup_module();
    return err;
}


static void cleanup_module(void)
{
    struct net_private *np;
    struct net_device *dev;

    while ( !list_empty(&dev_list) )
    {
        np = list_entry(dev_list.next, struct net_private, list);
        list_del(&np->list);
        dev = np->dev;
        unregister_netdev(dev);
        kfree(dev);
    }

    if ( start_info.dom_id == 0 )
        (void)unregister_inetaddr_notifier(&notifier_inetdev);
}


module_init(init_module);
module_exit(cleanup_module);
