/******************************************************************************
 * network.c
 * 
 * Virtual network driver for XenoLinux.
 * 
 * Copyright (c) 2002, K A Fraser
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

#define NET_TX_IRQ _EVENT_NET_TX
#define NET_RX_IRQ _EVENT_NET_RX

#define TX_MAX_ENTRIES (TX_RING_SIZE - 2)
#define RX_MAX_ENTRIES (RX_RING_SIZE - 2)

#define TX_RING_INC(_i)    (((_i)+1) & (TX_RING_SIZE-1))
#define RX_RING_INC(_i)    (((_i)+1) & (RX_RING_SIZE-1))
#define TX_RING_ADD(_i,_j) (((_i)+(_j)) & (TX_RING_SIZE-1))
#define RX_RING_ADD(_i,_j) (((_i)+(_j)) & (RX_RING_SIZE-1))

#define RX_BUF_SIZE ((PAGE_SIZE/2)+1) /* Fool the slab allocator :-) */

static void network_rx_int(int irq, void *dev_id, struct pt_regs *ptregs);
static void network_tx_int(int irq, void *dev_id, struct pt_regs *ptregs);
static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);
static void network_free_rx_buffers(struct net_device *dev);
static void cleanup_module(void);

static struct list_head dev_list;

/*
 * RX RING:   RX_IDX <= rx_cons <= rx_prod
 * TX RING:   TX_IDX <= tx_cons <= tx_prod
 * (*_IDX allocated privately here, *_cons & *_prod shared with hypervisor)
 */
struct net_private
{
    struct list_head list;
    struct net_device *dev;

    struct net_device_stats stats;
    struct sk_buff **tx_skb_ring;
    struct sk_buff **rx_skb_ring;
    atomic_t tx_entries;
    unsigned int rx_idx, tx_idx, tx_full;
    net_ring_t *net_ring;
    spinlock_t tx_lock;
};

 
static void dbg_network_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
  struct net_device *dev = (struct net_device *)dev_id;
  struct net_private *np = dev->priv;
  printk(KERN_ALERT "tx_full = %d, tx_entries = %d, tx_idx = %d, tx_cons = %d, tx_prod = %d, tx_event = %d, state=%d\n",
	 np->tx_full, np->tx_entries, np->tx_idx, 
	 np->net_ring->tx_cons,np->net_ring->tx_prod,np->net_ring->tx_event,
	 test_bit(__LINK_STATE_XOFF, &dev->state));
}


static int network_open(struct net_device *dev)
{
    struct net_private *np = dev->priv;
    int error = 0;

    np->rx_idx = np->tx_idx = np->tx_full = 0;

    memset(&np->stats, 0, sizeof(np->stats));

    spin_lock_init(&np->tx_lock);

    atomic_set(&np->tx_entries, 0);

    np->net_ring->tx_prod = np->net_ring->tx_cons = np->net_ring->tx_event = 0;
    np->net_ring->rx_prod = np->net_ring->rx_cons = np->net_ring->rx_event = 0;
    np->net_ring->tx_ring = NULL;
    np->net_ring->rx_ring = NULL;

    np->tx_skb_ring = kmalloc(TX_RING_SIZE * sizeof(struct sk_buff *),
                              GFP_KERNEL);
    np->rx_skb_ring = kmalloc(RX_RING_SIZE * sizeof(struct sk_buff *),
                              GFP_KERNEL);
    np->net_ring->tx_ring = kmalloc(TX_RING_SIZE * sizeof(tx_entry_t), 
                                    GFP_KERNEL);
    np->net_ring->rx_ring = kmalloc(RX_RING_SIZE * sizeof(rx_entry_t), 
                                    GFP_KERNEL);
    if ( (np->tx_skb_ring == NULL) || (np->rx_skb_ring == NULL) ||
         (np->net_ring->tx_ring == NULL) || (np->net_ring->rx_ring == NULL) )
    {
        printk(KERN_WARNING "%s; Could not allocate ring memory\n", dev->name);
        error = -ENOBUFS;
        goto fail;
    }

    network_alloc_rx_buffers(dev);

    error = request_irq(NET_RX_IRQ, network_rx_int, 0, 
                        "net-rx", dev);
    if ( error )
    {
        printk(KERN_WARNING "%s: Could not allocate receive interrupt\n",
               dev->name);
        network_free_rx_buffers(dev);
        goto fail;
    }

    error = request_irq(NET_TX_IRQ, network_tx_int, 0, 
                        "net-tx", dev);
    if ( error )
    {
        printk(KERN_WARNING "%s: Could not allocate transmit interrupt\n",
               dev->name);
        free_irq(NET_RX_IRQ, dev);
        network_free_rx_buffers(dev);
        goto fail;
    }

#if 1
    request_irq( _EVENT_DEBUG, dbg_network_int, SA_SHARED, "debug", dev);    
#endif


    printk("XenoLinux Virtual Network Driver installed as %s\n", dev->name);

    netif_start_queue(dev);

    MOD_INC_USE_COUNT;

    return 0;

 fail:
    if ( np->net_ring->rx_ring ) kfree(np->net_ring->rx_ring);
    if ( np->net_ring->tx_ring ) kfree(np->net_ring->tx_ring);
    if ( np->rx_skb_ring ) kfree(np->rx_skb_ring);
    if ( np->tx_skb_ring ) kfree(np->tx_skb_ring);
    kfree(np);
    return error;
}


static void network_tx_buf_gc(struct net_device *dev)
{
    unsigned int i;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    unsigned long flags;

    spin_lock_irqsave(&np->tx_lock, flags);

    for ( i = np->tx_idx; i != np->net_ring->tx_cons; i = TX_RING_INC(i) )
    {
        skb = np->tx_skb_ring[i];
        dev_kfree_skb_any(skb);
        atomic_dec(&np->tx_entries);
    }

    np->tx_idx = i;

    if ( np->tx_full && (atomic_read(&np->tx_entries) < TX_MAX_ENTRIES) )
    {
        np->tx_full = 0;
        netif_wake_queue(dev);
    }

    spin_unlock_irqrestore(&np->tx_lock, flags);
}

inline unsigned long get_ppte(unsigned long addr)
{
    unsigned long ppte;
    pgd_t *pgd; pmd_t *pmd; pte_t *ptep;
    pgd = pgd_offset_k(addr);

    if ( pgd_none(*pgd) || pgd_bad(*pgd) ) BUG();
        
    pmd = pmd_offset(pgd, addr);
    if ( pmd_none(*pmd) || pmd_bad(*pmd) ) BUG(); 
        
    ptep = pte_offset(pmd, addr);
    ppte = (unsigned long)phys_to_machine(virt_to_phys(ptep));

    return ppte;
}

static void network_alloc_rx_buffers(struct net_device *dev)
{
    unsigned int i;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    unsigned int end = RX_RING_ADD(np->rx_idx, RX_MAX_ENTRIES);    

    for ( i = np->net_ring->rx_prod; i != end; i = RX_RING_INC(i) )
    {
        skb = dev_alloc_skb(RX_BUF_SIZE);
        if ( skb == NULL ) break;
        skb->dev = dev;
        skb_reserve(skb, 2); /* word align the IP header */
        np->rx_skb_ring[i] = skb;
        np->net_ring->rx_ring[i].addr = get_ppte((unsigned long)skb->head); 
        np->net_ring->rx_ring[i].size = RX_BUF_SIZE - 16; /* arbitrary */
    }

    np->net_ring->rx_prod = i;

    np->net_ring->rx_event = RX_RING_INC(np->rx_idx);

    HYPERVISOR_net_update();
}


static void network_free_rx_buffers(struct net_device *dev)
{
    unsigned int i;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;    

    for ( i = np->rx_idx; i != np->net_ring->rx_prod; i = RX_RING_INC(i) )
    {
        skb = np->rx_skb_ring[i];
        dev_kfree_skb_any(skb);
    }
}

static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned int i;
    struct net_private *np = (struct net_private *)dev->priv;

    if ( np->tx_full )
    {
        printk(KERN_ALERT "%s: full queue wasn't stopped!\n", dev->name);
        netif_stop_queue(dev);
        return -ENOBUFS;
    }
    i = np->net_ring->tx_prod;

    if ( (((unsigned long)skb->data & ~PAGE_MASK) + skb->len) >= PAGE_SIZE )
    {
        struct sk_buff *new_skb = dev_alloc_skb(RX_BUF_SIZE);
        if ( new_skb == NULL ) return 1;
        skb_put(new_skb, skb->len);
        memcpy(new_skb->data, skb->data, skb->len);
        dev_kfree_skb(skb);
        skb = new_skb;
    }   
    
    np->tx_skb_ring[i] = skb;
    np->net_ring->tx_ring[i].addr =
        (unsigned long)phys_to_machine(virt_to_phys(skb->data));
    np->net_ring->tx_ring[i].size = skb->len;
    np->net_ring->tx_prod = TX_RING_INC(i);
    atomic_inc(&np->tx_entries);

    np->stats.tx_bytes += skb->len;
    np->stats.tx_packets++;

    spin_lock_irq(&np->tx_lock);
    if ( atomic_read(&np->tx_entries) >= TX_MAX_ENTRIES )
    {
        np->tx_full = 1;
        netif_stop_queue(dev);
        np->net_ring->tx_event = 
            TX_RING_ADD(np->tx_idx, atomic_read(&np->tx_entries) >> 1);
    }
    else
    {
        /* Avoid unnecessary tx interrupts. */
        np->net_ring->tx_event = np->net_ring->tx_prod;
    }
    spin_unlock_irq(&np->tx_lock);

    /* Must do this after setting tx_event: race with updates of tx_cons. */
    network_tx_buf_gc(dev);

    HYPERVISOR_net_update();

    return 0;
}


static void network_rx_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    unsigned int i;
    struct net_device *dev = (struct net_device *)dev_id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    
 again:
    for ( i = np->rx_idx; i != np->net_ring->rx_cons; i = RX_RING_INC(i) )
    {
        if (np->net_ring->rx_ring[i].status != RING_STATUS_OK)
        {
            printk("bad buffer on RX ring!(%d)\n", 
                   np->net_ring->rx_ring[i].status);
            continue;
        }
        skb = np->rx_skb_ring[i];

        phys_to_machine_mapping[virt_to_phys(skb->head) >> PAGE_SHIFT] =
            (*(unsigned long *)phys_to_virt(
                machine_to_phys(np->net_ring->rx_ring[i].addr))
                ) >> PAGE_SHIFT;

        skb_put(skb, np->net_ring->rx_ring[i].size);
        skb->protocol = eth_type_trans(skb, dev);

        /*
         * Set up shinfo -- from alloc_skb This was particularily nasty:  the
         * shared info is hidden at the back of the data area (presumably so it
         * can be shared), but on page flip it gets very spunked.
         */
        atomic_set(&(skb_shinfo(skb)->dataref), 1);
        skb_shinfo(skb)->nr_frags = 0;
        skb_shinfo(skb)->frag_list = NULL;
                                
        np->stats.rx_packets++;

        np->stats.rx_bytes += np->net_ring->rx_ring[i].size;
        netif_rx(skb);
        dev->last_rx = jiffies;
    }

    np->rx_idx = i;

    network_alloc_rx_buffers(dev);
    
    /* Deal with hypervisor racing our resetting of rx_event. */
    smp_mb();
    if ( np->net_ring->rx_cons != i ) goto again;
}


static void network_tx_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    struct net_device *dev = (struct net_device *)dev_id;
    network_tx_buf_gc(dev);
}


int network_close(struct net_device *dev)
{
    struct net_private *np = dev->priv;

    netif_stop_queue(dev);

    free_irq(NET_RX_IRQ, dev);
    free_irq(NET_TX_IRQ, dev);

    /*
     * XXXX This cannot be done safely until be have a proper interface
     * for setting up and tearing down virtual interfaces on the fly.
     * Currently the receive buffers are locked down by Xen and we have
     * no sensible way of retrieving them.
     */
#if 0
    network_free_rx_buffers(dev);
    kfree(np->net_ring->rx_ring);
    kfree(np->net_ring->tx_ring);
#endif

    kfree(np->rx_skb_ring);
    kfree(np->tx_skb_ring);

    MOD_DEC_USE_COUNT;

    return 0;
}


static struct net_device_stats *network_get_stats(struct net_device *dev)
{
    struct net_private *np = (struct net_private *)dev->priv;
    return &np->stats;
}


int __init init_module(void)
{
    int i, err;
    struct net_device *dev;
    struct net_private *np;

    INIT_LIST_HEAD(&dev_list);

    for ( i = 0; i < start_info.num_net_rings; i++ )
    {
        dev = alloc_etherdev(sizeof(struct net_private));
        if ( dev == NULL )
        {
            err = -ENOMEM;
            goto fail;
        }

        np = dev->priv;
        np->net_ring = start_info.net_rings + i;

        SET_MODULE_OWNER(dev);
        dev->open            = network_open;
        dev->hard_start_xmit = network_start_xmit;
        dev->stop            = network_close;
        dev->get_stats       = network_get_stats;

        memset(dev->dev_addr, 0, ETH_ALEN);
        *(unsigned int *)(dev->dev_addr + 1) = i;

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
}


module_init(init_module);
module_exit(cleanup_module);
