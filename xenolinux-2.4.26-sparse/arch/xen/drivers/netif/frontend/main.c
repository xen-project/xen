/******************************************************************************
 * arch/xen/drivers/netif/frontend/main.c
 * 
 * Virtual network driver for XenoLinux.
 * 
 * Copyright (c) 2002-2004, K A Fraser
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

#include "../netif.h"

static struct tq_struct netif_statechange_tq;

#define RX_BUF_SIZE ((PAGE_SIZE/2)+1) /* Fool the slab allocator :-) */

static void network_interrupt(int irq, void *dev_id, struct pt_regs *ptregs);
static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);
static void cleanup_module(void);

/* Dynamically-mapped IRQs. */
static int network_irq, debug_irq;

static struct list_head dev_list;

struct net_private
{
    struct list_head list;
    struct net_device *dev;

    struct net_device_stats stats;
    NET_RING_IDX rx_resp_cons, tx_resp_cons;
    unsigned int tx_full;
    
    netif_tx_interface_t *tx;
    netif_rx_interface_t *rx;

    spinlock_t   tx_lock;

    unsigned int handle;
    unsigned int evtchn;
    unsigned int irq;

#define NETIF_STATE_CLOSED       0
#define NETIF_STATE_DISCONNECTED 1
#define NETIF_STATE_CONNECTED    2
#define NETIF_STATE_ACTIVE       3
    unsigned int state;

    /*
     * {tx,rx}_skbs store outstanding skbuffs. The first entry in each
     * array is an index into a chain of free entries.
     */
    struct sk_buff *tx_skbs[XENNET_TX_RING_SIZE+1];
    struct sk_buff *rx_skbs[XENNET_RX_RING_SIZE+1];
};

/* Access macros for acquiring freeing slots in {tx,rx}_skbs[]. */
#define ADD_ID_TO_FREELIST(_list, _id)             \
    (_list)[(_id)] = (_list)[0];                   \
    (_list)[0]     = (void *)(unsigned long)(_id);
#define GET_ID_FROM_FREELIST(_list)                \
 ({ unsigned long _id = (unsigned long)(_list)[0]; \
    (_list)[0]  = (_list)[_id];                    \
    (unsigned short)_id; })


static struct net_device *find_dev_by_handle(unsigned int handle)
{
    struct list_head *ent;
    struct net_private *np;
    list_for_each ( ent, &dev_list )
    {
        np = list_entry(ent, struct net_private, list);
        if ( np->handle == handle )
            return np;
    }
    return NULL;
}


static int network_open(struct net_device *dev)
{
    struct net_private *np = dev->priv;
    netop_t netop;
    int i, ret;

    if ( np->state != NETIF_STATE_CONNECTED )
        return -EINVAL;

    np->rx_resp_cons = np->tx_resp_cons = np->tx_full = 0;
    memset(&np->stats, 0, sizeof(np->stats));
    spin_lock_init(&np->tx_lock);

    /* Initialise {tx,rx}_skbs to be a free chain containing every entry. */
    for ( i = 0; i <= XENNET_TX_RING_SIZE; i++ )
        np->tx_skbs[i] = (void *)(i+1);
    for ( i = 0; i <= XENNET_RX_RING_SIZE; i++ )
        np->rx_skbs[i] = (void *)(i+1);

    wmb();
    np->state = NETIF_STATE_ACTIVE;

    network_alloc_rx_buffers(dev);

    netif_start_queue(dev);

    MOD_INC_USE_COUNT;

    return 0;
}


static void network_tx_buf_gc(struct net_device *dev)
{
    NET_RING_IDX i, prod;
    unsigned short id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    tx_entry_t *tx_ring = np->net_ring->tx_ring;

    do {
        prod = np->net_idx->tx_resp_prod;

        for ( i = np->tx_resp_cons; i != prod; i++ )
        {
            id  = tx_ring[MASK_NET_TX_IDX(i)].resp.id;
            skb = np->tx_skbs[id];
            ADD_ID_TO_FREELIST(np->tx_skbs, id);
            dev_kfree_skb_any(skb);
        }
        
        np->tx_resp_cons = prod;
        
        /*
         * Set a new event, then check for race with update of tx_cons. Note
         * that it is essential to schedule a callback, no matter how few
         * buffers are pending. Even if there is space in the transmit ring,
         * higher layers may be blocked because too much data is outstanding:
         * in such cases notification from Xen is likely to be the only kick
         * that we'll get.
         */
        np->net_idx->tx_event = 
            prod + ((np->net_idx->tx_req_prod - prod) >> 1) + 1;
        mb();
    }
    while ( prod != np->net_idx->tx_resp_prod );

    if ( np->tx_full && 
         ((np->net_idx->tx_req_prod - prod) < XENNET_TX_RING_SIZE) )
    {
        np->tx_full = 0;
        if ( np->state == NETIF_STATE_ACTIVE )
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
    unsigned short id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    netop_t netop;
    NET_RING_IDX i = np->net_idx->rx_req_prod;

    if ( unlikely((i - np->rx_resp_cons) == XENNET_RX_RING_SIZE) || 
         unlikely(np->state != NETIF_STATE_ACTIVE) )
        return;

    do {
        skb = dev_alloc_skb(RX_BUF_SIZE);
        if ( unlikely(skb == NULL) )
            break;

        skb->dev = dev;

        if ( unlikely(((unsigned long)skb->head & (PAGE_SIZE-1)) != 0) )
            panic("alloc_skb needs to provide us page-aligned buffers.");

        id = GET_ID_FROM_FREELIST(np->rx_skbs);
        np->rx_skbs[id] = skb;

        np->net_ring->rx_ring[MASK_NET_RX_IDX(i)].req.id   = id;
        np->net_ring->rx_ring[MASK_NET_RX_IDX(i)].req.addr = 
            virt_to_machine(get_ppte(skb->head));

        np->rx_bufs_to_notify++;
    }
    while ( (++i - np->rx_resp_cons) != XENNET_RX_RING_SIZE );

    /*
     * We may have allocated buffers which have entries outstanding in the page
     * update queue -- make sure we flush those first!
     */
    flush_page_update_queue();

    np->net_idx->rx_req_prod = i;
    np->net_idx->rx_event    = np->rx_resp_cons + 1;
        
    /* Batch Xen notifications. */
    if ( np->rx_bufs_to_notify > (XENNET_RX_RING_SIZE/4) )
    {
        netop.cmd = NETOP_PUSH_BUFFERS;
        netop.vif = np->idx;
        (void)HYPERVISOR_net_io_op(&netop);
        np->rx_bufs_to_notify = 0;
    }
}


static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned short id;
    struct net_private *np = (struct net_private *)dev->priv;
    tx_req_entry_t *tx;
    netop_t netop;
    NET_RING_IDX i;

    if ( unlikely(np->tx_full) )
    {
        printk(KERN_ALERT "%s: full queue wasn't stopped!\n", dev->name);
        netif_stop_queue(dev);
        return -ENOBUFS;
    }

    if ( unlikely((((unsigned long)skb->data & ~PAGE_MASK) + skb->len) >=
                  PAGE_SIZE) )
    {
        struct sk_buff *new_skb = dev_alloc_skb(RX_BUF_SIZE);
        if ( unlikely(new_skb == NULL) )
            return 1;
        skb_put(new_skb, skb->len);
        memcpy(new_skb->data, skb->data, skb->len);
        dev_kfree_skb(skb);
        skb = new_skb;
    }   
    
    spin_lock_irq(&np->tx_lock);

    i = np->net_idx->tx_req_prod;

    id = GET_ID_FROM_FREELIST(np->tx_skbs);
    np->tx_skbs[id] = skb;

    tx = &np->net_ring->tx_ring[MASK_NET_TX_IDX(i)].req;

    tx->id   = id;
    tx->addr = phys_to_machine(virt_to_phys(skb->data));
    tx->size = skb->len;

    wmb();
    np->net_idx->tx_req_prod = i + 1;

    network_tx_buf_gc(dev);

    if ( (i - np->tx_resp_cons) == (XENNET_TX_RING_SIZE - 1) )
    {
        np->tx_full = 1;
        netif_stop_queue(dev);
    }

    spin_unlock_irq(&np->tx_lock);

    np->stats.tx_bytes += skb->len;
    np->stats.tx_packets++;

    /* Only notify Xen if there are no outstanding responses. */
    mb();
    if ( np->net_idx->tx_resp_prod == i )
    {
        netop.cmd = NETOP_PUSH_BUFFERS;
        netop.vif = np->idx;
        (void)HYPERVISOR_net_io_op(&netop);
    }

    return 0;
}


static void netif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    struct net_device *dev = dev_id;
    struct net_private *np = dev->priv;
    unsigned long flags;
    struct sk_buff *skb;
    rx_resp_entry_t *rx;
    NET_RING_IDX i;

    spin_lock_irqsave(&np->tx_lock, flags);
    network_tx_buf_gc(dev);
    spin_unlock_irqrestore(&np->tx_lock, flags);

 again:
    for ( i = np->rx_resp_cons; i != np->net_idx->rx_resp_prod; i++ )
    {
        rx = &np->net_ring->rx_ring[MASK_NET_RX_IDX(i)].resp;

        skb = np->rx_skbs[rx->id];
        ADD_ID_TO_FREELIST(np->rx_skbs, rx->id);

        if ( unlikely(rx->status != RING_STATUS_OK) )
        {
            /* Gate this error. We get a (valid) slew of them on suspend. */
            if ( np->state == NETIF_STATE_ACTIVE )
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

        skb->data = skb->tail = skb->head + rx->offset;
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
    mb();
    if ( np->net_idx->rx_resp_prod != i )
        goto again;
}


static int network_close(struct net_device *dev)
{
    struct net_private *np = dev->priv;
    netop_t netop;

    netif_stop_queue(np->dev);

    netop.cmd = NETOP_FLUSH_BUFFERS;
    netop.vif = np->idx;
    (void)HYPERVISOR_net_io_op(&netop);

    while ( (np->rx_resp_cons != np->net_idx->rx_req_prod) ||
            (np->tx_resp_cons != np->net_idx->tx_req_prod) )
    {
        barrier();
        current->state = TASK_INTERRUPTIBLE;
        schedule_timeout(1);
    }

    wmb();
    np->state = NETIF_STATE_CONNECTED;
    wmb();

    MOD_DEC_USE_COUNT;

    return 0;
}


static struct net_device_stats *network_get_stats(struct net_device *dev)
{
    struct net_private *np = (struct net_private *)dev->priv;
    return &np->stats;
}


static void netif_bringup_phase1(void *unused)
{
    ctrl_msg_t                   cmsg;
    netif_fe_interface_connect_t up;
    struct net_device *dev;
    struct net_private *np;

    dev = find_dev_by_handle(0);
    np  = dev->priv;
    
    /* Move from CLOSED to DISCONNECTED state. */
    np->tx = (netif_tx_interface_t *)__get_free_page(GFP_KERNEL);
    np->rx = (netif_rx_interface_t *)__get_free_page(GFP_KERNEL);
    memset(np->tx, 0, PAGE_SIZE);
    memset(np->rx, 0, PAGE_SIZE);
    np->state  = NETIF_STATE_DISCONNECTED;

    /* Construct an interface-CONNECT message for the domain controller. */
    cmsg.type      = CMSG_NETIF_FE;
    cmsg.subtype   = CMSG_NETIF_FE_INTERFACE_CONNECT;
    cmsg.length    = sizeof(netif_fe_interface_connect_t);
    up.handle      = 0;
    up.tx_shmem_frame = virt_to_machine(np->tx) >> PAGE_SHIFT;
    up.rx_shmem_frame = virt_to_machine(np->rx) >> PAGE_SHIFT;
    memcpy(cmsg.msg, &up, sizeof(up));

    /* Tell the controller to bring up the interface. */
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

static void netif_bringup_phase2(void *unused)
{
    struct net_device *dev;
    struct net_private *np;

    dev = find_dev_by_handle(0);
    np  = dev->priv;
    
    np->irq = bind_evtchn_to_irq(np->evtchn);
    (void)request_irq(np->irq, netif_int, SA_SAMPLE_RANDOM, 
                      "netif", dev);

    np->state = NETIF_STATE_CONNECTED;
}

static void netif_status_change(netif_fe_interface_status_changed_t *status)
{
    struct net_device *dev;
    struct net_private *np;
    
    if ( status->handle != 0 )
    {
        printk(KERN_WARNING "Status change on unsupported netif %d\n",
               status->handle);
        return;
    }

    dev = find_dev_by_handle(0);
    np  = dev->priv;
    
    switch ( status->status )
    {
    case NETIF_INTERFACE_STATUS_DESTROYED:
        printk(KERN_WARNING "Unexpected netif-DESTROYED message in state %d\n",
               netif_state);
        break;

    case NETIF_INTERFACE_STATUS_DISCONNECTED:
        if ( np->state != NETIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected netif-DISCONNECTED message"
                   " in state %d\n", netif_state);
            break;
        }
        netif_statechange_tq.routine = netif_bringup_phase1;
        schedule_task(&netif_statechange_tq);
        break;

    case NETIF_INTERFACE_STATUS_CONNECTED:
        if ( np->state == NETIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected netif-CONNECTED message"
                   " in state %d\n", netif_state);
            break;
        }
        np->evtchn = status->evtchn;
        memcpy(dev->dev_addr, status->mac, ETH_ALEN);
        netif_statechange_tq.routine = netif_bringup_phase2;
        schedule_task(&netif_statechange_tq);
        break;

    default:
        printk(KERN_WARNING "Status change to unknown value %d\n", 
               status->status);
        break;
    }
}


static void netif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{
    switch ( msg->subtype )
    {
    case CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED:
        if ( msg->length != sizeof(netif_fe_interface_status_changed_t) )
            goto parse_error;
        netif_status_change((netif_fe_interface_status_changed_t *)
                            &msg->msg[0]);
        break;
    default:
        goto parse_error;
    }

    ctrl_if_send_response(msg);
    return;

 parse_error:
    msg->length = 0;
    ctrl_if_send_response(msg);
}


static int __init init_module(void)
{
    ctrl_msg_t                       cmsg;
    netif_fe_driver_status_changed_t st;
    int i, err;
    struct net_device *dev;
    struct net_private *np;

    INIT_LIST_HEAD(&dev_list);

    if ( (dev = alloc_etherdev(sizeof(struct net_private))) == NULL )
    {
        err = -ENOMEM;
        goto fail;
    }

    np = dev->priv;
    np->state  = NETIF_STATE_CLOSED;
    np->handle = 0;

    dev->open            = network_open;
    dev->hard_start_xmit = network_start_xmit;
    dev->stop            = network_close;
    dev->get_stats       = network_get_stats;
    
    if ( (err = register_netdev(dev)) != 0 )
    {
        kfree(dev);
        goto fail;
    }
    
    np->dev = dev;
    list_add(&np->list, &dev_list);

    (void)ctrl_if_register_receiver(CMSG_NETIF_FE, netif_ctrlif_rx);

    /* Send a driver-UP notification to the domain controller. */
    cmsg.type      = CMSG_NETIF_FE;
    cmsg.subtype   = CMSG_NETIF_FE_DRIVER_STATUS_CHANGED;
    cmsg.length    = sizeof(netif_fe_driver_status_changed_t);
    st.status      = NETIF_DRIVER_STATUS_UP;
    memcpy(cmsg.msg, &st, sizeof(st));
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);

    /*
     * We should read 'nr_interfaces' from response message and wait
     * for notifications before proceeding. For now we assume that we
     * will be notified of exactly one interface.
     */
    while ( np->state != NETIF_STATE_CONNECTED )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    return 0;

 fail:
    cleanup_module();
    return err;
}


static void cleanup_module(void)
{
    /* XXX FIXME */
    BUG();
}


module_init(init_module);
module_exit(cleanup_module);
