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

#include <asm/evtchn.h>
#include <asm/ctrl_if.h>
#include <asm/hypervisor-ifs/dom_mem_ops.h>

#include "../netif.h"

#define RX_BUF_SIZE ((PAGE_SIZE/2)+1) /* Fool the slab allocator :-) */

static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);
static void cleanup_module(void);

static struct list_head dev_list;

struct net_private
{
    struct list_head list;
    struct net_device *dev;

    struct net_device_stats stats;
    NETIF_RING_IDX rx_resp_cons, tx_resp_cons;
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
    struct sk_buff *tx_skbs[NETIF_TX_RING_SIZE+1];
    struct sk_buff *rx_skbs[NETIF_RX_RING_SIZE+1];
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
            return np->dev;
    }
    return NULL;
}


static int network_open(struct net_device *dev)
{
    struct net_private *np = dev->priv;
    int i;

    if ( np->state != NETIF_STATE_CONNECTED )
        return -EINVAL;

    np->rx_resp_cons = np->tx_resp_cons = np->tx_full = 0;
    memset(&np->stats, 0, sizeof(np->stats));
    spin_lock_init(&np->tx_lock);

    /* Initialise {tx,rx}_skbs to be a free chain containing every entry. */
    for ( i = 0; i <= NETIF_TX_RING_SIZE; i++ )
        np->tx_skbs[i] = (void *)(i+1);
    for ( i = 0; i <= NETIF_RX_RING_SIZE; i++ )
        np->rx_skbs[i] = (void *)(i+1);

    wmb();
    np->state = NETIF_STATE_ACTIVE;

    network_alloc_rx_buffers(dev);
    np->rx->event = np->rx_resp_cons + 1;

    netif_start_queue(dev);

    MOD_INC_USE_COUNT;

    return 0;
}


static void network_tx_buf_gc(struct net_device *dev)
{
    NETIF_RING_IDX i, prod;
    unsigned short id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;

    do {
        prod = np->tx->resp_prod;

        for ( i = np->tx_resp_cons; i != prod; i++ )
        {
            id  = np->tx->ring[MASK_NET_TX_IDX(i)].resp.id;
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
        np->tx->event = 
            prod + ((np->tx->req_prod - prod) >> 1) + 1;
        mb();
    }
    while ( prod != np->tx->resp_prod );

    if ( np->tx_full && 
         ((np->tx->req_prod - prod) < NETIF_TX_RING_SIZE) )
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
    NETIF_RING_IDX i = np->rx->req_prod;
    dom_mem_op_t op;
    unsigned long pfn_array[NETIF_RX_RING_SIZE];
    int ret, nr_pfns = 0;
    pte_t *pte;

    /* Make sure the batch is large enough to be worthwhile (1/2 ring). */
    if ( unlikely((i - np->rx_resp_cons) > (NETIF_RX_RING_SIZE/2)) || 
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

        np->rx->ring[MASK_NET_RX_IDX(i)].req.id = id;
        
        pte = get_ppte(skb->head);
        pfn_array[nr_pfns++] = pte->pte_low >> PAGE_SHIFT;
        queue_l1_entry_update(pte, 0);
    }
    while ( (++i - np->rx_resp_cons) != NETIF_RX_RING_SIZE );

    /*
     * We may have allocated buffers which have entries outstanding in the page
     * update queue -- make sure we flush those first!
     */
    flush_page_update_queue();

    op.op = MEMOP_RESERVATION_DECREASE;
    op.u.decrease.size  = nr_pfns;
    op.u.decrease.pages = pfn_array;
    if ( (ret = HYPERVISOR_dom_mem_op(&op)) != nr_pfns )
    {
        printk(KERN_WARNING "Unable to reduce memory reservation (%d)\n", ret);
        BUG();
    }

    np->rx->req_prod = i;
}


static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned short id;
    struct net_private *np = (struct net_private *)dev->priv;
    netif_tx_request_t *tx;
    NETIF_RING_IDX i;

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

    i = np->tx->req_prod;

    id = GET_ID_FROM_FREELIST(np->tx_skbs);
    np->tx_skbs[id] = skb;

    tx = &np->tx->ring[MASK_NET_TX_IDX(i)].req;

    tx->id   = id;
    tx->addr = virt_to_machine(skb->data);
    tx->size = skb->len;

    wmb();
    np->tx->req_prod = i + 1;

    network_tx_buf_gc(dev);

    if ( (i - np->tx_resp_cons) == (NETIF_TX_RING_SIZE - 1) )
    {
        np->tx_full = 1;
        netif_stop_queue(dev);
    }

    spin_unlock_irq(&np->tx_lock);

    np->stats.tx_bytes += skb->len;
    np->stats.tx_packets++;

    /* Only notify Xen if there are no outstanding responses. */
    mb();
    if ( np->tx->resp_prod == i )
        notify_via_evtchn(np->evtchn);

    return 0;
}


static void netif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    struct net_device *dev = dev_id;
    struct net_private *np = dev->priv;
    unsigned long flags;
    struct sk_buff *skb;
    netif_rx_response_t *rx;
    NETIF_RING_IDX i;
    mmu_update_t mmu[2];
    pte_t *pte;

    spin_lock_irqsave(&np->tx_lock, flags);
    network_tx_buf_gc(dev);
    spin_unlock_irqrestore(&np->tx_lock, flags);

 again:
    for ( i = np->rx_resp_cons; i != np->rx->resp_prod; i++ )
    {
        rx = &np->rx->ring[MASK_NET_RX_IDX(i)].resp;

        skb = np->rx_skbs[rx->id];
        ADD_ID_TO_FREELIST(np->rx_skbs, rx->id);

        if ( unlikely(rx->status <= 0) )
        {
            /* Gate this error. We get a (valid) slew of them on suspend. */
            if ( np->state == NETIF_STATE_ACTIVE )
                printk(KERN_ALERT "bad buffer on RX ring!(%d)\n", rx->status);
            dev_kfree_skb_any(skb);
            continue;
        }

        /* Remap the page. */
        pte = get_ppte(skb->head);
        mmu[0].ptr  = virt_to_machine(pte);
        mmu[0].val  = (rx->addr & PAGE_MASK) | __PAGE_KERNEL;
        mmu[1].ptr  = (rx->addr & PAGE_MASK) | MMU_MACHPHYS_UPDATE;
        mmu[1].val  = __pa(skb->head) >> PAGE_SHIFT;
        if ( HYPERVISOR_mmu_update(mmu, 2) != 0 )
            BUG();
        phys_to_machine_mapping[__pa(skb->head) >> PAGE_SHIFT] = 
            rx->addr >> PAGE_SHIFT;

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

        skb->data = skb->tail = skb->head + (rx->addr & ~PAGE_MASK);
        skb_put(skb, rx->status);
        skb->protocol = eth_type_trans(skb, dev);

        np->stats.rx_packets++;

        np->stats.rx_bytes += rx->status;
        netif_rx(skb);
        dev->last_rx = jiffies;
    }

    np->rx_resp_cons = i;

    network_alloc_rx_buffers(dev);
    np->rx->event = np->rx_resp_cons + 1;
    
    /* Deal with hypervisor racing our resetting of rx_event. */
    mb();
    if ( np->rx->resp_prod != i )
        goto again;
}


static int network_close(struct net_device *dev)
{
    struct net_private *np = dev->priv;

    netif_stop_queue(np->dev);

    while ( (np->rx_resp_cons != np->rx->req_prod) ||
            (np->tx_resp_cons != np->tx->req_prod) )
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


static void netif_status_change(netif_fe_interface_status_changed_t *status)
{
    ctrl_msg_t                   cmsg;
    netif_fe_interface_connect_t up;
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
               np->state);
        break;

    case NETIF_INTERFACE_STATUS_DISCONNECTED:
        if ( np->state != NETIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected netif-DISCONNECTED message"
                   " in state %d\n", np->state);
            break;
        }

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
        break;

    case NETIF_INTERFACE_STATUS_CONNECTED:
        if ( np->state == NETIF_STATE_CLOSED )
        {
            printk(KERN_WARNING "Unexpected netif-CONNECTED message"
                   " in state %d\n", np->state);
            break;
        }

        memcpy(dev->dev_addr, status->mac, ETH_ALEN);

        np->evtchn = status->evtchn;
        np->irq = bind_evtchn_to_irq(np->evtchn);
        (void)request_irq(np->irq, netif_int, SA_SAMPLE_RANDOM, 
                      dev->name, dev);
        
        np->state = NETIF_STATE_CONNECTED;
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
    int err;
    struct net_device *dev;
    struct net_private *np;

    if ( start_info.flags & SIF_INITDOMAIN )
        return 0;

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

    (void)ctrl_if_register_receiver(CMSG_NETIF_FE, netif_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);

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
