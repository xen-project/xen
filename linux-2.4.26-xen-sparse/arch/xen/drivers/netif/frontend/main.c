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

#include <asm/page.h>

#include "../netif.h"

#define RX_BUF_SIZE ((PAGE_SIZE/2)+1) /* Fool the slab allocator :-) */

static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);
static void cleanup_module(void);

static unsigned long rx_pfn_array[NETIF_RX_RING_SIZE];
static multicall_entry_t rx_mcl[NETIF_RX_RING_SIZE+1];
static mmu_update_t rx_mmu[NETIF_RX_RING_SIZE];

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
    spinlock_t   rx_lock;

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
    spin_lock_init(&np->rx_lock);

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
            id  = np->tx->ring[MASK_NETIF_TX_IDX(i)].resp.id;
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


static void network_alloc_rx_buffers(struct net_device *dev)
{
    unsigned short id;
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    NETIF_RING_IDX i = np->rx->req_prod;
    int nr_pfns = 0;

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
        
        np->rx->ring[MASK_NETIF_RX_IDX(i)].req.id = id;
        
        rx_pfn_array[nr_pfns] = virt_to_machine(skb->head) >> PAGE_SHIFT;

        rx_mcl[nr_pfns].op = __HYPERVISOR_update_va_mapping;
        rx_mcl[nr_pfns].args[0] = (unsigned long)skb->head >> PAGE_SHIFT;
        rx_mcl[nr_pfns].args[1] = 0;
        rx_mcl[nr_pfns].args[2] = 0;

        nr_pfns++;
    }
    while ( (++i - np->rx_resp_cons) != NETIF_RX_RING_SIZE );

    /*
     * We may have allocated buffers which have entries outstanding in the page
     * update queue -- make sure we flush those first!
     */
    flush_page_update_queue();

    /* After all PTEs have been zapped we blow away stale TLB entries. */
    rx_mcl[nr_pfns-1].args[2] = UVMF_FLUSH_TLB;

    /* Give away a batch of pages. */
    rx_mcl[nr_pfns].op = __HYPERVISOR_dom_mem_op;
    rx_mcl[nr_pfns].args[0] = MEMOP_decrease_reservation;
    rx_mcl[nr_pfns].args[1] = (unsigned long)rx_pfn_array;
    rx_mcl[nr_pfns].args[2] = (unsigned long)nr_pfns;

    /* Zap PTEs and give away pages in one big multicall. */
    (void)HYPERVISOR_multicall(rx_mcl, nr_pfns+1);

    /* Check return status of HYPERVISOR_dom_mem_op(). */
    if ( rx_mcl[nr_pfns].args[5] != nr_pfns )
        panic("Unable to reduce memory reservation\n");

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

    /* if the backend isn't available then don't do anything! */
    if ( !netif_carrier_ok(dev) )
    {
        spin_unlock_irq(&np->tx_lock);
        return 1;
    }

    i = np->tx->req_prod;

    id = GET_ID_FROM_FREELIST(np->tx_skbs);
    np->tx_skbs[id] = skb;

    tx = &np->tx->ring[MASK_NETIF_TX_IDX(i)].req;

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

    spin_lock_irqsave(&np->tx_lock, flags);
    
    if( !netif_carrier_ok(dev) )
    {
        spin_unlock_irqrestore(&np->tx_lock, flags);
        return;
    }
    
    network_tx_buf_gc(dev);
    spin_unlock_irqrestore(&np->tx_lock, flags);

    if ( np->rx_resp_cons != np->rx->resp_prod )
        netif_rx_schedule(dev);
}


static int netif_poll(struct net_device *dev, int *pbudget)
{
    struct net_private *np = dev->priv;
    struct sk_buff *skb;
    netif_rx_response_t *rx;
    NETIF_RING_IDX i;
    mmu_update_t *mmu = rx_mmu;
    multicall_entry_t *mcl = rx_mcl;
    int work_done, budget, more_to_do = 1;
    struct sk_buff_head rxq;
    unsigned long flags;

    spin_lock(&np->rx_lock);

    /* if the device is undergoing recovery then don't do anything */
    if ( !netif_carrier_ok(dev) )
    {
        spin_unlock(&np->rx_lock);
        return 0;
    }

    skb_queue_head_init(&rxq);

    if ( (budget = *pbudget) > dev->quota )
        budget = dev->quota;

    for ( i = np->rx_resp_cons, work_done = 0; 
          (i != np->rx->resp_prod) && (work_done < budget); 
          i++, work_done++ )
    {
        rx = &np->rx->ring[MASK_NETIF_RX_IDX(i)].resp;

        skb = np->rx_skbs[rx->id];
        ADD_ID_TO_FREELIST(np->rx_skbs, rx->id);

        if ( unlikely(rx->status <= 0) )
        {
            /* Gate this error. We get a (valid) slew of them on suspend. */
            if ( np->state == NETIF_STATE_ACTIVE )
                printk(KERN_ALERT "bad buffer on RX ring!(%d)\n", rx->status);
            dev_kfree_skb(skb);
            continue;
        }

        skb->data = skb->tail = skb->head + (rx->addr & ~PAGE_MASK);
        skb_put(skb, rx->status);

        np->stats.rx_packets++;
        np->stats.rx_bytes += rx->status;

        /* Remap the page. */
        mmu->ptr  = (rx->addr & PAGE_MASK) | MMU_MACHPHYS_UPDATE;
        mmu->val  = __pa(skb->head) >> PAGE_SHIFT;
        mmu++;
        mcl->op = __HYPERVISOR_update_va_mapping;
        mcl->args[0] = (unsigned long)skb->head >> PAGE_SHIFT;
        mcl->args[1] = (rx->addr & PAGE_MASK) | __PAGE_KERNEL;
        mcl->args[2] = 0;
        mcl++;

        phys_to_machine_mapping[__pa(skb->head) >> PAGE_SHIFT] = 
            rx->addr >> PAGE_SHIFT;

        __skb_queue_tail(&rxq, skb);
    }

    /* Do all the remapping work, and M->P updates, in one big hypercall. */
    if ( likely((mcl - rx_mcl) != 0) )
    {
        mcl->op = __HYPERVISOR_mmu_update;
        mcl->args[0] = (unsigned long)rx_mmu;
        mcl->args[1] = mmu - rx_mmu;
        mcl->args[2] = 0;
        mcl++;
        (void)HYPERVISOR_multicall(rx_mcl, mcl - rx_mcl);
    }

    while ( (skb = __skb_dequeue(&rxq)) != NULL )
    {
        /* Set the shared-info area, which is hidden behind the real data. */
        atomic_set(&(skb_shinfo(skb)->dataref), 1);
        skb_shinfo(skb)->nr_frags = 0;
        skb_shinfo(skb)->frag_list = NULL;

        /* Ethernet-specific work. Delayed to here as it peeks the header. */
        skb->protocol = eth_type_trans(skb, dev);

        /* Pass it up. */
        netif_rx(skb);
        dev->last_rx = jiffies;
    }

    np->rx_resp_cons = i;

    network_alloc_rx_buffers(dev);

    *pbudget   -= work_done;
    dev->quota -= work_done;

    if ( work_done < budget )
    {
        local_irq_save(flags);

        np->rx->event = i + 1;
    
        /* Deal with hypervisor racing our resetting of rx_event. */
        mb();
        if ( np->rx->resp_prod == i )
        {
            __netif_rx_complete(dev);
            more_to_do = 0;
        }

        local_irq_restore(flags);
    }

    spin_unlock(&np->rx_lock);

    return more_to_do;
}


static int network_close(struct net_device *dev)
{
    struct net_private *np = dev->priv;

    netif_stop_queue(np->dev);

    np->state = NETIF_STATE_CONNECTED;

    /* XXX We need to properly disconnect via the domain controller. */
    while ( /*(np->rx_resp_cons != np->rx->req_prod) ||*/
            (np->tx_resp_cons != np->tx->req_prod) )
    {
        barrier();
        current->state = TASK_INTERRUPTIBLE;
        schedule_timeout(1);
    }

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
	    printk(KERN_INFO "Attempting to reconnect network interface\n");

            /* Begin interface recovery.
	     *
	     * NB. Whilst we're recovering, we turn the carrier state off.  We
	     * take measures to ensure that this device isn't used for
	     * anything.  We also stop the queue for this device.  Various
	     * different approaches (e.g. continuing to buffer packets) have
	     * been tested but don't appear to improve the overall impact on
             * TCP connections.
	     *
             * TODO: (MAW) Change the Xend<->Guest protocol so that a recovery
             * is initiated by a special "RESET" message - disconnect could
             * just mean we're not allowed to use this interface any more.
             */

            /* Stop old i/f to prevent errors whilst we rebuild the state. */
            spin_lock_irq(&np->tx_lock);
            spin_lock(&np->rx_lock);
            netif_stop_queue(dev);
            netif_carrier_off(dev);
            np->state  = NETIF_STATE_DISCONNECTED;
            spin_unlock(&np->rx_lock);
            spin_unlock_irq(&np->tx_lock);

            /* Free resources. */
            free_irq(np->irq, dev);
            unbind_evtchn_from_irq(np->evtchn);
	    free_page((unsigned long)np->tx);
            free_page((unsigned long)np->rx);
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

        if(netif_carrier_ok(dev))
            np->state = NETIF_STATE_CONNECTED;
        else
        {
            int i, requeue_idx;
            netif_tx_request_t *tx;

            spin_lock_irq(&np->rx_lock);
            spin_lock(&np->tx_lock);

            /* Recovery procedure: */

            /* Step 1: Reinitialise variables. */
            np->rx_resp_cons = np->tx_resp_cons = np->tx_full = 0;
            np->rx->event = 1;

            /* Step 2: Rebuild the RX and TX ring contents.
             * NB. We could just free the queued TX packets now but we hope
             * that sending them out might do some good.  We have to rebuild
             * the RX ring because some of our pages are currently flipped out
             * so we can't just free the RX skbs.
	     * NB2. Freelist index entries are always going to be less than
	     *  __PAGE_OFFSET, whereas pointers to skbs will always be equal or
	     * greater than __PAGE_OFFSET: we use this property to distinguish
             * them.
             */

            /* Rebuild the TX buffer freelist and the TX ring itself.
             * NB. This reorders packets.  We could keep more private state
             * to avoid this but maybe it doesn't matter so much given the
             * interface has been down.
             */
            for ( requeue_idx = 0, i = 1; i <= NETIF_TX_RING_SIZE; i++ )
            {
                if ( (unsigned long)np->tx_skbs[i] >= __PAGE_OFFSET )
                {
                    struct sk_buff *skb = np->tx_skbs[i];
                    
                    tx = &np->tx->ring[requeue_idx++].req;
                    
                    tx->id   = i;
                    tx->addr = virt_to_machine(skb->data);
                    tx->size = skb->len;
                    
                    np->stats.tx_bytes += skb->len;
                    np->stats.tx_packets++;
                }
            }
            wmb();
            np->tx->req_prod = requeue_idx;

            /* Rebuild the RX buffer freelist and the RX ring itself. */
            for ( requeue_idx = 0, i = 1; i <= NETIF_RX_RING_SIZE; i++ )
                if ( (unsigned long)np->rx_skbs[i] >= __PAGE_OFFSET )
                    np->rx->ring[requeue_idx++].req.id = i;
            wmb();                
            np->rx->req_prod = requeue_idx;

            /* Step 3: All public and private state should now be sane.  Get
             * ready to start sending and receiving packets and give the driver
             * domain a kick because we've probably just requeued some
             * packets.
             */
            netif_carrier_on(dev);
            netif_start_queue(dev);
            np->state = NETIF_STATE_ACTIVE;

            notify_via_evtchn(status->evtchn);  

	    network_tx_buf_gc(dev);

            printk(KERN_INFO "Recovery completed\n");

            spin_unlock(&np->tx_lock);
            spin_unlock_irq(&np->rx_lock);
        }

        np->evtchn = status->evtchn;
        np->irq = bind_evtchn_to_irq(np->evtchn);
        (void)request_irq(np->irq, netif_int, SA_SAMPLE_RANDOM, 
                          dev->name, dev);
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

    if ( (start_info.flags & SIF_INITDOMAIN) ||
         (start_info.flags & SIF_NET_BE_DOMAIN) )
        return 0;

    printk("Initialising Xen virtual ethernet frontend driver");

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
    dev->poll            = netif_poll;
    dev->weight          = 64;
    
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
