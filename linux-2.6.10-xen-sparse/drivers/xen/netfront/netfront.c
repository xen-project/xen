/******************************************************************************
 * Virtual network driver for conversing with remote driver backends.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
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
#include <linux/bitops.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <net/arp.h>
#include <net/route.h>
#include <asm/io.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/ctrl_if.h>
#include <asm-xen/xen-public/io/netif.h>
#include <asm-xen/balloon.h>
#include <asm/page.h>

#ifndef __GFP_NOWARN
#define __GFP_NOWARN 0
#endif
#define alloc_xen_skb(_l) __dev_alloc_skb((_l), GFP_ATOMIC|__GFP_NOWARN)

#define init_skb_shinfo(_skb)                         \
    do {                                              \
        atomic_set(&(skb_shinfo(_skb)->dataref), 1);  \
        skb_shinfo(_skb)->nr_frags = 0;               \
        skb_shinfo(_skb)->frag_list = NULL;           \
    } while (0)

/* Allow headroom on each rx pkt for Ethernet header, alignment padding, ... */
#define RX_HEADROOM 200

/*
 * If the backend driver is pipelining transmit requests then we can be very
 * aggressive in avoiding new-packet notifications -- only need to send a
 * notification if there are no outstanding unreceived responses.
 * If the backend may be buffering our transmit buffers for any reason then we
 * are rather more conservative.
 */
#ifdef CONFIG_XEN_NETDEV_FRONTEND_PIPELINED_TRANSMITTER
#define TX_TEST_IDX resp_prod /* aggressive: any outstanding responses? */
#else
#define TX_TEST_IDX req_cons  /* conservative: not seen all our requests? */
#endif

static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);

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

    /* What is the status of our connection to the remote backend? */
#define BEST_CLOSED       0
#define BEST_DISCONNECTED 1
#define BEST_CONNECTED    2
    unsigned int backend_state;

    /* Is this interface open or closed (down or up)? */
#define UST_CLOSED        0
#define UST_OPEN          1
    unsigned int user_state;

    /* Receive-ring batched refills. */
#define RX_MIN_TARGET 8
#define RX_MAX_TARGET NETIF_RX_RING_SIZE
    int rx_target;
    struct sk_buff_head rx_batch;

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

static char *status_name[] = {
    [NETIF_INTERFACE_STATUS_CLOSED]       = "closed",
    [NETIF_INTERFACE_STATUS_DISCONNECTED] = "disconnected",
    [NETIF_INTERFACE_STATUS_CONNECTED]    = "connected",
    [NETIF_INTERFACE_STATUS_CHANGED]      = "changed",
};

static char *be_state_name[] = {
    [BEST_CLOSED]       = "closed",
    [BEST_DISCONNECTED] = "disconnected",
    [BEST_CONNECTED]    = "connected",
};

#if DEBUG
#define DPRINTK(fmt, args...) \
    printk(KERN_ALERT "xen_net (%s:%d) " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define DPRINTK(fmt, args...) ((void)0)
#endif
#define IPRINTK(fmt, args...) \
    printk(KERN_INFO "xen_net: " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_net: " fmt, ##args)

static struct net_device *find_dev_by_handle(unsigned int handle)
{
    struct list_head *ent;
    struct net_private *np;
    list_for_each (ent, &dev_list) {
        np = list_entry(ent, struct net_private, list);
        if (np->handle == handle)
            return np->dev;
    }
    return NULL;
}

/** Network interface info. */
struct netif_ctrl {
    /** Number of interfaces. */
    int interface_n;
    /** Number of connected interfaces. */
    int connected_n;
    /** Error code. */
    int err;
    int up;
};

static struct netif_ctrl netctrl;

static void netctrl_init(void)
{
    memset(&netctrl, 0, sizeof(netctrl));
    netctrl.up = NETIF_DRIVER_STATUS_DOWN;
}

/** Get or set a network interface error.
 */
static int netctrl_err(int err)
{
    if ((err < 0) && !netctrl.err)
        netctrl.err = err;
    return netctrl.err;
}

/** Test if all network interfaces are connected.
 *
 * @return 1 if all connected, 0 if not, negative error code otherwise
 */
static int netctrl_connected(void)
{
    int ok;

    if (netctrl.err)
        ok = netctrl.err;
    else if (netctrl.up == NETIF_DRIVER_STATUS_UP)
        ok = (netctrl.connected_n == netctrl.interface_n);
    else
        ok = 0;

    return ok;
}

/** Count the connected network interfaces.
 *
 * @return connected count
 */
static int netctrl_connected_count(void)
{
    
    struct list_head *ent;
    struct net_private *np;
    unsigned int connected;

    connected = 0;
    
    list_for_each(ent, &dev_list) {
        np = list_entry(ent, struct net_private, list);
        if (np->backend_state == BEST_CONNECTED)
            connected++;
    }

    netctrl.connected_n = connected;
    DPRINTK("> connected_n=%d interface_n=%d\n",
            netctrl.connected_n, netctrl.interface_n);
    return connected;
}

/** Send a packet on a net device to encourage switches to learn the
 * MAC. We send a fake ARP request.
 *
 * @param dev device
 * @return 0 on success, error code otherwise
 */
static int send_fake_arp(struct net_device *dev)
{
    struct sk_buff *skb;
    u32             src_ip, dst_ip;

    dst_ip = INADDR_BROADCAST;
    src_ip = inet_select_addr(dev, dst_ip, RT_SCOPE_LINK);

    /* No IP? Then nothing to do. */
    if (src_ip == 0)
        return 0;

    skb = arp_create(ARPOP_REPLY, ETH_P_ARP,
                     dst_ip, dev, src_ip,
                     /*dst_hw*/ NULL, /*src_hw*/ NULL, 
                     /*target_hw*/ dev->dev_addr);
    if (skb == NULL)
        return -ENOMEM;

    return dev_queue_xmit(skb);
}

static int network_open(struct net_device *dev)
{
    struct net_private *np = netdev_priv(dev);

    memset(&np->stats, 0, sizeof(np->stats));

    np->user_state = UST_OPEN;

    network_alloc_rx_buffers(dev);
    np->rx->event = np->rx_resp_cons + 1;

    netif_start_queue(dev);

    return 0;
}

static void network_tx_buf_gc(struct net_device *dev)
{
    NETIF_RING_IDX i, prod;
    unsigned short id;
    struct net_private *np = netdev_priv(dev);
    struct sk_buff *skb;

    if (np->backend_state != BEST_CONNECTED)
        return;

    do {
        prod = np->tx->resp_prod;
        rmb(); /* Ensure we see responses up to 'rp'. */

        for (i = np->tx_resp_cons; i != prod; i++) {
            id  = np->tx->ring[MASK_NETIF_TX_IDX(i)].resp.id;
            skb = np->tx_skbs[id];
            ADD_ID_TO_FREELIST(np->tx_skbs, id);
            dev_kfree_skb_irq(skb);
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
    } while (prod != np->tx->resp_prod);

    if (np->tx_full && ((np->tx->req_prod - prod) < NETIF_TX_RING_SIZE)) {
        np->tx_full = 0;
        if (np->user_state == UST_OPEN)
            netif_wake_queue(dev);
    }
}


static void network_alloc_rx_buffers(struct net_device *dev)
{
    unsigned short id;
    struct net_private *np = netdev_priv(dev);
    struct sk_buff *skb;
    int i, batch_target;
    NETIF_RING_IDX req_prod = np->rx->req_prod;

    if (unlikely(np->backend_state != BEST_CONNECTED))
        return;

    /*
     * Allocate skbuffs greedily, even though we batch updates to the
     * receive ring. This creates a less bursty demand on the memory allocator,
     * so should reduce the chance of failed allocation requests both for
     * ourself and for other kernel subsystems.
     */
    batch_target = np->rx_target - (req_prod - np->rx_resp_cons);
    for (i = skb_queue_len(&np->rx_batch); i < batch_target; i++) {
        if (unlikely((skb = alloc_xen_skb(dev->mtu + RX_HEADROOM)) == NULL))
            break;
        __skb_queue_tail(&np->rx_batch, skb);
    }

    /* Is the batch large enough to be worthwhile? */
    if (i < (np->rx_target/2))
        return;

    for (i = 0; ; i++) {
        if ((skb = __skb_dequeue(&np->rx_batch)) == NULL)
            break;

        skb->dev = dev;

        id = GET_ID_FROM_FREELIST(np->rx_skbs);

        np->rx_skbs[id] = skb;
        
        np->rx->ring[MASK_NETIF_RX_IDX(req_prod + i)].req.id = id;
        
        rx_pfn_array[i] = virt_to_machine(skb->head) >> PAGE_SHIFT;

	/* Remove this page from pseudo phys map before passing back to Xen. */
	phys_to_machine_mapping[__pa(skb->head) >> PAGE_SHIFT] 
	    = INVALID_P2M_ENTRY;

        rx_mcl[i].op = __HYPERVISOR_update_va_mapping;
        rx_mcl[i].args[0] = (unsigned long)skb->head >> PAGE_SHIFT;
        rx_mcl[i].args[1] = 0;
        rx_mcl[i].args[2] = 0;
    }

    /*
     * We may have allocated buffers which have entries outstanding in the page
     * update queue -- make sure we flush those first!
     */
    flush_page_update_queue();

    /* After all PTEs have been zapped we blow away stale TLB entries. */
    rx_mcl[i-1].args[2] = UVMF_FLUSH_TLB;

    /* Give away a batch of pages. */
    rx_mcl[i].op = __HYPERVISOR_dom_mem_op;
    rx_mcl[i].args[0] = MEMOP_decrease_reservation;
    rx_mcl[i].args[1] = (unsigned long)rx_pfn_array;
    rx_mcl[i].args[2] = (unsigned long)i;
    rx_mcl[i].args[3] = 0;
    rx_mcl[i].args[4] = DOMID_SELF;

    /* Tell the ballon driver what is going on. */
    balloon_update_driver_allowance(i);

    /* Zap PTEs and give away pages in one big multicall. */
    (void)HYPERVISOR_multicall(rx_mcl, i+1);

    /* Check return status of HYPERVISOR_dom_mem_op(). */
    if (unlikely(rx_mcl[i].args[5] != i))
        panic("Unable to reduce memory reservation\n");

    /* Above is a suitable barrier to ensure backend will see requests. */
    np->rx->req_prod = req_prod + i;

    /* Adjust our floating fill target if we risked running out of buffers. */
    if (((req_prod - np->rx->resp_prod) < (np->rx_target / 4)) &&
         ((np->rx_target *= 2) > RX_MAX_TARGET))
        np->rx_target = RX_MAX_TARGET;
}


static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned short id;
    struct net_private *np = netdev_priv(dev);
    netif_tx_request_t *tx;
    NETIF_RING_IDX i;

    if (unlikely(np->tx_full)) {
        printk(KERN_ALERT "%s: full queue wasn't stopped!\n", dev->name);
        netif_stop_queue(dev);
        goto drop;
    }

    if (unlikely((((unsigned long)skb->data & ~PAGE_MASK) + skb->len) >=
                  PAGE_SIZE)) {
        struct sk_buff *nskb;
        if (unlikely((nskb = alloc_xen_skb(skb->len)) == NULL))
            goto drop;
        skb_put(nskb, skb->len);
        memcpy(nskb->data, skb->data, skb->len);
        nskb->dev = skb->dev;
        dev_kfree_skb(skb);
        skb = nskb;
    }
    
    spin_lock_irq(&np->tx_lock);

    if (np->backend_state != BEST_CONNECTED) {
        spin_unlock_irq(&np->tx_lock);
        goto drop;
    }

    i = np->tx->req_prod;

    id = GET_ID_FROM_FREELIST(np->tx_skbs);
    np->tx_skbs[id] = skb;

    tx = &np->tx->ring[MASK_NETIF_TX_IDX(i)].req;

    tx->id   = id;
    tx->addr = virt_to_machine(skb->data);
    tx->size = skb->len;

    wmb(); /* Ensure that backend will see the request. */
    np->tx->req_prod = i + 1;

    network_tx_buf_gc(dev);

    if ((i - np->tx_resp_cons) == (NETIF_TX_RING_SIZE - 1)) {
        np->tx_full = 1;
        netif_stop_queue(dev);
    }

    spin_unlock_irq(&np->tx_lock);

    np->stats.tx_bytes += skb->len;
    np->stats.tx_packets++;

    /* Only notify Xen if we really have to. */
    mb();
    if (np->tx->TX_TEST_IDX == i)
        notify_via_evtchn(np->evtchn);

    return 0;

 drop:
    np->stats.tx_dropped++;
    dev_kfree_skb(skb);
    return 0;
}

static irqreturn_t netif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
    struct net_device *dev = dev_id;
    struct net_private *np = netdev_priv(dev);
    unsigned long flags;

    spin_lock_irqsave(&np->tx_lock, flags);
    network_tx_buf_gc(dev);
    spin_unlock_irqrestore(&np->tx_lock, flags);

    if ((np->rx_resp_cons != np->rx->resp_prod) && (np->user_state == UST_OPEN))
        netif_rx_schedule(dev);

    return IRQ_HANDLED;
}


static int netif_poll(struct net_device *dev, int *pbudget)
{
    struct net_private *np = netdev_priv(dev);
    struct sk_buff *skb, *nskb;
    netif_rx_response_t *rx;
    NETIF_RING_IDX i, rp;
    mmu_update_t *mmu = rx_mmu;
    multicall_entry_t *mcl = rx_mcl;
    int work_done, budget, more_to_do = 1;
    struct sk_buff_head rxq;
    unsigned long flags;

    spin_lock(&np->rx_lock);

    if (np->backend_state != BEST_CONNECTED) {
        spin_unlock(&np->rx_lock);
        return 0;
    }

    skb_queue_head_init(&rxq);

    if ((budget = *pbudget) > dev->quota)
        budget = dev->quota;

    rp = np->rx->resp_prod;
    rmb(); /* Ensure we see queued responses up to 'rp'. */

    for (i = np->rx_resp_cons, work_done = 0; 
		    (i != rp) && (work_done < budget);
		    i++, work_done++) {
        rx = &np->rx->ring[MASK_NETIF_RX_IDX(i)].resp;

        /*
         * An error here is very odd. Usually indicates a backend bug,
         * low-memory condition, or that we didn't have reservation headroom.
         */
        if (unlikely(rx->status <= 0)) {
            if (net_ratelimit())
                printk(KERN_WARNING "Bad rx buffer (memory squeeze?).\n");
            np->rx->ring[MASK_NETIF_RX_IDX(np->rx->req_prod)].req.id = rx->id;
            wmb();
            np->rx->req_prod++;
            work_done--;
            continue;
        }

        skb = np->rx_skbs[rx->id];
        ADD_ID_TO_FREELIST(np->rx_skbs, rx->id);

        /* NB. We handle skb overflow later. */
        skb->data = skb->head + (rx->addr & ~PAGE_MASK);
        skb->len  = rx->status;
        skb->tail = skb->data + skb->len;

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

    /* Some pages are no longer absent... */
    balloon_update_driver_allowance(-work_done);

    /* Do all the remapping work, and M->P updates, in one big hypercall. */
    if (likely((mcl - rx_mcl) != 0)) {
        mcl->op = __HYPERVISOR_mmu_update;
        mcl->args[0] = (unsigned long)rx_mmu;
        mcl->args[1] = mmu - rx_mmu;
        mcl->args[2] = 0;
        mcl++;
        (void)HYPERVISOR_multicall(rx_mcl, mcl - rx_mcl);
    }

    while ((skb = __skb_dequeue(&rxq)) != NULL) {
        /*
         * Enough room in skbuff for the data we were passed? Also, Linux 
         * expects at least 16 bytes headroom in each receive buffer.
         */
        if (unlikely(skb->tail > skb->end) || 
			unlikely((skb->data - skb->head) < 16)) {
            nskb = NULL;

            /* Only copy the packet if it fits in the current MTU. */
            if (skb->len <= (dev->mtu + ETH_HLEN)) {
                if ((skb->tail > skb->end) && net_ratelimit())
                    printk(KERN_INFO "Received packet needs %d bytes more "
                           "headroom.\n", skb->tail - skb->end);

                if ((nskb = alloc_xen_skb(skb->len + 2)) != NULL) {
                    skb_reserve(nskb, 2);
                    skb_put(nskb, skb->len);
                    memcpy(nskb->data, skb->data, skb->len);
                    nskb->dev = skb->dev;
                }
            }
            else if (net_ratelimit())
                printk(KERN_INFO "Received packet too big for MTU "
                       "(%d > %d)\n", skb->len - ETH_HLEN, dev->mtu);

            /* Reinitialise and then destroy the old skbuff. */
            skb->len  = 0;
            skb->tail = skb->data;
            init_skb_shinfo(skb);
            dev_kfree_skb(skb);

            /* Switch old for new, if we copied the buffer. */
            if ((skb = nskb) == NULL)
                continue;
        }
        
        /* Set the shared-info area, which is hidden behind the real data. */
        init_skb_shinfo(skb);

        /* Ethernet-specific work. Delayed to here as it peeks the header. */
        skb->protocol = eth_type_trans(skb, dev);

        /* Pass it up. */
        netif_receive_skb(skb);
        dev->last_rx = jiffies;
    }

    np->rx_resp_cons = i;

    /* If we get a callback with very few responses, reduce fill target. */
    /* NB. Note exponential increase, linear decrease. */
    if (((np->rx->req_prod - np->rx->resp_prod) > ((3*np->rx_target) / 4)) &&
         (--np->rx_target < RX_MIN_TARGET))
        np->rx_target = RX_MIN_TARGET;

    network_alloc_rx_buffers(dev);

    *pbudget   -= work_done;
    dev->quota -= work_done;

    if (work_done < budget) {
        local_irq_save(flags);

        np->rx->event = i + 1;
    
        /* Deal with hypervisor racing our resetting of rx_event. */
        mb();
        if (np->rx->resp_prod == i) {
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
    struct net_private *np = netdev_priv(dev);
    np->user_state = UST_CLOSED;
    netif_stop_queue(np->dev);
    return 0;
}


static struct net_device_stats *network_get_stats(struct net_device *dev)
{
    struct net_private *np = netdev_priv(dev);
    return &np->stats;
}


static void network_connect(struct net_device *dev,
                            netif_fe_interface_status_t *status)
{
    struct net_private *np;
    int i, requeue_idx;
    netif_tx_request_t *tx;

    np = netdev_priv(dev);
    spin_lock_irq(&np->tx_lock);
    spin_lock(&np->rx_lock);

    /* Recovery procedure: */

    /* Step 1: Reinitialise variables. */
    np->rx_resp_cons = np->tx_resp_cons = np->tx_full = 0;
    np->rx->event = np->tx->event = 1;

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
    for (requeue_idx = 0, i = 1; i <= NETIF_TX_RING_SIZE; i++) {
            if ((unsigned long)np->tx_skbs[i] >= __PAGE_OFFSET) {
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
    for (requeue_idx = 0, i = 1; i <= NETIF_RX_RING_SIZE; i++)
        if ((unsigned long)np->rx_skbs[i] >= __PAGE_OFFSET)
            np->rx->ring[requeue_idx++].req.id = i;
    wmb();                
    np->rx->req_prod = requeue_idx;

    /* Step 3: All public and private state should now be sane.  Get
     * ready to start sending and receiving packets and give the driver
     * domain a kick because we've probably just requeued some
     * packets.
     */
    np->backend_state = BEST_CONNECTED;
    wmb();
    notify_via_evtchn(status->evtchn);  
    network_tx_buf_gc(dev);

    if (np->user_state == UST_OPEN)
        netif_start_queue(dev);

    spin_unlock(&np->rx_lock);
    spin_unlock_irq(&np->tx_lock);
}

static void vif_show(struct net_private *np)
{
#if DEBUG
    if (np) {
        IPRINTK("<vif handle=%u %s(%s) evtchn=%u irq=%u tx=%p rx=%p>\n",
               np->handle,
               be_state_name[np->backend_state],
               np->user_state ? "open" : "closed",
               np->evtchn,
               np->irq,
               np->tx,
               np->rx);
    } else {
        IPRINTK("<vif NULL>\n");
    }
#endif
}

/* Send a connect message to xend to tell it to bring up the interface. */
static void send_interface_connect(struct net_private *np)
{
    ctrl_msg_t cmsg = {
        .type    = CMSG_NETIF_FE,
        .subtype = CMSG_NETIF_FE_INTERFACE_CONNECT,
        .length  = sizeof(netif_fe_interface_connect_t),
    };
    netif_fe_interface_connect_t *msg = (void*)cmsg.msg;

    msg->handle = np->handle;
    msg->tx_shmem_frame = (virt_to_machine(np->tx) >> PAGE_SHIFT);
    msg->rx_shmem_frame = (virt_to_machine(np->rx) >> PAGE_SHIFT);
        
    ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
}

/* Send a driver status notification to the domain controller. */
static int send_driver_status(int ok)
{
    int err = 0;
    ctrl_msg_t cmsg = {
        .type    = CMSG_NETIF_FE,
        .subtype = CMSG_NETIF_FE_DRIVER_STATUS,
        .length  = sizeof(netif_fe_driver_status_t),
    };
    netif_fe_driver_status_t *msg = (void*)cmsg.msg;

    msg->status = (ok ? NETIF_DRIVER_STATUS_UP : NETIF_DRIVER_STATUS_DOWN);
    err = ctrl_if_send_message_block(&cmsg, NULL, 0, TASK_UNINTERRUPTIBLE);
    return err;
}

/* Stop network device and free tx/rx queues and irq.
 */
static void vif_release(struct net_private *np)
{
    /* Stop old i/f to prevent errors whilst we rebuild the state. */
    spin_lock_irq(&np->tx_lock);
    spin_lock(&np->rx_lock);
    netif_stop_queue(np->dev);
    /* np->backend_state = BEST_DISCONNECTED; */
    spin_unlock(&np->rx_lock);
    spin_unlock_irq(&np->tx_lock);
    
    /* Free resources. */
    if(np->tx != NULL){
        free_irq(np->irq, np->dev);
        unbind_evtchn_from_irq(np->evtchn);
        free_page((unsigned long)np->tx);
        free_page((unsigned long)np->rx);
        np->irq = 0;
        np->evtchn = 0;
        np->tx = NULL;
        np->rx = NULL;
    }
}

/* Release vif resources and close it down completely.
 */
static void vif_close(struct net_private *np)
{
    WPRINTK("Unexpected netif-CLOSED message in state %s\n",
            be_state_name[np->backend_state]);
    vif_release(np);
    np->backend_state = BEST_CLOSED;
    /* todo: take dev down and free. */
    vif_show(np);
}

/* Move the vif into disconnected state.
 * Allocates tx/rx pages.
 * Sends connect message to xend.
 */
static void vif_disconnect(struct net_private *np)
{
    if(np->tx) free_page((unsigned long)np->tx);
    if(np->rx) free_page((unsigned long)np->rx);
    // Before this np->tx and np->rx had better be null.
    np->tx = (netif_tx_interface_t *)__get_free_page(GFP_KERNEL);
    np->rx = (netif_rx_interface_t *)__get_free_page(GFP_KERNEL);
    memset(np->tx, 0, PAGE_SIZE);
    memset(np->rx, 0, PAGE_SIZE);
    np->backend_state = BEST_DISCONNECTED;
    send_interface_connect(np);
    vif_show(np);
}

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
static void vif_reset(struct net_private *np)
{
    IPRINTK("Attempting to reconnect network interface: handle=%u\n",
            np->handle);    
    vif_release(np);
    vif_disconnect(np);
    vif_show(np);
}

/* Move the vif into connected state.
 * Sets the mac and event channel from the message.
 * Binds the irq to the event channel.
 */
static void 
vif_connect(struct net_private *np, netif_fe_interface_status_t *status)
{
    struct net_device *dev = np->dev;
    memcpy(dev->dev_addr, status->mac, ETH_ALEN);
    network_connect(dev, status);
    np->evtchn = status->evtchn;
    np->irq = bind_evtchn_to_irq(np->evtchn);
    (void)request_irq(np->irq, netif_int, SA_SAMPLE_RANDOM, dev->name, dev);
    netctrl_connected_count();
    (void)send_fake_arp(dev);
    vif_show(np);
}


/** Create a network device.
 * @param handle device handle
 * @param val return parameter for created device
 * @return 0 on success, error code otherwise
 */
static int create_netdev(int handle, struct net_device **val)
{
    int i, err = 0;
    struct net_device *dev = NULL;
    struct net_private *np = NULL;

    if ((dev = alloc_etherdev(sizeof(struct net_private))) == NULL) {
        printk(KERN_WARNING "%s> alloc_etherdev failed.\n", __FUNCTION__);
        err = -ENOMEM;
        goto exit;
    }

    np                = netdev_priv(dev);
    np->backend_state = BEST_CLOSED;
    np->user_state    = UST_CLOSED;
    np->handle        = handle;
    
    spin_lock_init(&np->tx_lock);
    spin_lock_init(&np->rx_lock);

    skb_queue_head_init(&np->rx_batch);
    np->rx_target = RX_MIN_TARGET;

    /* Initialise {tx,rx}_skbs to be a free chain containing every entry. */
    for (i = 0; i <= NETIF_TX_RING_SIZE; i++)
        np->tx_skbs[i] = (void *)(i+1);
    for (i = 0; i <= NETIF_RX_RING_SIZE; i++)
        np->rx_skbs[i] = (void *)(i+1);

    dev->open            = network_open;
    dev->hard_start_xmit = network_start_xmit;
    dev->stop            = network_close;
    dev->get_stats       = network_get_stats;
    dev->poll            = netif_poll;
    dev->weight          = 64;
    
    if ((err = register_netdev(dev)) != 0) {
        printk(KERN_WARNING "%s> register_netdev err=%d\n", __FUNCTION__, err);
        goto exit;
    }
    np->dev = dev;
    list_add(&np->list, &dev_list);

  exit:
    if ((err != 0) && (dev != NULL ))
        kfree(dev);
    else if (val != NULL)
        *val = dev;
    return err;
}

/* Get the target interface for a status message.
 * Creates the interface when it makes sense.
 * The returned interface may be null when there is no error.
 *
 * @param status status message
 * @param np return parameter for interface state
 * @return 0 on success, error code otherwise
 */
static int 
target_vif(netif_fe_interface_status_t *status, struct net_private **np)
{
    int err = 0;
    struct net_device *dev;

    DPRINTK("> handle=%d\n", status->handle);
    if (status->handle < 0) {
        err = -EINVAL;
        goto exit;
    }

    if ((dev = find_dev_by_handle(status->handle)) != NULL)
        goto exit;

    if (status->status == NETIF_INTERFACE_STATUS_CLOSED)
        goto exit;
    if (status->status == NETIF_INTERFACE_STATUS_CHANGED)
        goto exit;

    /* It's a new interface in a good state - create it. */
    DPRINTK("> create device...\n");
    if ((err = create_netdev(status->handle, &dev)) != 0)
        goto exit;

    netctrl.interface_n++;

  exit:
    if (np != NULL)
        *np = ((dev && !err) ? netdev_priv(dev) : NULL);
    DPRINTK("< err=%d\n", err);
    return err;
}

/* Handle an interface status message. */
static void netif_interface_status(netif_fe_interface_status_t *status)
{
    int err = 0;
    struct net_private *np = NULL;
    
    DPRINTK("> status=%s handle=%d\n",
            status_name[status->status], status->handle);

    if ((err = target_vif(status, &np)) != 0) {
        WPRINTK("Invalid netif: handle=%u\n", status->handle);
        return;
    }

    if (np == NULL) {
        DPRINTK("> no vif\n");
        return;
    }

    switch (status->status) {
    case NETIF_INTERFACE_STATUS_CLOSED:
        switch (np->backend_state) {
        case BEST_CLOSED:
        case BEST_DISCONNECTED:
        case BEST_CONNECTED:
            vif_close(np);
            break;
        }
        break;

    case NETIF_INTERFACE_STATUS_DISCONNECTED:
        switch (np->backend_state) {
        case BEST_CLOSED:
            vif_disconnect(np);
            break;
        case BEST_DISCONNECTED:
        case BEST_CONNECTED:
            vif_reset(np);
            break;
        }
        break;

    case NETIF_INTERFACE_STATUS_CONNECTED:
        switch (np->backend_state) {
        case BEST_CLOSED:
            WPRINTK("Unexpected netif status %s in state %s\n",
                    status_name[status->status],
                    be_state_name[np->backend_state]);
            vif_disconnect(np);
            vif_connect(np, status);
            break;
        case BEST_DISCONNECTED:
            vif_connect(np, status);
            break;
        }
        break;

    case NETIF_INTERFACE_STATUS_CHANGED:
        /*
         * The domain controller is notifying us that a device has been
         * added or removed.
         */
        break;

    default:
        WPRINTK("Invalid netif status code %d\n", status->status);
        break;
    }

    vif_show(np);
}

/*
 * Initialize the network control interface. 
 */
static void netif_driver_status(netif_fe_driver_status_t *status)
{
    netctrl.up = status->status;
    netctrl_connected_count();
}

/* Receive handler for control messages. */
static void netif_ctrlif_rx(ctrl_msg_t *msg, unsigned long id)
{

    switch (msg->subtype) {
    case CMSG_NETIF_FE_INTERFACE_STATUS:
        if (msg->length != sizeof(netif_fe_interface_status_t))
            goto error;
        netif_interface_status((netif_fe_interface_status_t *) &msg->msg[0]);
        break;

    case CMSG_NETIF_FE_DRIVER_STATUS:
        if (msg->length != sizeof(netif_fe_driver_status_t))
            goto error;
        netif_driver_status((netif_fe_driver_status_t *) &msg->msg[0]);
        break;

    error:
    default:
        msg->length = 0;
        break;
    }

    ctrl_if_send_response(msg);
}


#if 1
/* Wait for all interfaces to be connected.
 *
 * This works OK, but we'd like to use the probing mode (see below).
 */
static int probe_interfaces(void)
{
    int err = 0, conn = 0;
    int wait_i, wait_n = 100;

    DPRINTK(">\n");

    for (wait_i = 0; wait_i < wait_n; wait_i++) { 
        DPRINTK("> wait_i=%d\n", wait_i);
        conn = netctrl_connected();
        if(conn) break;
        DPRINTK("> schedule_timeout...\n");
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(10);
    }

    DPRINTK("> wait finished...\n");
    if (conn <= 0) {
        err = netctrl_err(-ENETDOWN);
        WPRINTK("Failed to connect all virtual interfaces: err=%d\n", err);
    }

    DPRINTK("< err=%d\n", err);

    return err;
}
#else
/* Probe for interfaces until no more are found.
 *
 * This is the mode we'd like to use, but at the moment it panics the kernel.
*/
static int probe_interfaces(void)
{
    int err = 0;
    int wait_i, wait_n = 100;
    ctrl_msg_t cmsg = {
        .type    = CMSG_NETIF_FE,
        .subtype = CMSG_NETIF_FE_INTERFACE_STATUS,
        .length  = sizeof(netif_fe_interface_status_t),
    };
    netif_fe_interface_status_t msg = {};
    ctrl_msg_t rmsg = {};
    netif_fe_interface_status_t *reply = (void*)rmsg.msg;
    int state = TASK_UNINTERRUPTIBLE;
    u32 query = -1;

    DPRINTK(">\n");

    netctrl.interface_n = 0;
    for (wait_i = 0; wait_i < wait_n; wait_i++) { 
        DPRINTK("> wait_i=%d query=%d\n", wait_i, query);
        msg.handle = query;
        memcpy(cmsg.msg, &msg, sizeof(msg));
        DPRINTK("> set_current_state...\n");
        set_current_state(state);
        DPRINTK("> rmsg=%p msg=%p, reply=%p\n", &rmsg, rmsg.msg, reply);
        DPRINTK("> sending...\n");
        err = ctrl_if_send_message_and_get_response(&cmsg, &rmsg, state);
        DPRINTK("> err=%d\n", err);
        if(err) goto exit;
        DPRINTK("> rmsg=%p msg=%p, reply=%p\n", &rmsg, rmsg.msg, reply);
        if((int)reply->handle < 0) {
            // No more interfaces.
            break;
        }
        query = -reply->handle - 2;
        DPRINTK(">netif_interface_status ...\n");
        netif_interface_status(reply);
    }

  exit:
    if (err) {
        err = netctrl_err(-ENETDOWN);
        WPRINTK("Connecting virtual network interfaces failed: err=%d\n", err);
    }

    DPRINTK("< err=%d\n", err);
    return err;
}

#endif

/*
 * We use this notifier to send out a fake ARP reply to reset switches and
 * router ARP caches when an IP interface is brought up on a VIF.
 */
static int 
inetdev_notify(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct in_ifaddr  *ifa = (struct in_ifaddr *)ptr; 
    struct net_device *dev = ifa->ifa_dev->dev;
    struct list_head  *ent;
    struct net_private *np;

    if (event != NETDEV_UP)
        goto out;

    list_for_each (ent, &dev_list) {
        np = list_entry(ent, struct net_private, list);
        if (np->dev == dev)
            (void)send_fake_arp(dev);
    }
        
 out:
    return NOTIFY_DONE;
}

static struct notifier_block notifier_inetdev = {
    .notifier_call  = inetdev_notify,
    .next           = NULL,
    .priority       = 0
};

static int __init netif_init(void)
{
    int err = 0;

    if (xen_start_info.flags & SIF_INITDOMAIN)
        return 0;

    IPRINTK("Initialising virtual ethernet driver.\n");
    INIT_LIST_HEAD(&dev_list);
    (void)register_inetaddr_notifier(&notifier_inetdev);
    netctrl_init();
    (void)ctrl_if_register_receiver(CMSG_NETIF_FE, netif_ctrlif_rx,
                                    CALLBACK_IN_BLOCKING_CONTEXT);
    send_driver_status(1);
    err = probe_interfaces();
    if (err)
        ctrl_if_unregister_receiver(CMSG_NETIF_FE, netif_ctrlif_rx);

    DPRINTK("< err=%d\n", err);
    return err;
}

static void vif_suspend(struct net_private *np)
{
    /* Avoid having tx/rx stuff happen until we're ready. */
    free_irq(np->irq, np->dev);
    unbind_evtchn_from_irq(np->evtchn);
}

static void vif_resume(struct net_private *np)
{
    /*
     * Connect regardless of whether IFF_UP flag set.
     * Stop bad things from happening until we're back up.
     */
    np->backend_state = BEST_DISCONNECTED;
    memset(np->tx, 0, PAGE_SIZE);
    memset(np->rx, 0, PAGE_SIZE);
    
    send_interface_connect(np);
}

void netif_suspend(void)
{
    struct list_head *ent;
    struct net_private *np;
    
    list_for_each (ent, &dev_list) {
        np = list_entry(ent, struct net_private, list);
        vif_suspend(np);
    }
}

void netif_resume(void)
{
    struct list_head *ent;
    struct net_private *np;

    list_for_each (ent, &dev_list) {
        np = list_entry(ent, struct net_private, list);
        vif_resume(np);
    }
}


module_init(netif_init);

