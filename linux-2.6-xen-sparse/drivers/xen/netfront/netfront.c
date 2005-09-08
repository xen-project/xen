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
#include <linux/proc_fs.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <net/arp.h>
#include <net/route.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm-xen/evtchn.h>
#include <asm-xen/xenbus.h>
#include <asm-xen/xen-public/io/netif.h>
#include <asm-xen/xen-public/memory.h>
#include <asm-xen/balloon.h>
#include <asm/page.h>
#include <asm/uaccess.h>

#ifdef CONFIG_XEN_NETDEV_GRANT
#include <asm-xen/xen-public/grant_table.h>
#include <asm-xen/gnttab.h>

static grant_ref_t gref_tx_head;
static grant_ref_t grant_tx_ref[NETIF_TX_RING_SIZE + 1]; 

static grant_ref_t gref_rx_head;
static grant_ref_t grant_rx_ref[NETIF_RX_RING_SIZE + 1];

#define GRANT_INVALID_REF	(0xFFFF)

#ifdef GRANT_DEBUG
static void
dump_packet(int tag, void *addr, u32 ap)
{
    unsigned char *p = (unsigned char *)ap;
    int i;
    
    printk(KERN_ALERT "#### rx_poll   %c %08x ", tag & 0xff, addr);
    for (i = 0; i < 20; i++) {
        printk("%02x", p[i]);
    }
    printk("\n");
}

#define GDPRINTK(_f, _a...) printk(KERN_ALERT "(file=%s, line=%d) " _f, \
                           __FILE__ , __LINE__ , ## _a )
#else 
#define dump_packet(x,y,z)  ((void)0)  
#define GDPRINTK(_f, _a...) ((void)0)
#endif

#endif



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


#define NETIF_STATE_DISCONNECTED 0
#define NETIF_STATE_CONNECTED    1


static unsigned int netif_state = NETIF_STATE_DISCONNECTED;

static void network_tx_buf_gc(struct net_device *dev);
static void network_alloc_rx_buffers(struct net_device *dev);

static unsigned long rx_pfn_array[NETIF_RX_RING_SIZE];
static multicall_entry_t rx_mcl[NETIF_RX_RING_SIZE+1];
static mmu_update_t rx_mmu[NETIF_RX_RING_SIZE];

#ifdef CONFIG_PROC_FS
static int xennet_proc_init(void);
static int xennet_proc_addif(struct net_device *dev);
static void xennet_proc_delif(struct net_device *dev);
#else
#define xennet_proc_init()   (0)
#define xennet_proc_addif(d) (0)
#define xennet_proc_delif(d) ((void)0)
#endif

#define netfront_info net_private
struct net_private
{
    struct list_head list;
    struct net_device *netdev;

    struct net_device_stats stats;
    NETIF_RING_IDX rx_resp_cons, tx_resp_cons;
    unsigned int tx_full;
    
    netif_tx_interface_t *tx;
    netif_rx_interface_t *rx;

    spinlock_t   tx_lock;
    spinlock_t   rx_lock;

    unsigned int handle;
    unsigned int evtchn;

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
    int rx_min_target, rx_max_target, rx_target;
    struct sk_buff_head rx_batch;

    /*
     * {tx,rx}_skbs store outstanding skbuffs. The first entry in each
     * array is an index into a chain of free entries.
     */
    struct sk_buff *tx_skbs[NETIF_TX_RING_SIZE+1];
    struct sk_buff *rx_skbs[NETIF_RX_RING_SIZE+1];

	struct xenbus_device *xbdev;
	char *backend;
	int backend_id;
	struct xenbus_watch watch;
	int tx_ring_ref;
	int rx_ring_ref;
	u8 mac[ETH_ALEN];
};

/* Access macros for acquiring freeing slots in {tx,rx}_skbs[]. */
#define ADD_ID_TO_FREELIST(_list, _id)             \
    (_list)[(_id)] = (_list)[0];                   \
    (_list)[0]     = (void *)(unsigned long)(_id);
#define GET_ID_FROM_FREELIST(_list)                \
 ({ unsigned long _id = (unsigned long)(_list)[0]; \
    (_list)[0]  = (_list)[_id];                    \
    (unsigned short)_id; })

#ifdef DEBUG
static char *be_state_name[] = {
    [BEST_CLOSED]       = "closed",
    [BEST_DISCONNECTED] = "disconnected",
    [BEST_CONNECTED]    = "connected",
};
#endif

#ifdef DEBUG
#define DPRINTK(fmt, args...) \
    printk(KERN_ALERT "xen_net (%s:%d) " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define DPRINTK(fmt, args...) ((void)0)
#endif
#define IPRINTK(fmt, args...) \
    printk(KERN_INFO "xen_net: " fmt, ##args)
#define WPRINTK(fmt, args...) \
    printk(KERN_WARNING "xen_net: " fmt, ##args)

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
#ifdef CONFIG_XEN_NETDEV_GRANT
            if (unlikely(gnttab_query_foreign_access(grant_tx_ref[id]) != 0)) {
                /* other domain is still using this grant - shouldn't happen
                   but if it does, we'll try to reclaim the grant later */
                printk(KERN_ALERT "network_tx_buf_gc: warning -- grant "
                       "still in use by backend domain.\n");
                goto out; 
            }
            gnttab_end_foreign_access_ref(grant_tx_ref[id], GNTMAP_readonly);
            gnttab_release_grant_reference(&gref_tx_head, grant_tx_ref[id]);
            grant_tx_ref[id] = GRANT_INVALID_REF;
#endif
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

#ifdef CONFIG_XEN_NETDEV_GRANT
  out: 
#endif

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
    struct xen_memory_reservation reservation;
#ifdef CONFIG_XEN_NETDEV_GRANT
    grant_ref_t ref;
#endif

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
#ifdef CONFIG_XEN_NETDEV_GRANT
	ref = gnttab_claim_grant_reference(&gref_rx_head);
        if (unlikely((signed short)ref < 0)) {
            printk(KERN_ALERT "#### netfront can't claim rx reference\n");
            BUG();
        }
        grant_rx_ref[id] = ref;
        gnttab_grant_foreign_transfer_ref(ref, np->backend_id,
                                          virt_to_mfn(skb->head));
        np->rx->ring[MASK_NETIF_RX_IDX(req_prod + i)].req.gref = ref;
#endif
        rx_pfn_array[i] = virt_to_mfn(skb->head);

	/* Remove this page from pseudo phys map before passing back to Xen. */
	phys_to_machine_mapping[__pa(skb->head) >> PAGE_SHIFT] 
	    = INVALID_P2M_ENTRY;

	MULTI_update_va_mapping(rx_mcl+i, (unsigned long)skb->head,
				__pte(0), 0);
    }

    /* After all PTEs have been zapped we blow away stale TLB entries. */
    rx_mcl[i-1].args[MULTI_UVMFLAGS_INDEX] = UVMF_TLB_FLUSH|UVMF_ALL;

    /* Give away a batch of pages. */
    rx_mcl[i].op = __HYPERVISOR_memory_op;
    rx_mcl[i].args[0] = XENMEM_decrease_reservation;
    rx_mcl[i].args[1] = (unsigned long)&reservation;

    reservation.extent_start = rx_pfn_array;
    reservation.nr_extents   = i;
    reservation.extent_order = 0;
    reservation.address_bits = 0;
    reservation.domid        = DOMID_SELF;

    /* Tell the ballon driver what is going on. */
    balloon_update_driver_allowance(i);

    /* Zap PTEs and give away pages in one big multicall. */
    (void)HYPERVISOR_multicall(rx_mcl, i+1);

    /* Check return status of HYPERVISOR_memory_op(). */
    if (unlikely(rx_mcl[i].result != i))
        panic("Unable to reduce memory reservation\n");

    /* Above is a suitable barrier to ensure backend will see requests. */
    np->rx->req_prod = req_prod + i;

    /* Adjust our floating fill target if we risked running out of buffers. */
    if (((req_prod - np->rx->resp_prod) < (np->rx_target / 4)) &&
         ((np->rx_target *= 2) > np->rx_max_target))
        np->rx_target = np->rx_max_target;
}


static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    unsigned short id;
    struct net_private *np = netdev_priv(dev);
    netif_tx_request_t *tx;
    NETIF_RING_IDX i;
#ifdef CONFIG_XEN_NETDEV_GRANT
    grant_ref_t ref;
    unsigned long mfn;
#endif

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
#ifdef CONFIG_XEN_NETDEV_GRANT
    ref = gnttab_claim_grant_reference(&gref_tx_head);
    if (unlikely((signed short)ref < 0)) {
        printk(KERN_ALERT "#### netfront can't claim tx grant reference\n");
        BUG();
    }
    mfn = virt_to_mfn(skb->data);
    gnttab_grant_foreign_access_ref(ref, np->backend_id, mfn, GNTMAP_readonly);
    tx->addr = ref << PAGE_SHIFT;
    grant_tx_ref[id] = ref;
#else
    tx->addr = virt_to_mfn(skb->data) << PAGE_SHIFT;
#endif
    tx->addr |= (unsigned long)skb->data & ~PAGE_MASK;
    tx->size = skb->len;
    tx->csum_blank = (skb->ip_summed == CHECKSUM_HW);

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

    if((np->rx_resp_cons != np->rx->resp_prod) && (np->user_state == UST_OPEN))
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
#ifdef CONFIG_XEN_NETDEV_GRANT
    unsigned long mfn;
    grant_ref_t ref;
#endif

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

#ifdef CONFIG_XEN_NETDEV_GRANT
        ref = grant_rx_ref[rx->id]; 

        if(ref == GRANT_INVALID_REF) { 
            printk(KERN_WARNING "Bad rx grant reference %d from dom %d.\n",
                   ref, np->backend_id);
            np->rx->ring[MASK_NETIF_RX_IDX(np->rx->req_prod)].req.id = rx->id;
            wmb();
            np->rx->req_prod++;
            work_done--;
            continue;
        }

        grant_rx_ref[rx->id] = GRANT_INVALID_REF;
        mfn = gnttab_end_foreign_transfer_ref(ref);
        gnttab_release_grant_reference(&gref_rx_head, ref);
#endif

        skb = np->rx_skbs[rx->id];
        ADD_ID_TO_FREELIST(np->rx_skbs, rx->id);

        /* NB. We handle skb overflow later. */
#ifdef CONFIG_XEN_NETDEV_GRANT
        skb->data = skb->head + rx->addr;
#else
        skb->data = skb->head + (rx->addr & ~PAGE_MASK);
#endif
        skb->len  = rx->status;
        skb->tail = skb->data + skb->len;

        if ( rx->csum_valid )
            skb->ip_summed = CHECKSUM_UNNECESSARY;

        np->stats.rx_packets++;
        np->stats.rx_bytes += rx->status;

        /* Remap the page. */
#ifdef CONFIG_XEN_NETDEV_GRANT
        mmu->ptr = ((unsigned long long)mfn << PAGE_SHIFT) | MMU_MACHPHYS_UPDATE;
#else
        mmu->ptr  = (rx->addr & PAGE_MASK) | MMU_MACHPHYS_UPDATE;
#endif
        mmu->val  = __pa(skb->head) >> PAGE_SHIFT;
        mmu++;
#ifdef CONFIG_XEN_NETDEV_GRANT
	MULTI_update_va_mapping(mcl, (unsigned long)skb->head,
				pfn_pte_ma(mfn, PAGE_KERNEL), 0);
#else
	MULTI_update_va_mapping(mcl, (unsigned long)skb->head,
				pfn_pte_ma(rx->addr >> PAGE_SHIFT, 
                                           PAGE_KERNEL), 0);
#endif
        mcl++;

#ifdef CONFIG_XEN_NETDEV_GRANT
        phys_to_machine_mapping[__pa(skb->head) >> PAGE_SHIFT] = mfn;
        GDPRINTK("#### rx_poll     enqueue vdata=%p mfn=%lu ref=%x\n",
                skb->data, mfn, ref);
#else
        phys_to_machine_mapping[__pa(skb->head) >> PAGE_SHIFT] = 
            rx->addr >> PAGE_SHIFT;
#endif 


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
        mcl->args[3] = DOMID_SELF;
        mcl++;
        (void)HYPERVISOR_multicall(rx_mcl, mcl - rx_mcl);
    }

    while ((skb = __skb_dequeue(&rxq)) != NULL) {
#ifdef CONFIG_XEN_NETDEV_GRANT
        GDPRINTK("#### rx_poll     dequeue vdata=%p mfn=%lu\n",
                skb->data, virt_to_mfn(skb->data));
        dump_packet('d', skb->data, (unsigned long)skb->data);
#endif
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
                    printk(KERN_INFO "Received packet needs %zd bytes more "
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
         (--np->rx_target < np->rx_min_target))
        np->rx_target = np->rx_min_target;

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
    netif_stop_queue(np->netdev);
    return 0;
}


static struct net_device_stats *network_get_stats(struct net_device *dev)
{
    struct net_private *np = netdev_priv(dev);
    return &np->stats;
}

static void network_connect(struct net_device *dev)
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
#ifdef CONFIG_XEN_NETDEV_GRANT
            gnttab_grant_foreign_access_ref(grant_tx_ref[i], np->backend_id, 
                                            virt_to_mfn(np->tx_skbs[i]->data),
                                            GNTMAP_readonly); 
            tx->addr = grant_tx_ref[i] << PAGE_SHIFT; 
#else
            tx->addr = virt_to_mfn(skb->data) << PAGE_SHIFT;
#endif
            tx->addr |= (unsigned long)skb->data & ~PAGE_MASK;
            tx->size = skb->len;

            np->stats.tx_bytes += skb->len;
            np->stats.tx_packets++;
        }
    }
    wmb();
    np->tx->req_prod = requeue_idx;

    /* Rebuild the RX buffer freelist and the RX ring itself. */
    for (requeue_idx = 0, i = 1; i <= NETIF_RX_RING_SIZE; i++) { 
        if ((unsigned long)np->rx_skbs[i] >= __PAGE_OFFSET) {
#ifdef CONFIG_XEN_NETDEV_GRANT 
            /* Reinstate the grant ref so backend can 'donate' mfn to us. */
            gnttab_grant_foreign_transfer_ref(grant_rx_ref[i], np->backend_id,
                                              virt_to_mfn(np->rx_skbs[i]->head)
                );
            np->rx->ring[requeue_idx].req.gref = grant_rx_ref[i];
#endif
            np->rx->ring[requeue_idx].req.id   = i;
            requeue_idx++; 
        }
    }

    wmb();                
    np->rx->req_prod = requeue_idx;

    /* Step 3: All public and private state should now be sane.  Get
     * ready to start sending and receiving packets and give the driver
     * domain a kick because we've probably just requeued some
     * packets.
     */
    np->backend_state = BEST_CONNECTED;
    wmb();
    notify_via_evtchn(np->evtchn);  
    network_tx_buf_gc(dev);

    if (np->user_state == UST_OPEN)
        netif_start_queue(dev);

    spin_unlock(&np->rx_lock);
    spin_unlock_irq(&np->tx_lock);
}

static void show_device(struct net_private *np)
{
#ifdef DEBUG
	if (np) {
		IPRINTK("<vif handle=%u %s(%s) evtchn=%u tx=%p rx=%p>\n",
			np->handle,
			be_state_name[np->backend_state],
			np->user_state ? "open" : "closed",
			np->evtchn,
			np->tx,
			np->rx);
	} else {
		IPRINTK("<vif NULL>\n");
	}
#endif
}

/* Move the vif into connected state.
 * Sets the mac and event channel from the message.
 * Binds the irq to the event channel.
 */
static void 
connect_device(struct net_private *np, unsigned int evtchn)
{
	struct net_device *dev = np->netdev;
	memcpy(dev->dev_addr, np->mac, ETH_ALEN);
	np->evtchn = evtchn;
	network_connect(dev);
	(void)bind_evtchn_to_irqhandler(
		np->evtchn, netif_int, SA_SAMPLE_RANDOM, dev->name, dev);
	(void)send_fake_arp(dev);
	show_device(np);
}

static struct ethtool_ops network_ethtool_ops =
{
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = ethtool_op_set_tx_csum,
};

/** Create a network device.
 * @param handle device handle
 * @param val return parameter for created device
 * @return 0 on success, error code otherwise
 */
static int create_netdev(int handle, struct xenbus_device *dev,
			 struct net_device **val)
{
    int i, err = 0;
    struct net_device *netdev = NULL;
    struct net_private *np = NULL;

    if ((netdev = alloc_etherdev(sizeof(struct net_private))) == NULL) {
        printk(KERN_WARNING "%s> alloc_etherdev failed.\n", __FUNCTION__);
        err = -ENOMEM;
        goto exit;
    }

    np                = netdev_priv(netdev);
    np->backend_state = BEST_CLOSED;
    np->user_state    = UST_CLOSED;
    np->handle        = handle;
    np->xbdev         = dev;
    
    spin_lock_init(&np->tx_lock);
    spin_lock_init(&np->rx_lock);

    skb_queue_head_init(&np->rx_batch);
    np->rx_target     = RX_MIN_TARGET;
    np->rx_min_target = RX_MIN_TARGET;
    np->rx_max_target = RX_MAX_TARGET;

    /* Initialise {tx,rx}_skbs to be a free chain containing every entry. */
    for (i = 0; i <= NETIF_TX_RING_SIZE; i++) {
        np->tx_skbs[i] = (void *)((unsigned long) i+1);
#ifdef CONFIG_XEN_NETDEV_GRANT
        grant_tx_ref[i] = GRANT_INVALID_REF;
#endif
    }

    for (i = 0; i <= NETIF_RX_RING_SIZE; i++) {
        np->rx_skbs[i] = (void *)((unsigned long) i+1);
#ifdef CONFIG_XEN_NETDEV_GRANT
        grant_rx_ref[i] = GRANT_INVALID_REF;
#endif
    }

    netdev->open            = network_open;
    netdev->hard_start_xmit = network_start_xmit;
    netdev->stop            = network_close;
    netdev->get_stats       = network_get_stats;
    netdev->poll            = netif_poll;
    netdev->weight          = 64;
    netdev->features        = NETIF_F_IP_CSUM;

    SET_ETHTOOL_OPS(netdev, &network_ethtool_ops);

    if ((err = register_netdev(netdev)) != 0) {
        printk(KERN_WARNING "%s> register_netdev err=%d\n", __FUNCTION__, err);
        goto exit;
    }

    if ((err = xennet_proc_addif(netdev)) != 0) {
        unregister_netdev(netdev);
        goto exit;
    }

    np->netdev = netdev;

  exit:
    if ((err != 0) && (netdev != NULL))
        kfree(netdev);
    else if (val != NULL)
        *val = netdev;
    return err;
}

static int destroy_netdev(struct net_device *netdev)
{

#ifdef CONFIG_PROC_FS
	xennet_proc_delif(netdev);
#endif

        unregister_netdev(netdev);

	return 0;
}

/*
 * We use this notifier to send out a fake ARP reply to reset switches and
 * router ARP caches when an IP interface is brought up on a VIF.
 */
static int 
inetdev_notify(struct notifier_block *this, unsigned long event, void *ptr)
{
    struct in_ifaddr  *ifa = (struct in_ifaddr *)ptr; 
    struct net_device *dev = ifa->ifa_dev->dev;

    /* UP event and is it one of our devices? */
    if (event == NETDEV_UP && dev->open == network_open)
        (void)send_fake_arp(dev);
        
    return NOTIFY_DONE;
}

static struct notifier_block notifier_inetdev = {
    .notifier_call  = inetdev_notify,
    .next           = NULL,
    .priority       = 0
};

static struct xenbus_device_id netfront_ids[] = {
	{ "vif" },
	{ "" }
};

static void watch_for_status(struct xenbus_watch *watch, const char *node)
{
}

static int setup_device(struct xenbus_device *dev, struct netfront_info *info)
{
	evtchn_op_t op = { .cmd = EVTCHNOP_alloc_unbound };
	int err;

#ifdef CONFIG_XEN_NETDEV_GRANT
	info->tx_ring_ref = GRANT_INVALID_REF;
	info->rx_ring_ref = GRANT_INVALID_REF;
#endif

	info->tx = (netif_tx_interface_t *)__get_free_page(GFP_KERNEL);
	if (info->tx == 0) {
		err = -ENOMEM;
		xenbus_dev_error(dev, err, "allocating tx ring page");
		goto out;
	}
	info->rx = (netif_rx_interface_t *)__get_free_page(GFP_KERNEL);
	if (info->rx == 0) {
		err = -ENOMEM;
		xenbus_dev_error(dev, err, "allocating rx ring page");
		goto out;
	}
	memset(info->tx, 0, PAGE_SIZE);
	memset(info->rx, 0, PAGE_SIZE);
	info->backend_state = BEST_DISCONNECTED;

#ifdef CONFIG_XEN_NETDEV_GRANT
	err = gnttab_grant_foreign_access(info->backend_id,
					  virt_to_mfn(info->tx), 0);
	if (err < 0) {
		xenbus_dev_error(dev, err, "granting access to tx ring page");
		goto out;
	}
	info->tx_ring_ref = err;

	err = gnttab_grant_foreign_access(info->backend_id,
					  virt_to_mfn(info->rx), 0);
	if (err < 0) {
		xenbus_dev_error(dev, err, "granting access to rx ring page");
		goto out;
	}
	info->rx_ring_ref = err;

#else
	info->tx_ring_ref = virt_to_mfn(info->tx);
	info->rx_ring_ref = virt_to_mfn(info->rx);
#endif

	op.u.alloc_unbound.dom = info->backend_id;
	err = HYPERVISOR_event_channel_op(&op);
	if (err) {
		xenbus_dev_error(dev, err, "allocating event channel");
		goto out;
	}
	connect_device(info, op.u.alloc_unbound.port);
	return 0;

 out:
	if (info->tx)
		free_page((unsigned long)info->tx);
	info->tx = 0;
	if (info->rx)
		free_page((unsigned long)info->rx);
	info->rx = 0;

#ifdef CONFIG_XEN_NETDEV_GRANT
	if (info->tx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(info->tx_ring_ref, 0);
	info->tx_ring_ref = GRANT_INVALID_REF;

	if (info->rx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(info->rx_ring_ref, 0);
	info->rx_ring_ref = GRANT_INVALID_REF;
#endif

	return err;
}

static void netif_free(struct netfront_info *info)
{
	if (info->tx)
		free_page((unsigned long)info->tx);
	info->tx = 0;
	if (info->rx)
		free_page((unsigned long)info->rx);
	info->rx = 0;

#ifdef CONFIG_XEN_NETDEV_GRANT
	if (info->tx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(info->tx_ring_ref, 0);
	info->tx_ring_ref = GRANT_INVALID_REF;

	if (info->rx_ring_ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(info->rx_ring_ref, 0);
	info->rx_ring_ref = GRANT_INVALID_REF;
#endif

	unbind_evtchn_from_irqhandler(info->evtchn, info->netdev);
	info->evtchn = 0;
}

/* Stop network device and free tx/rx queues and irq.
 */
static void shutdown_device(struct net_private *np)
{
	/* Stop old i/f to prevent errors whilst we rebuild the state. */
	spin_lock_irq(&np->tx_lock);
	spin_lock(&np->rx_lock);
	netif_stop_queue(np->netdev);
	/* np->backend_state = BEST_DISCONNECTED; */
	spin_unlock(&np->rx_lock);
	spin_unlock_irq(&np->tx_lock);
    
	/* Free resources. */
	netif_free(np);
}

/* Common code used when first setting up, and when resuming. */
static int talk_to_backend(struct xenbus_device *dev,
			   struct netfront_info *info)
{
	char *backend, *mac, *e, *s;
	const char *message;
	int err, i;

	backend = NULL;
	err = xenbus_gather(dev->nodename,
			    "backend-id", "%i", &info->backend_id,
			    "backend", NULL, &backend,
			    NULL);
	if (XENBUS_EXIST_ERR(err))
		goto out;
	if (backend && strlen(backend) == 0) {
		err = -ENOENT;
		goto out;
	}
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading %s/backend or backend-id",
				 dev->nodename);
		goto out;
	}

	mac = xenbus_read(dev->nodename, "mac", NULL);
	if (IS_ERR(mac)) {
		err = PTR_ERR(mac);
		xenbus_dev_error(dev, err, "reading %s/mac",
				 dev->nodename);
		goto out;
	}
	s = mac;
	for (i = 0; i < ETH_ALEN; i++) {
		info->mac[i] = simple_strtoul(s, &e, 16);
		if (s == e || (e[0] != ':' && e[0] != 0)) {
			kfree(mac);
			err = -ENOENT;
			xenbus_dev_error(dev, err, "parsing %s/mac",
					 dev->nodename);
			goto out;
		}
		s = &e[1];
	}
	kfree(mac);

	/* Create shared ring, alloc event channel. */
	err = setup_device(dev, info);
	if (err) {
		xenbus_dev_error(dev, err, "setting up ring");
		goto out;
	}

	err = xenbus_transaction_start(dev->nodename);
	if (err) {
		xenbus_dev_error(dev, err, "starting transaction");
		goto destroy_ring;
	}

	err = xenbus_printf(dev->nodename, "tx-ring-ref","%u",
			    info->tx_ring_ref);
	if (err) {
		message = "writing tx ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(dev->nodename, "rx-ring-ref","%u",
			    info->rx_ring_ref);
	if (err) {
		message = "writing rx ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(dev->nodename,
			    "event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	info->backend = backend;
	backend = NULL;

	info->watch.node = info->backend;
	info->watch.callback = watch_for_status;
	err = register_xenbus_watch(&info->watch);
	if (err) {
		message = "registering watch on backend";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(0);
	if (err) {
		xenbus_dev_error(dev, err, "completing transaction");
		goto destroy_ring;
	}

	netif_state = NETIF_STATE_CONNECTED;

 out:
	if (backend)
		kfree(backend);
	return err;

 abort_transaction:
	xenbus_transaction_end(1);
	/* Have to do this *outside* transaction.  */
	xenbus_dev_error(dev, err, "%s", message);
 destroy_ring:
	shutdown_device(info);
	goto out;
}

/* Setup supplies the backend dir, virtual device.

   We place an event channel and shared frame entries.
   We watch backend to wait if it's ok. */
static int netfront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	int err;
	struct net_device *netdev;
	struct netfront_info *info;
	unsigned int handle;

	err = xenbus_scanf(dev->nodename, "handle", "%u", &handle);
	if (XENBUS_EXIST_ERR(err))
		return err;
	if (err < 0) {
		xenbus_dev_error(dev, err, "reading handle");
		return err;
	}

	err = create_netdev(handle, dev, &netdev);
	if (err) {
		xenbus_dev_error(dev, err, "creating netdev");
		return err;
	}

	info = netdev_priv(netdev);
	dev->data = info;

	err = talk_to_backend(dev, info);
	if (err) {
		destroy_netdev(netdev);
		kfree(netdev);
		dev->data = NULL;
		return err;
	}


	/* Call once in case entries already there. */
	watch_for_status(&info->watch, info->watch.node);

	return 0;
}

static int netfront_remove(struct xenbus_device *dev)
{
	struct netfront_info *info = dev->data;

	if (info->backend)
		unregister_xenbus_watch(&info->watch);

	netif_free(info);

	kfree(info->backend);
	kfree(info);

	return 0;
}

static int netfront_suspend(struct xenbus_device *dev)
{
	struct netfront_info *info = dev->data;

	unregister_xenbus_watch(&info->watch);
	kfree(info->backend);
	info->backend = NULL;

	netif_free(info);

	return 0;
}

static int netfront_resume(struct xenbus_device *dev)
{
	struct net_private *np = dev->data;
	int err;

	err = talk_to_backend(dev, np);

	return err;
}

static struct xenbus_driver netfront = {
	.name = "vif",
	.owner = THIS_MODULE,
	.ids = netfront_ids,
	.probe = netfront_probe,
	.remove = netfront_remove,
	.resume = netfront_resume,
	.suspend = netfront_suspend,
};

static void __init init_net_xenbus(void)
{
	xenbus_register_device(&netfront);
}

static int wait_for_netif(void)
{
    int err = 0;
    int i;

    /*
     * We should figure out how many and which devices we need to
     * proceed and only wait for those.  For now, continue once the
     * first device is around.
     */
    for ( i=0; netif_state != NETIF_STATE_CONNECTED && (i < 10*HZ); i++ )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(1);
    }

    if (netif_state != NETIF_STATE_CONNECTED) {
        WPRINTK("Timeout connecting to device!\n");
        err = -ENOSYS;
    }
    return err;
}

static int __init netif_init(void)
{
    int err = 0;

    if (xen_start_info->flags & SIF_INITDOMAIN)
        return 0;

    if ((err = xennet_proc_init()) != 0)
        return err;

    IPRINTK("Initialising virtual ethernet driver.\n");

#ifdef CONFIG_XEN_NETDEV_GRANT
    IPRINTK("Using grant tables.\n"); 

    /* A grant for every tx ring slot */
    if (gnttab_alloc_grant_references(NETIF_TX_RING_SIZE,
                                      &gref_tx_head) < 0) {
        printk(KERN_ALERT "#### netfront can't alloc tx grant refs\n");
        return 1;
    }
    /* A grant for every rx ring slot */
    if (gnttab_alloc_grant_references(NETIF_RX_RING_SIZE,
                                      &gref_rx_head) < 0) {
        printk(KERN_ALERT "#### netfront can't alloc rx grant refs\n");
        return 1;
    }
#endif


    (void)register_inetaddr_notifier(&notifier_inetdev);

    init_net_xenbus();

    wait_for_netif();

    return err;
}

static void netif_exit(void)
{
#ifdef CONFIG_XEN_NETDEV_GRANT
    gnttab_free_grant_references(gref_tx_head);
    gnttab_free_grant_references(gref_rx_head);
#endif
}

#ifdef CONFIG_PROC_FS

#define TARGET_MIN 0UL
#define TARGET_MAX 1UL
#define TARGET_CUR 2UL

static int xennet_proc_read(
    char *page, char **start, off_t off, int count, int *eof, void *data)
{
    struct net_device *dev = (struct net_device *)((unsigned long)data & ~3UL);
    struct net_private *np = netdev_priv(dev);
    int len = 0, which_target = (long)data & 3;
    
    switch (which_target)
    {
    case TARGET_MIN:
        len = sprintf(page, "%d\n", np->rx_min_target);
        break;
    case TARGET_MAX:
        len = sprintf(page, "%d\n", np->rx_max_target);
        break;
    case TARGET_CUR:
        len = sprintf(page, "%d\n", np->rx_target);
        break;
    }

    *eof = 1;
    return len;
}

static int xennet_proc_write(
    struct file *file, const char __user *buffer,
    unsigned long count, void *data)
{
    struct net_device *dev = (struct net_device *)((unsigned long)data & ~3UL);
    struct net_private *np = netdev_priv(dev);
    int which_target = (long)data & 3;
    char string[64];
    long target;

    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    if (count <= 1)
        return -EBADMSG; /* runt */
    if (count > sizeof(string))
        return -EFBIG;   /* too long */

    if (copy_from_user(string, buffer, count))
        return -EFAULT;
    string[sizeof(string)-1] = '\0';

    target = simple_strtol(string, NULL, 10);
    if (target < RX_MIN_TARGET)
        target = RX_MIN_TARGET;
    if (target > RX_MAX_TARGET)
        target = RX_MAX_TARGET;

    spin_lock(&np->rx_lock);

    switch (which_target)
    {
    case TARGET_MIN:
        if (target > np->rx_max_target)
            np->rx_max_target = target;
        np->rx_min_target = target;
        if (target > np->rx_target)
            np->rx_target = target;
        break;
    case TARGET_MAX:
        if (target < np->rx_min_target)
            np->rx_min_target = target;
        np->rx_max_target = target;
        if (target < np->rx_target)
            np->rx_target = target;
        break;
    case TARGET_CUR:
        break;
    }

    network_alloc_rx_buffers(dev);

    spin_unlock(&np->rx_lock);

    return count;
}

static int xennet_proc_init(void)
{
    if (proc_mkdir("xen/net", NULL) == NULL)
        return -ENOMEM;
    return 0;
}

static int xennet_proc_addif(struct net_device *dev)
{
    struct proc_dir_entry *dir, *min, *max, *cur;
    char name[30];

    sprintf(name, "xen/net/%s", dev->name);

    dir = proc_mkdir(name, NULL);
    if (!dir)
        goto nomem;

    min = create_proc_entry("rxbuf_min", 0644, dir);
    max = create_proc_entry("rxbuf_max", 0644, dir);
    cur = create_proc_entry("rxbuf_cur", 0444, dir);
    if (!min || !max || !cur)
        goto nomem;

    min->read_proc  = xennet_proc_read;
    min->write_proc = xennet_proc_write;
    min->data       = (void *)((unsigned long)dev | TARGET_MIN);

    max->read_proc  = xennet_proc_read;
    max->write_proc = xennet_proc_write;
    max->data       = (void *)((unsigned long)dev | TARGET_MAX);

    cur->read_proc  = xennet_proc_read;
    cur->write_proc = xennet_proc_write;
    cur->data       = (void *)((unsigned long)dev | TARGET_CUR);

    return 0;

 nomem:
    xennet_proc_delif(dev);
    return -ENOMEM;
}

static void xennet_proc_delif(struct net_device *dev)
{
    char name[30];

    sprintf(name, "xen/net/%s/rxbuf_min", dev->name);
    remove_proc_entry(name, NULL);

    sprintf(name, "xen/net/%s/rxbuf_max", dev->name);
    remove_proc_entry(name, NULL);

    sprintf(name, "xen/net/%s/rxbuf_cur", dev->name);
    remove_proc_entry(name, NULL);

    sprintf(name, "xen/net/%s", dev->name);
    remove_proc_entry(name, NULL);
}

#endif

module_init(netif_init);
module_exit(netif_exit);
