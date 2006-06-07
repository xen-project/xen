/******************************************************************************
 * Virtual network driver for conversing with remote driver backends.
 *
 * Copyright (c) 2002-2005, K A Fraser
 * Copyright (c) 2005, XenSource Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
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
#include <linux/ethtool.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <net/arp.h>
#include <net/route.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <xen/evtchn.h>
#include <xen/xenbus.h>
#include <xen/interface/io/netif.h>
#include <xen/interface/memory.h>
#include <xen/balloon.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <xen/interface/grant_table.h>
#include <xen/gnttab.h>

#define GRANT_INVALID_REF	0

#define NET_TX_RING_SIZE __RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)
#define NET_RX_RING_SIZE __RING_SIZE((struct netif_rx_sring *)0, PAGE_SIZE)

static inline void init_skb_shinfo(struct sk_buff *skb)
{
	atomic_set(&(skb_shinfo(skb)->dataref), 1);
	skb_shinfo(skb)->nr_frags = 0;
	skb_shinfo(skb)->frag_list = NULL;
}

struct netfront_info {
	struct list_head list;
	struct net_device *netdev;

	struct net_device_stats stats;

	struct netif_tx_front_ring tx;
	struct netif_rx_front_ring rx;

	spinlock_t   tx_lock;
	spinlock_t   rx_lock;

	unsigned int handle;
	unsigned int evtchn, irq;

	/* Receive-ring batched refills. */
#define RX_MIN_TARGET 8
#define RX_DFL_MIN_TARGET 64
#define RX_MAX_TARGET min_t(int, NET_RX_RING_SIZE, 256)
	unsigned rx_min_target, rx_max_target, rx_target;
	struct sk_buff_head rx_batch;

	struct timer_list rx_refill_timer;

	/*
	 * {tx,rx}_skbs store outstanding skbuffs. The first entry in each
	 * array is an index into a chain of free entries.
	 */
	struct sk_buff *tx_skbs[NET_TX_RING_SIZE+1];
	struct sk_buff *rx_skbs[NET_RX_RING_SIZE+1];

#define TX_MAX_TARGET min_t(int, NET_RX_RING_SIZE, 256)
	grant_ref_t gref_tx_head;
	grant_ref_t grant_tx_ref[NET_TX_RING_SIZE + 1];
	grant_ref_t gref_rx_head;
	grant_ref_t grant_rx_ref[NET_TX_RING_SIZE + 1];

	struct xenbus_device *xbdev;
	int tx_ring_ref;
	int rx_ring_ref;
	u8 mac[ETH_ALEN];

	unsigned long rx_pfn_array[NET_RX_RING_SIZE];
	struct multicall_entry rx_mcl[NET_RX_RING_SIZE+1];
	struct mmu_update rx_mmu[NET_RX_RING_SIZE];
};

/*
 * Access macros for acquiring freeing slots in {tx,rx}_skbs[].
 */

static inline void add_id_to_freelist(struct sk_buff **list, unsigned short id)
{
	list[id] = list[0];
	list[0]  = (void *)(unsigned long)id;
}

static inline unsigned short get_id_from_freelist(struct sk_buff **list)
{
	unsigned int id = (unsigned int)(unsigned long)list[0];
	list[0] = list[id];
	return id;
}

#define DPRINTK(fmt, args...) pr_debug("netfront (%s:%d) " fmt, \
                                       __FUNCTION__, __LINE__, ##args)
#define IPRINTK(fmt, args...)				\
	printk(KERN_INFO "netfront: " fmt, ##args)
#define WPRINTK(fmt, args...)				\
	printk(KERN_WARNING "netfront: " fmt, ##args)


static int talk_to_backend(struct xenbus_device *, struct netfront_info *);
static int setup_device(struct xenbus_device *, struct netfront_info *);
static struct net_device *create_netdev(int, struct xenbus_device *);

static void netfront_closing(struct xenbus_device *);

static void end_access(int, void *);
static void netif_disconnect_backend(struct netfront_info *);
static void close_netdev(struct netfront_info *);
static void netif_free(struct netfront_info *);

static void show_device(struct netfront_info *);

static void network_connect(struct net_device *);
static void network_tx_buf_gc(struct net_device *);
static void network_alloc_rx_buffers(struct net_device *);
static int send_fake_arp(struct net_device *);

static irqreturn_t netif_int(int irq, void *dev_id, struct pt_regs *ptregs);

#ifdef CONFIG_SYSFS
static int xennet_sysfs_addif(struct net_device *netdev);
static void xennet_sysfs_delif(struct net_device *netdev);
#else /* !CONFIG_SYSFS */
#define xennet_sysfs_addif(dev) (0)
#define xennet_sysfs_delif(dev) do { } while(0)
#endif

static inline int xennet_can_sg(struct net_device *dev)
{
	return dev->features & NETIF_F_SG;
}

/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and the ring buffers for communication with the backend, and
 * inform the backend of the appropriate details for those.  Switch to
 * Connected state.
 */
static int __devinit netfront_probe(struct xenbus_device *dev,
				    const struct xenbus_device_id *id)
{
	int err;
	struct net_device *netdev;
	struct netfront_info *info;
	unsigned int handle;

	err = xenbus_scanf(XBT_NULL, dev->nodename, "handle", "%u", &handle);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading handle");
		return err;
	}

	netdev = create_netdev(handle, dev);
	if (IS_ERR(netdev)) {
		err = PTR_ERR(netdev);
		xenbus_dev_fatal(dev, err, "creating netdev");
		return err;
	}

	info = netdev_priv(netdev);
	dev->data = info;

	err = talk_to_backend(dev, info);
	if (err) {
		xennet_sysfs_delif(info->netdev);
		unregister_netdev(netdev);
		free_netdev(netdev);
		dev->data = NULL;
		return err;
	}

	return 0;
}


/**
 * We are reconnecting to the backend, due to a suspend/resume, or a backend
 * driver restart.  We tear down our netif structure and recreate it, but
 * leave the device-layer structures intact so that this is transparent to the
 * rest of the kernel.
 */
static int netfront_resume(struct xenbus_device *dev)
{
	struct netfront_info *info = dev->data;

	DPRINTK("%s\n", dev->nodename);

	netif_disconnect_backend(info);
	return talk_to_backend(dev, info);
}

static int xen_net_read_mac(struct xenbus_device *dev, u8 mac[])
{
	char *s, *e, *macstr;
	int i;

	macstr = s = xenbus_read(XBT_NULL, dev->nodename, "mac", NULL);
	if (IS_ERR(macstr))
		return PTR_ERR(macstr);

	for (i = 0; i < ETH_ALEN; i++) {
		mac[i] = simple_strtoul(s, &e, 16);
		if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
			kfree(macstr);
			return -ENOENT;
		}
		s = e+1;
	}

	kfree(macstr);
	return 0;
}

/* Common code used when first setting up, and when resuming. */
static int talk_to_backend(struct xenbus_device *dev,
			   struct netfront_info *info)
{
	const char *message;
	xenbus_transaction_t xbt;
	int err;

	err = xen_net_read_mac(dev, info->mac);
	if (err) {
		xenbus_dev_fatal(dev, err, "parsing %s/mac", dev->nodename);
		goto out;
	}

	/* Create shared ring, alloc event channel. */
	err = setup_device(dev, info);
	if (err)
		goto out;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_ring;
	}

	err = xenbus_printf(xbt, dev->nodename, "tx-ring-ref","%u",
			    info->tx_ring_ref);
	if (err) {
		message = "writing tx ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename, "rx-ring-ref","%u",
			    info->rx_ring_ref);
	if (err) {
		message = "writing rx ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_ring;
	}

	return 0;

 abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, err, "%s", message);
 destroy_ring:
	netif_free(info);
 out:
	return err;
}


static int setup_device(struct xenbus_device *dev, struct netfront_info *info)
{
	struct netif_tx_sring *txs;
	struct netif_rx_sring *rxs;
	int err;
	struct net_device *netdev = info->netdev;

	info->tx_ring_ref = GRANT_INVALID_REF;
	info->rx_ring_ref = GRANT_INVALID_REF;
	info->rx.sring = NULL;
	info->tx.sring = NULL;
	info->irq = 0;

	txs = (struct netif_tx_sring *)__get_free_page(GFP_KERNEL);
	if (!txs) {
		err = -ENOMEM;
		xenbus_dev_fatal(dev, err, "allocating tx ring page");
		goto fail;
	}
	rxs = (struct netif_rx_sring *)__get_free_page(GFP_KERNEL);
	if (!rxs) {
		err = -ENOMEM;
		xenbus_dev_fatal(dev, err, "allocating rx ring page");
		goto fail;
	}
	memset(txs, 0, PAGE_SIZE);
	memset(rxs, 0, PAGE_SIZE);

	SHARED_RING_INIT(txs);
	FRONT_RING_INIT(&info->tx, txs, PAGE_SIZE);

	SHARED_RING_INIT(rxs);
	FRONT_RING_INIT(&info->rx, rxs, PAGE_SIZE);

	err = xenbus_grant_ring(dev, virt_to_mfn(txs));
	if (err < 0)
		goto fail;
	info->tx_ring_ref = err;

	err = xenbus_grant_ring(dev, virt_to_mfn(rxs));
	if (err < 0)
		goto fail;
	info->rx_ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err)
		goto fail;

	memcpy(netdev->dev_addr, info->mac, ETH_ALEN);
	info->irq = bind_evtchn_to_irqhandler(
		info->evtchn, netif_int, SA_SAMPLE_RANDOM, netdev->name,
		netdev);

	return 0;

 fail:
	netif_free(info);
	return err;
}


/**
 * Callback received when the backend's state changes.
 */
static void backend_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	struct netfront_info *np = dev->data;
	struct net_device *netdev = np->netdev;

	DPRINTK("\n");

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	case XenbusStateConnected:
	case XenbusStateUnknown:
	case XenbusStateClosed:
		break;

	case XenbusStateInitWait:
		network_connect(netdev);
		xenbus_switch_state(dev, XenbusStateConnected);
		(void)send_fake_arp(netdev);
		show_device(np);
		break;

	case XenbusStateClosing:
		netfront_closing(dev);
		break;
	}
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
	struct netfront_info *np = netdev_priv(dev);

	memset(&np->stats, 0, sizeof(np->stats));

	network_alloc_rx_buffers(dev);
	np->rx.sring->rsp_event = np->rx.rsp_cons + 1;

	netif_start_queue(dev);

	return 0;
}

static inline int netfront_tx_slot_available(struct netfront_info *np)
{
	return RING_FREE_REQUESTS(&np->tx) >= MAX_SKB_FRAGS + 1;
}

static inline void network_maybe_wake_tx(struct net_device *dev)
{
	struct netfront_info *np = netdev_priv(dev);

	if (unlikely(netif_queue_stopped(dev)) &&
	    netfront_tx_slot_available(np) &&
	    likely(netif_running(dev)))
		netif_wake_queue(dev);
}

static void network_tx_buf_gc(struct net_device *dev)
{
	RING_IDX cons, prod;
	unsigned short id;
	struct netfront_info *np = netdev_priv(dev);
	struct sk_buff *skb;

	if (unlikely(!netif_carrier_ok(dev)))
		return;

	do {
		prod = np->tx.sring->rsp_prod;
		rmb(); /* Ensure we see responses up to 'rp'. */

		for (cons = np->tx.rsp_cons; cons != prod; cons++) {
			id  = RING_GET_RESPONSE(&np->tx, cons)->id;
			skb = np->tx_skbs[id];
			if (unlikely(gnttab_query_foreign_access(
				np->grant_tx_ref[id]) != 0)) {
				printk(KERN_ALERT "network_tx_buf_gc: warning "
				       "-- grant still in use by backend "
				       "domain.\n");
				BUG();
			}
			gnttab_end_foreign_access_ref(
				np->grant_tx_ref[id], GNTMAP_readonly);
			gnttab_release_grant_reference(
				&np->gref_tx_head, np->grant_tx_ref[id]);
			np->grant_tx_ref[id] = GRANT_INVALID_REF;
			add_id_to_freelist(np->tx_skbs, id);
			dev_kfree_skb_irq(skb);
		}

		np->tx.rsp_cons = prod;

		/*
		 * Set a new event, then check for race with update of tx_cons.
		 * Note that it is essential to schedule a callback, no matter
		 * how few buffers are pending. Even if there is space in the
		 * transmit ring, higher layers may be blocked because too much
		 * data is outstanding: in such cases notification from Xen is
		 * likely to be the only kick that we'll get.
		 */
		np->tx.sring->rsp_event =
			prod + ((np->tx.sring->req_prod - prod) >> 1) + 1;
		mb();
	} while ((cons == prod) && (prod != np->tx.sring->rsp_prod));

	network_maybe_wake_tx(dev);
}


static void rx_refill_timeout(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	netif_rx_schedule(dev);
}


static void network_alloc_rx_buffers(struct net_device *dev)
{
	unsigned short id;
	struct netfront_info *np = netdev_priv(dev);
	struct sk_buff *skb;
	int i, batch_target;
	RING_IDX req_prod = np->rx.req_prod_pvt;
	struct xen_memory_reservation reservation;
	grant_ref_t ref;

	if (unlikely(!netif_carrier_ok(dev)))
		return;

	/*
	 * Allocate skbuffs greedily, even though we batch updates to the
	 * receive ring. This creates a less bursty demand on the memory
	 * allocator, so should reduce the chance of failed allocation requests
	 * both for ourself and for other kernel subsystems.
	 */
	batch_target = np->rx_target - (req_prod - np->rx.rsp_cons);
	for (i = skb_queue_len(&np->rx_batch); i < batch_target; i++) {
		/*
		 * Subtract dev_alloc_skb headroom (16 bytes) and shared info
		 * tailroom then round down to SKB_DATA_ALIGN boundary.
		 */
		skb = __dev_alloc_skb(
			((PAGE_SIZE - sizeof(struct skb_shared_info)) &
			 (-SKB_DATA_ALIGN(1))) - 16,
			GFP_ATOMIC|__GFP_NOWARN);
		if (skb == NULL) {
			/* Any skbuffs queued for refill? Force them out. */
			if (i != 0)
				goto refill;
			/* Could not allocate any skbuffs. Try again later. */
			mod_timer(&np->rx_refill_timer,
				  jiffies + (HZ/10));
			return;
		}
		__skb_queue_tail(&np->rx_batch, skb);
	}

	/* Is the batch large enough to be worthwhile? */
	if (i < (np->rx_target/2))
		return;

	/* Adjust our fill target if we risked running out of buffers. */
	if (((req_prod - np->rx.sring->rsp_prod) < (np->rx_target / 4)) &&
	    ((np->rx_target *= 2) > np->rx_max_target))
		np->rx_target = np->rx_max_target;

 refill:
	for (i = 0; ; i++) {
		if ((skb = __skb_dequeue(&np->rx_batch)) == NULL)
			break;

		skb->dev = dev;

		id = get_id_from_freelist(np->rx_skbs);

		np->rx_skbs[id] = skb;

		RING_GET_REQUEST(&np->rx, req_prod + i)->id = id;
		ref = gnttab_claim_grant_reference(&np->gref_rx_head);
		BUG_ON((signed short)ref < 0);
		np->grant_rx_ref[id] = ref;
		gnttab_grant_foreign_transfer_ref(ref,
						  np->xbdev->otherend_id,
						  __pa(skb->head) >> PAGE_SHIFT);
		RING_GET_REQUEST(&np->rx, req_prod + i)->gref = ref;
		np->rx_pfn_array[i] = virt_to_mfn(skb->head);

		if (!xen_feature(XENFEAT_auto_translated_physmap)) {
			/* Remove this page before passing back to Xen. */
			set_phys_to_machine(__pa(skb->head) >> PAGE_SHIFT,
					    INVALID_P2M_ENTRY);
			MULTI_update_va_mapping(np->rx_mcl+i,
						(unsigned long)skb->head,
						__pte(0), 0);
		}
	}

	/* Tell the ballon driver what is going on. */
	balloon_update_driver_allowance(i);

	set_xen_guest_handle(reservation.extent_start, np->rx_pfn_array);
	reservation.nr_extents   = i;
	reservation.extent_order = 0;
	reservation.address_bits = 0;
	reservation.domid        = DOMID_SELF;

	if (!xen_feature(XENFEAT_auto_translated_physmap)) {
		/* After all PTEs have been zapped, flush the TLB. */
		np->rx_mcl[i-1].args[MULTI_UVMFLAGS_INDEX] =
			UVMF_TLB_FLUSH|UVMF_ALL;

		/* Give away a batch of pages. */
		np->rx_mcl[i].op = __HYPERVISOR_memory_op;
		np->rx_mcl[i].args[0] = XENMEM_decrease_reservation;
		np->rx_mcl[i].args[1] = (unsigned long)&reservation;

		/* Zap PTEs and give away pages in one big multicall. */
		(void)HYPERVISOR_multicall(np->rx_mcl, i+1);

		/* Check return status of HYPERVISOR_memory_op(). */
		if (unlikely(np->rx_mcl[i].result != i))
			panic("Unable to reduce memory reservation\n");
	} else
		if (HYPERVISOR_memory_op(XENMEM_decrease_reservation,
					 &reservation) != i)
			panic("Unable to reduce memory reservation\n");

	/* Above is a suitable barrier to ensure backend will see requests. */
	np->rx.req_prod_pvt = req_prod + i;
	RING_PUSH_REQUESTS(&np->rx);
}

static void xennet_make_frags(struct sk_buff *skb, struct net_device *dev,
			      struct netif_tx_request *tx)
{
	struct netfront_info *np = netdev_priv(dev);
	char *data = skb->data;
	unsigned long mfn;
	RING_IDX prod = np->tx.req_prod_pvt;
	int frags = skb_shinfo(skb)->nr_frags;
	unsigned int offset = offset_in_page(data);
	unsigned int len = skb_headlen(skb);
	unsigned int id;
	grant_ref_t ref;
	int i;

	while (len > PAGE_SIZE - offset) {
		tx->size = PAGE_SIZE - offset;
		tx->flags |= NETTXF_more_data;
		len -= tx->size;
		data += tx->size;
		offset = 0;

		id = get_id_from_freelist(np->tx_skbs);
		np->tx_skbs[id] = skb_get(skb);
		tx = RING_GET_REQUEST(&np->tx, prod++);
		tx->id = id;
		ref = gnttab_claim_grant_reference(&np->gref_tx_head);
		BUG_ON((signed short)ref < 0);

		mfn = virt_to_mfn(data);
		gnttab_grant_foreign_access_ref(ref, np->xbdev->otherend_id,
						mfn, GNTMAP_readonly);

		tx->gref = np->grant_tx_ref[id] = ref;
		tx->offset = offset;
		tx->size = len;
		tx->flags = 0;
	}

	for (i = 0; i < frags; i++) {
		skb_frag_t *frag = skb_shinfo(skb)->frags + i;

		tx->flags |= NETTXF_more_data;

		id = get_id_from_freelist(np->tx_skbs);
		np->tx_skbs[id] = skb_get(skb);
		tx = RING_GET_REQUEST(&np->tx, prod++);
		tx->id = id;
		ref = gnttab_claim_grant_reference(&np->gref_tx_head);
		BUG_ON((signed short)ref < 0);

		mfn = pfn_to_mfn(page_to_pfn(frag->page));
		gnttab_grant_foreign_access_ref(ref, np->xbdev->otherend_id,
						mfn, GNTMAP_readonly);

		tx->gref = np->grant_tx_ref[id] = ref;
		tx->offset = frag->page_offset;
		tx->size = frag->size;
		tx->flags = 0;
	}

	np->tx.req_prod_pvt = prod;
}

static int network_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	unsigned short id;
	struct netfront_info *np = netdev_priv(dev);
	struct netif_tx_request *tx;
	char *data = skb->data;
	RING_IDX i;
	grant_ref_t ref;
	unsigned long mfn;
	int notify;
	int frags = skb_shinfo(skb)->nr_frags;
	unsigned int offset = offset_in_page(data);
	unsigned int len = skb_headlen(skb);

	frags += (offset + len + PAGE_SIZE - 1) / PAGE_SIZE;
	if (unlikely(frags > MAX_SKB_FRAGS + 1)) {
		printk(KERN_ALERT "xennet: skb rides the rocket: %d frags\n",
		       frags);
		dump_stack();
		goto drop;
	}

	spin_lock_irq(&np->tx_lock);

	if (unlikely(!netif_carrier_ok(dev) ||
		     (frags > 1 && !xennet_can_sg(dev)))) {
		spin_unlock_irq(&np->tx_lock);
		goto drop;
	}

	i = np->tx.req_prod_pvt;

	id = get_id_from_freelist(np->tx_skbs);
	np->tx_skbs[id] = skb;

	tx = RING_GET_REQUEST(&np->tx, i);

	tx->id   = id;
	ref = gnttab_claim_grant_reference(&np->gref_tx_head);
	BUG_ON((signed short)ref < 0);
	mfn = virt_to_mfn(data);
	gnttab_grant_foreign_access_ref(
		ref, np->xbdev->otherend_id, mfn, GNTMAP_readonly);
	tx->gref = np->grant_tx_ref[id] = ref;
	tx->offset = offset;
	tx->size = len;

	tx->flags = 0;
	if (skb->ip_summed == CHECKSUM_HW) /* local packet? */
		tx->flags |= NETTXF_csum_blank | NETTXF_data_validated;
	if (skb->proto_data_valid) /* remote but checksummed? */
		tx->flags |= NETTXF_data_validated;

	np->tx.req_prod_pvt = i + 1;

	xennet_make_frags(skb, dev, tx);
	tx->size = skb->len;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&np->tx, notify);
	if (notify)
		notify_remote_via_irq(np->irq);

	network_tx_buf_gc(dev);

	if (!netfront_tx_slot_available(np))
		netif_stop_queue(dev);

	spin_unlock_irq(&np->tx_lock);

	np->stats.tx_bytes += skb->len;
	np->stats.tx_packets++;

	return 0;

 drop:
	np->stats.tx_dropped++;
	dev_kfree_skb(skb);
	return 0;
}

static irqreturn_t netif_int(int irq, void *dev_id, struct pt_regs *ptregs)
{
	struct net_device *dev = dev_id;
	struct netfront_info *np = netdev_priv(dev);
	unsigned long flags;

	spin_lock_irqsave(&np->tx_lock, flags);
	network_tx_buf_gc(dev);
	spin_unlock_irqrestore(&np->tx_lock, flags);

	if (RING_HAS_UNCONSUMED_RESPONSES(&np->rx) &&
	    likely(netif_running(dev)))
		netif_rx_schedule(dev);

	return IRQ_HANDLED;
}


static int netif_poll(struct net_device *dev, int *pbudget)
{
	struct netfront_info *np = netdev_priv(dev);
	struct sk_buff *skb, *nskb;
	struct netif_rx_response *rx;
	RING_IDX i, rp;
	struct mmu_update *mmu = np->rx_mmu;
	struct multicall_entry *mcl = np->rx_mcl;
	int work_done, budget, more_to_do = 1;
	struct sk_buff_head rxq;
	unsigned long flags;
	unsigned long mfn;
	grant_ref_t ref;

	spin_lock(&np->rx_lock);

	if (unlikely(!netif_carrier_ok(dev))) {
		spin_unlock(&np->rx_lock);
		return 0;
	}

	skb_queue_head_init(&rxq);

	if ((budget = *pbudget) > dev->quota)
		budget = dev->quota;
	rp = np->rx.sring->rsp_prod;
	rmb(); /* Ensure we see queued responses up to 'rp'. */

	for (i = np->rx.rsp_cons, work_done = 0;
	     (i != rp) && (work_done < budget);
	     i++, work_done++) {
		rx = RING_GET_RESPONSE(&np->rx, i);

		/*
                 * This definitely indicates a bug, either in this driver or
                 * in the backend driver. In future this should flag the bad
                 * situation to the system controller to reboot the backed.
                 */
		if ((ref = np->grant_rx_ref[rx->id]) == GRANT_INVALID_REF) {
			WPRINTK("Bad rx response id %d.\n", rx->id);
			work_done--;
			continue;
		}

		/* Memory pressure, insufficient buffer headroom, ... */
		if ((mfn = gnttab_end_foreign_transfer_ref(ref)) == 0) {
			if (net_ratelimit())
				WPRINTK("Unfulfilled rx req (id=%d, st=%d).\n",
					rx->id, rx->status);
			RING_GET_REQUEST(&np->rx, np->rx.req_prod_pvt)->id =
				rx->id;
			RING_GET_REQUEST(&np->rx, np->rx.req_prod_pvt)->gref =
				ref;
			np->rx.req_prod_pvt++;
			RING_PUSH_REQUESTS(&np->rx);
			work_done--;
			continue;
		}

		gnttab_release_grant_reference(&np->gref_rx_head, ref);
		np->grant_rx_ref[rx->id] = GRANT_INVALID_REF;

		skb = np->rx_skbs[rx->id];
		add_id_to_freelist(np->rx_skbs, rx->id);

		/* NB. We handle skb overflow later. */
		skb->data = skb->head + rx->offset;
		skb->len  = rx->status;
		skb->tail = skb->data + skb->len;

		/*
		 * Old backends do not assert data_validated but we
		 * can infer it from csum_blank so test both flags.
		 */
		if (rx->flags & (NETRXF_data_validated|NETRXF_csum_blank)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb->proto_data_valid = 1;
		} else {
			skb->ip_summed = CHECKSUM_NONE;
			skb->proto_data_valid = 0;
		}
		skb->proto_csum_blank = !!(rx->flags & NETRXF_csum_blank);

		np->stats.rx_packets++;
		np->stats.rx_bytes += rx->status;

		if (!xen_feature(XENFEAT_auto_translated_physmap)) {
			/* Remap the page. */
			MULTI_update_va_mapping(mcl, (unsigned long)skb->head,
						pfn_pte_ma(mfn, PAGE_KERNEL),
						0);
			mcl++;
			mmu->ptr = ((maddr_t)mfn << PAGE_SHIFT)
				| MMU_MACHPHYS_UPDATE;
			mmu->val = __pa(skb->head) >> PAGE_SHIFT;
			mmu++;

			set_phys_to_machine(__pa(skb->head) >> PAGE_SHIFT,
					    mfn);
		}

		__skb_queue_tail(&rxq, skb);
	}

	/* Some pages are no longer absent... */
	balloon_update_driver_allowance(-work_done);

	/* Do all the remapping work, and M2P updates, in one big hypercall. */
	if (likely((mcl - np->rx_mcl) != 0)) {
		mcl->op = __HYPERVISOR_mmu_update;
		mcl->args[0] = (unsigned long)np->rx_mmu;
		mcl->args[1] = mmu - np->rx_mmu;
		mcl->args[2] = 0;
		mcl->args[3] = DOMID_SELF;
		mcl++;
		(void)HYPERVISOR_multicall(np->rx_mcl, mcl - np->rx_mcl);
	}

	while ((skb = __skb_dequeue(&rxq)) != NULL) {
		if (skb->len > (dev->mtu + ETH_HLEN + 4)) {
			if (net_ratelimit())
				printk(KERN_INFO "Received packet too big for "
				       "MTU (%d > %d)\n",
				       skb->len - ETH_HLEN - 4, dev->mtu);
			skb->len  = 0;
			skb->tail = skb->data;
			init_skb_shinfo(skb);
			dev_kfree_skb(skb);
			continue;
		}

		/*
		 * Enough room in skbuff for the data we were passed? Also,
		 * Linux expects at least 16 bytes headroom in each rx buffer.
		 */
		if (unlikely(skb->tail > skb->end) ||
		    unlikely((skb->data - skb->head) < 16)) {
			if (net_ratelimit()) {
				if (skb->tail > skb->end)
					printk(KERN_INFO "Received packet "
					       "is %zd bytes beyond tail.\n",
					       skb->tail - skb->end);
				else
					printk(KERN_INFO "Received packet "
					       "is %zd bytes before head.\n",
					       16 - (skb->data - skb->head));
			}

			nskb = __dev_alloc_skb(skb->len + 2,
					       GFP_ATOMIC|__GFP_NOWARN);
			if (nskb != NULL) {
				skb_reserve(nskb, 2);
				skb_put(nskb, skb->len);
				memcpy(nskb->data, skb->data, skb->len);
				/* Copy any other fields we already set up. */
				nskb->dev = skb->dev;
				nskb->ip_summed = skb->ip_summed;
				nskb->proto_data_valid = skb->proto_data_valid;
				nskb->proto_csum_blank = skb->proto_csum_blank;
			}

			/* Reinitialise and then destroy the old skbuff. */
			skb->len  = 0;
			skb->tail = skb->data;
			init_skb_shinfo(skb);
			dev_kfree_skb(skb);

			/* Switch old for new, if we copied the buffer. */
			if ((skb = nskb) == NULL)
				continue;
		}

		/* Set the shinfo area, which is hidden behind the data. */
		init_skb_shinfo(skb);
		/* Ethernet work: Delayed to here as it peeks the header. */
		skb->protocol = eth_type_trans(skb, dev);

		/* Pass it up. */
		netif_receive_skb(skb);
		dev->last_rx = jiffies;
	}

	np->rx.rsp_cons = i;

	/* If we get a callback with very few responses, reduce fill target. */
	/* NB. Note exponential increase, linear decrease. */
	if (((np->rx.req_prod_pvt - np->rx.sring->rsp_prod) >
	     ((3*np->rx_target) / 4)) &&
	    (--np->rx_target < np->rx_min_target))
		np->rx_target = np->rx_min_target;

	network_alloc_rx_buffers(dev);

	*pbudget   -= work_done;
	dev->quota -= work_done;

	if (work_done < budget) {
		local_irq_save(flags);

		RING_FINAL_CHECK_FOR_RESPONSES(&np->rx, more_to_do);
		if (!more_to_do)
			__netif_rx_complete(dev);

		local_irq_restore(flags);
	}

	spin_unlock(&np->rx_lock);

	return more_to_do;
}


static int network_close(struct net_device *dev)
{
	struct netfront_info *np = netdev_priv(dev);
	netif_stop_queue(np->netdev);
	return 0;
}


static struct net_device_stats *network_get_stats(struct net_device *dev)
{
	struct netfront_info *np = netdev_priv(dev);
	return &np->stats;
}

static int xennet_change_mtu(struct net_device *dev, int mtu)
{
	int max = xennet_can_sg(dev) ? 65535 - ETH_HLEN : ETH_DATA_LEN;

	if (mtu > max)
		return -EINVAL;
	dev->mtu = mtu;
	return 0;
}

static int xennet_set_sg(struct net_device *dev, u32 data)
{
	if (data) {
		struct netfront_info *np = netdev_priv(dev);
		int val;

		if (xenbus_scanf(XBT_NULL, np->xbdev->otherend, "feature-sg",
				 "%d", &val) < 0)
			val = 0;
		if (!val)
			return -ENOSYS;
	} else if (dev->mtu > ETH_DATA_LEN)
		dev->mtu = ETH_DATA_LEN;

	return ethtool_op_set_sg(dev, data);
}

static void xennet_set_features(struct net_device *dev)
{
	xennet_set_sg(dev, 1);
}

static void network_connect(struct net_device *dev)
{
	struct netfront_info *np;
	int i, requeue_idx;
	struct netif_tx_request *tx;
	struct sk_buff *skb;

	xennet_set_features(dev);

	np = netdev_priv(dev);
	spin_lock_irq(&np->tx_lock);
	spin_lock(&np->rx_lock);

	/* Recovery procedure: */

	/*
	 * Step 1: Rebuild the RX and TX ring contents.
	 * NB. We could just free the queued TX packets now but we hope
	 * that sending them out might do some good.  We have to rebuild
	 * the RX ring because some of our pages are currently flipped out
	 * so we can't just free the RX skbs.
	 * NB2. Freelist index entries are always going to be less than
	 *  PAGE_OFFSET, whereas pointers to skbs will always be equal or
	 * greater than PAGE_OFFSET: we use this property to distinguish
	 * them.
	 */

	/*
	 * Rebuild the TX buffer freelist and the TX ring itself.
	 * NB. This reorders packets.  We could keep more private state
	 * to avoid this but maybe it doesn't matter so much given the
	 * interface has been down.
	 */
	for (requeue_idx = 0, i = 1; i <= NET_TX_RING_SIZE; i++) {
		if ((unsigned long)np->tx_skbs[i] < PAGE_OFFSET)
			continue;

		skb = np->tx_skbs[i];

		tx = RING_GET_REQUEST(&np->tx, requeue_idx);
		requeue_idx++;

		tx->id = i;
		gnttab_grant_foreign_access_ref(
			np->grant_tx_ref[i], np->xbdev->otherend_id,
			virt_to_mfn(np->tx_skbs[i]->data),
			GNTMAP_readonly);
		tx->gref = np->grant_tx_ref[i];
		tx->offset = (unsigned long)skb->data & ~PAGE_MASK;
		tx->size = skb->len;
		tx->flags = 0;
		if (skb->ip_summed == CHECKSUM_HW) /* local packet? */
			tx->flags |= NETTXF_csum_blank | NETTXF_data_validated;
		if (skb->proto_data_valid) /* remote but checksummed? */
			tx->flags |= NETTXF_data_validated;

		np->stats.tx_bytes += skb->len;
		np->stats.tx_packets++;
	}

	np->tx.req_prod_pvt = requeue_idx;
	RING_PUSH_REQUESTS(&np->tx);

	/* Rebuild the RX buffer freelist and the RX ring itself. */
	for (requeue_idx = 0, i = 1; i <= NET_RX_RING_SIZE; i++) {
		if ((unsigned long)np->rx_skbs[i] < PAGE_OFFSET)
			continue;
		gnttab_grant_foreign_transfer_ref(
			np->grant_rx_ref[i], np->xbdev->otherend_id,
			__pa(np->rx_skbs[i]->data) >> PAGE_SHIFT);
		RING_GET_REQUEST(&np->rx, requeue_idx)->gref =
			np->grant_rx_ref[i];
		RING_GET_REQUEST(&np->rx, requeue_idx)->id = i;
		requeue_idx++;
	}

	np->rx.req_prod_pvt = requeue_idx;
	RING_PUSH_REQUESTS(&np->rx);

	/*
	 * Step 2: All public and private state should now be sane.  Get
	 * ready to start sending and receiving packets and give the driver
	 * domain a kick because we've probably just requeued some
	 * packets.
	 */
	netif_carrier_on(dev);
	notify_remote_via_irq(np->irq);
	network_tx_buf_gc(dev);

	spin_unlock(&np->rx_lock);
	spin_unlock_irq(&np->tx_lock);
}

static void show_device(struct netfront_info *np)
{
#ifdef DEBUG
	if (np) {
		IPRINTK("<vif handle=%u %s(%s) evtchn=%u tx=%p rx=%p>\n",
			np->handle,
			netif_carrier_ok(np->netdev) ? "on" : "off",
			netif_running(np->netdev) ? "open" : "closed",
			np->evtchn,
			np->tx,
			np->rx);
	} else
		IPRINTK("<vif NULL>\n");
#endif
}

static void netif_uninit(struct net_device *dev)
{
	struct netfront_info *np = netdev_priv(dev);
	gnttab_free_grant_references(np->gref_tx_head);
	gnttab_free_grant_references(np->gref_rx_head);
}

static struct ethtool_ops network_ethtool_ops =
{
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = ethtool_op_set_tx_csum,
	.get_sg = ethtool_op_get_sg,
	.set_sg = xennet_set_sg,
};

#ifdef CONFIG_SYSFS
static ssize_t show_rxbuf_min(struct class_device *cd, char *buf)
{
	struct net_device *netdev = container_of(cd, struct net_device,
						 class_dev);
	struct netfront_info *info = netdev_priv(netdev);

	return sprintf(buf, "%u\n", info->rx_min_target);
}

static ssize_t store_rxbuf_min(struct class_device *cd,
			       const char *buf, size_t len)
{
	struct net_device *netdev = container_of(cd, struct net_device,
						 class_dev);
	struct netfront_info *np = netdev_priv(netdev);
	char *endp;
	unsigned long target;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	target = simple_strtoul(buf, &endp, 0);
	if (endp == buf)
		return -EBADMSG;

	if (target < RX_MIN_TARGET)
		target = RX_MIN_TARGET;
	if (target > RX_MAX_TARGET)
		target = RX_MAX_TARGET;

	spin_lock(&np->rx_lock);
	if (target > np->rx_max_target)
		np->rx_max_target = target;
	np->rx_min_target = target;
	if (target > np->rx_target)
		np->rx_target = target;

	network_alloc_rx_buffers(netdev);

	spin_unlock(&np->rx_lock);
	return len;
}

static ssize_t show_rxbuf_max(struct class_device *cd, char *buf)
{
	struct net_device *netdev = container_of(cd, struct net_device,
						 class_dev);
	struct netfront_info *info = netdev_priv(netdev);

	return sprintf(buf, "%u\n", info->rx_max_target);
}

static ssize_t store_rxbuf_max(struct class_device *cd,
			       const char *buf, size_t len)
{
	struct net_device *netdev = container_of(cd, struct net_device,
						 class_dev);
	struct netfront_info *np = netdev_priv(netdev);
	char *endp;
	unsigned long target;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	target = simple_strtoul(buf, &endp, 0);
	if (endp == buf)
		return -EBADMSG;

	if (target < RX_MIN_TARGET)
		target = RX_MIN_TARGET;
	if (target > RX_MAX_TARGET)
		target = RX_MAX_TARGET;

	spin_lock(&np->rx_lock);
	if (target < np->rx_min_target)
		np->rx_min_target = target;
	np->rx_max_target = target;
	if (target < np->rx_target)
		np->rx_target = target;

	network_alloc_rx_buffers(netdev);

	spin_unlock(&np->rx_lock);
	return len;
}

static ssize_t show_rxbuf_cur(struct class_device *cd, char *buf)
{
	struct net_device *netdev = container_of(cd, struct net_device,
						 class_dev);
	struct netfront_info *info = netdev_priv(netdev);

	return sprintf(buf, "%u\n", info->rx_target);
}

static const struct class_device_attribute xennet_attrs[] = {
	__ATTR(rxbuf_min, S_IRUGO|S_IWUSR, show_rxbuf_min, store_rxbuf_min),
	__ATTR(rxbuf_max, S_IRUGO|S_IWUSR, show_rxbuf_max, store_rxbuf_max),
	__ATTR(rxbuf_cur, S_IRUGO, show_rxbuf_cur, NULL),
};

static int xennet_sysfs_addif(struct net_device *netdev)
{
	int i;
	int error = 0;

	for (i = 0; i < ARRAY_SIZE(xennet_attrs); i++) {
		error = class_device_create_file(&netdev->class_dev, 
						 &xennet_attrs[i]);
		if (error)
			goto fail;
	}
	return 0;

 fail:
	while (--i >= 0)
		class_device_remove_file(&netdev->class_dev,
					 &xennet_attrs[i]);
	return error;
}

static void xennet_sysfs_delif(struct net_device *netdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(xennet_attrs); i++) {
		class_device_remove_file(&netdev->class_dev,
					 &xennet_attrs[i]);
	}
}

#endif /* CONFIG_SYSFS */


/*
 * Nothing to do here. Virtual interface is point-to-point and the
 * physical interface is probably promiscuous anyway.
 */
static void network_set_multicast_list(struct net_device *dev)
{
}

/** Create a network device.
 * @param handle device handle
 * @param val return parameter for created device
 * @return 0 on success, error code otherwise
 */
static struct net_device * __devinit create_netdev(int handle,
						   struct xenbus_device *dev)
{
	int i, err = 0;
	struct net_device *netdev = NULL;
	struct netfront_info *np = NULL;

	netdev = alloc_etherdev(sizeof(struct netfront_info));
	if (!netdev) {
		printk(KERN_WARNING "%s> alloc_etherdev failed.\n",
		       __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	np                = netdev_priv(netdev);
	np->handle        = handle;
	np->xbdev         = dev;

	netif_carrier_off(netdev);

	spin_lock_init(&np->tx_lock);
	spin_lock_init(&np->rx_lock);

	skb_queue_head_init(&np->rx_batch);
	np->rx_target     = RX_DFL_MIN_TARGET;
	np->rx_min_target = RX_DFL_MIN_TARGET;
	np->rx_max_target = RX_MAX_TARGET;

	init_timer(&np->rx_refill_timer);
	np->rx_refill_timer.data = (unsigned long)netdev;
	np->rx_refill_timer.function = rx_refill_timeout;

	/* Initialise {tx,rx}_skbs as a free chain containing every entry. */
	for (i = 0; i <= NET_TX_RING_SIZE; i++) {
		np->tx_skbs[i] = (void *)((unsigned long) i+1);
		np->grant_tx_ref[i] = GRANT_INVALID_REF;
	}

	for (i = 0; i <= NET_RX_RING_SIZE; i++) {
		np->rx_skbs[i] = (void *)((unsigned long) i+1);
		np->grant_rx_ref[i] = GRANT_INVALID_REF;
	}

	/* A grant for every tx ring slot */
	if (gnttab_alloc_grant_references(TX_MAX_TARGET,
					  &np->gref_tx_head) < 0) {
		printk(KERN_ALERT "#### netfront can't alloc tx grant refs\n");
		err = -ENOMEM;
		goto exit;
	}
	/* A grant for every rx ring slot */
	if (gnttab_alloc_grant_references(RX_MAX_TARGET,
					  &np->gref_rx_head) < 0) {
		printk(KERN_ALERT "#### netfront can't alloc rx grant refs\n");
		gnttab_free_grant_references(np->gref_tx_head);
		err = -ENOMEM;
		goto exit_free_tx;
	}

	netdev->open            = network_open;
	netdev->hard_start_xmit = network_start_xmit;
	netdev->stop            = network_close;
	netdev->get_stats       = network_get_stats;
	netdev->poll            = netif_poll;
	netdev->set_multicast_list = network_set_multicast_list;
	netdev->uninit          = netif_uninit;
	netdev->change_mtu	= xennet_change_mtu;
	netdev->weight          = 64;
	netdev->features        = NETIF_F_IP_CSUM;

	SET_ETHTOOL_OPS(netdev, &network_ethtool_ops);
	SET_MODULE_OWNER(netdev);
	SET_NETDEV_DEV(netdev, &dev->dev);

	err = register_netdev(netdev);
	if (err) {
		printk(KERN_WARNING "%s> register_netdev err=%d\n",
		       __FUNCTION__, err);
		goto exit_free_rx;
	}

	err = xennet_sysfs_addif(netdev);
	if (err) {
		/* This can be non-fatal: it only means no tuning parameters */
		printk(KERN_WARNING "%s> add sysfs failed err=%d\n",
		       __FUNCTION__, err);
	}

	np->netdev = netdev;

	return netdev;


 exit_free_rx:
	gnttab_free_grant_references(np->gref_rx_head);
 exit_free_tx:
	gnttab_free_grant_references(np->gref_tx_head);
 exit:
	free_netdev(netdev);
	return ERR_PTR(err);
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


/* ** Close down ** */


/**
 * Handle the change of state of the backend to Closing.  We must delete our
 * device-layer structures now, to ensure that writes are flushed through to
 * the backend.  Once is this done, we can switch to Closed in
 * acknowledgement.
 */
static void netfront_closing(struct xenbus_device *dev)
{
	struct netfront_info *info = dev->data;

	DPRINTK("netfront_closing: %s removed\n", dev->nodename);

	close_netdev(info);

	xenbus_switch_state(dev, XenbusStateClosed);
}


static int __devexit netfront_remove(struct xenbus_device *dev)
{
	struct netfront_info *info = dev->data;

	DPRINTK("%s\n", dev->nodename);

	netif_disconnect_backend(info);
	free_netdev(info->netdev);

	return 0;
}


static void close_netdev(struct netfront_info *info)
{
	del_timer_sync(&info->rx_refill_timer);

	xennet_sysfs_delif(info->netdev);
	unregister_netdev(info->netdev);
}


static void netif_disconnect_backend(struct netfront_info *info)
{
	/* Stop old i/f to prevent errors whilst we rebuild the state. */
	spin_lock_irq(&info->tx_lock);
	spin_lock(&info->rx_lock);
	netif_carrier_off(info->netdev);
	spin_unlock(&info->rx_lock);
	spin_unlock_irq(&info->tx_lock);

	if (info->irq)
		unbind_from_irqhandler(info->irq, info->netdev);
	info->evtchn = info->irq = 0;

	end_access(info->tx_ring_ref, info->tx.sring);
	end_access(info->rx_ring_ref, info->rx.sring);
	info->tx_ring_ref = GRANT_INVALID_REF;
	info->rx_ring_ref = GRANT_INVALID_REF;
	info->tx.sring = NULL;
	info->rx.sring = NULL;
}


static void netif_free(struct netfront_info *info)
{
	close_netdev(info);
	netif_disconnect_backend(info);
	free_netdev(info->netdev);
}


static void end_access(int ref, void *page)
{
	if (ref != GRANT_INVALID_REF)
		gnttab_end_foreign_access(ref, 0, (unsigned long)page);
}


/* ** Driver registration ** */


static struct xenbus_device_id netfront_ids[] = {
	{ "vif" },
	{ "" }
};


static struct xenbus_driver netfront = {
	.name = "vif",
	.owner = THIS_MODULE,
	.ids = netfront_ids,
	.probe = netfront_probe,
	.remove = __devexit_p(netfront_remove),
	.resume = netfront_resume,
	.otherend_changed = backend_changed,
};


static struct notifier_block notifier_inetdev = {
	.notifier_call  = inetdev_notify,
	.next           = NULL,
	.priority       = 0
};

static int __init netif_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	if (xen_start_info->flags & SIF_INITDOMAIN)
		return 0;

	IPRINTK("Initialising virtual ethernet driver.\n");

	(void)register_inetaddr_notifier(&notifier_inetdev);

	return xenbus_register_frontend(&netfront);
}
module_init(netif_init);


static void __exit netif_exit(void)
{
	unregister_inetaddr_notifier(&notifier_inetdev);

	return xenbus_unregister_driver(&netfront);
}
module_exit(netif_exit);

MODULE_LICENSE("Dual BSD/GPL");
