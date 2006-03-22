/******************************************************************************
 * arch/xen/drivers/netif/backend/interface.c
 * 
 * Network-device interface management.
 * 
 * Copyright (c) 2004-2005, Keir Fraser
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

#include "common.h"
#include <linux/rtnetlink.h>

static void __netif_up(netif_t *netif)
{
	struct net_device *dev = netif->dev;
	spin_lock_bh(&dev->xmit_lock);
	netif->active = 1;
	spin_unlock_bh(&dev->xmit_lock);
	enable_irq(netif->irq);
	netif_schedule_work(netif);
}

static void __netif_down(netif_t *netif)
{
	struct net_device *dev = netif->dev;
	disable_irq(netif->irq);
	spin_lock_bh(&dev->xmit_lock);
	netif->active = 0;
	spin_unlock_bh(&dev->xmit_lock);
	netif_deschedule_work(netif);
}

static int net_open(struct net_device *dev)
{
	netif_t *netif = netdev_priv(dev);
	if (netif->status == CONNECTED)
		__netif_up(netif);
	netif_start_queue(dev);
	return 0;
}

static int net_close(struct net_device *dev)
{
	netif_t *netif = netdev_priv(dev);
	netif_stop_queue(dev);
	if (netif->status == CONNECTED)
		__netif_down(netif);
	return 0;
}

netif_t *alloc_netif(domid_t domid, unsigned int handle, u8 be_mac[ETH_ALEN])
{
	int err = 0, i;
	struct net_device *dev;
	netif_t *netif;
	char name[IFNAMSIZ] = {};

	snprintf(name, IFNAMSIZ - 1, "vif%u.%u", domid, handle);
	dev = alloc_netdev(sizeof(netif_t), name, ether_setup);
	if (dev == NULL) {
		DPRINTK("Could not create netif: out of memory\n");
		return ERR_PTR(-ENOMEM);
	}

	netif = netdev_priv(dev);
	memset(netif, 0, sizeof(*netif));
	netif->domid  = domid;
	netif->handle = handle;
	netif->status = DISCONNECTED;
	atomic_set(&netif->refcnt, 0);
	netif->dev = dev;

	netif->credit_bytes = netif->remaining_credit = ~0UL;
	netif->credit_usec  = 0UL;
	init_timer(&netif->credit_timeout);

	dev->hard_start_xmit = netif_be_start_xmit;
	dev->get_stats       = netif_be_get_stats;
	dev->open            = net_open;
	dev->stop            = net_close;
	dev->features        = NETIF_F_NO_CSUM;

	/* Disable queuing. */
	dev->tx_queue_len = 0;

	for (i = 0; i < ETH_ALEN; i++)
		if (be_mac[i] != 0)
			break;
	if (i == ETH_ALEN) {
		/*
		 * Initialise a dummy MAC address. We choose the numerically
		 * largest non-broadcast address to prevent the address getting
		 * stolen by an Ethernet bridge for STP purposes.
                 * (FE:FF:FF:FF:FF:FF) 
		 */ 
		memset(dev->dev_addr, 0xFF, ETH_ALEN);
		dev->dev_addr[0] &= ~0x01;
	} else
		memcpy(dev->dev_addr, be_mac, ETH_ALEN);

	rtnl_lock();
	err = register_netdevice(dev);
	rtnl_unlock();
	if (err) {
		DPRINTK("Could not register new net device %s: err=%d\n",
			dev->name, err);
		free_netdev(dev);
		return ERR_PTR(err);
	}

	DPRINTK("Successfully created netif\n");
	return netif;
}

static int map_frontend_pages(
	netif_t *netif, grant_ref_t tx_ring_ref, grant_ref_t rx_ring_ref)
{
	struct gnttab_map_grant_ref op;
	int ret;

	op.host_addr = (unsigned long)netif->tx_comms_area->addr;
	op.flags     = GNTMAP_host_map;
	op.ref       = tx_ring_ref;
	op.dom       = netif->domid;
    
	lock_vm_area(netif->tx_comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
	unlock_vm_area(netif->tx_comms_area);
	BUG_ON(ret);

	if (op.status) { 
		DPRINTK(" Gnttab failure mapping tx_ring_ref!\n");
		return op.status;
	}

	netif->tx_shmem_ref    = tx_ring_ref;
	netif->tx_shmem_handle = op.handle;

	op.host_addr = (unsigned long)netif->rx_comms_area->addr;
	op.flags     = GNTMAP_host_map;
	op.ref       = rx_ring_ref;
	op.dom       = netif->domid;

	lock_vm_area(netif->rx_comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
	unlock_vm_area(netif->rx_comms_area);
	BUG_ON(ret);

	if (op.status) {
		DPRINTK(" Gnttab failure mapping rx_ring_ref!\n");
		return op.status;
	}

	netif->rx_shmem_ref    = rx_ring_ref;
	netif->rx_shmem_handle = op.handle;

	return 0;
}

static void unmap_frontend_pages(netif_t *netif)
{
	struct gnttab_unmap_grant_ref op;
	int ret;

	op.host_addr    = (unsigned long)netif->tx_comms_area->addr;
	op.handle       = netif->tx_shmem_handle;
	op.dev_bus_addr = 0;

	lock_vm_area(netif->tx_comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
	unlock_vm_area(netif->tx_comms_area);
	BUG_ON(ret);

	op.host_addr    = (unsigned long)netif->rx_comms_area->addr;
	op.handle       = netif->rx_shmem_handle;
	op.dev_bus_addr = 0;

	lock_vm_area(netif->rx_comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
	unlock_vm_area(netif->rx_comms_area);
	BUG_ON(ret);
}

int netif_map(netif_t *netif, unsigned long tx_ring_ref,
	      unsigned long rx_ring_ref, unsigned int evtchn)
{
	int err = -ENOMEM;
	netif_tx_sring_t *txs;
	netif_rx_sring_t *rxs;
	evtchn_op_t op = {
		.cmd = EVTCHNOP_bind_interdomain,
		.u.bind_interdomain.remote_dom = netif->domid,
		.u.bind_interdomain.remote_port = evtchn };

	/* Already connected through? */
	if (netif->irq)
		return 0;

	netif->tx_comms_area = alloc_vm_area(PAGE_SIZE);
	if (netif->tx_comms_area == NULL)
		return -ENOMEM;
	netif->rx_comms_area = alloc_vm_area(PAGE_SIZE);
	if (netif->rx_comms_area == NULL)
		goto err_rx;

	err = map_frontend_pages(netif, tx_ring_ref, rx_ring_ref);
	if (err)
		goto err_map;

	err = HYPERVISOR_event_channel_op(&op);
	if (err)
		goto err_hypervisor;

	netif->evtchn = op.u.bind_interdomain.local_port;

	netif->irq = bind_evtchn_to_irqhandler(
		netif->evtchn, netif_be_int, 0, netif->dev->name, netif);
	disable_irq(netif->irq);

	txs = (netif_tx_sring_t *)netif->tx_comms_area->addr;
	BACK_RING_INIT(&netif->tx, txs, PAGE_SIZE);

	rxs = (netif_rx_sring_t *)
		((char *)netif->rx_comms_area->addr);
	BACK_RING_INIT(&netif->rx, rxs, PAGE_SIZE);

	netif->rx_req_cons_peek = 0;

	netif_get(netif);
	wmb(); /* Other CPUs see new state before interface is started. */

	rtnl_lock();
	netif->status = CONNECTED;
	wmb();
	if (netif_running(netif->dev))
		__netif_up(netif);
	rtnl_unlock();

	return 0;
err_hypervisor:
	unmap_frontend_pages(netif);
err_map:
	free_vm_area(netif->rx_comms_area);
err_rx:
	free_vm_area(netif->tx_comms_area);
	return err;
}

static void free_netif_callback(void *arg)
{
	netif_t *netif = (netif_t *)arg;

	if (netif->irq)
		unbind_from_irqhandler(netif->irq, netif);
	
	unregister_netdev(netif->dev);

	if (netif->tx.sring) {
		unmap_frontend_pages(netif);
		free_vm_area(netif->tx_comms_area);
		free_vm_area(netif->rx_comms_area);
	}

	free_netdev(netif->dev);
}

void free_netif(netif_t *netif)
{
	INIT_WORK(&netif->free_work, free_netif_callback, (void *)netif);
	schedule_work(&netif->free_work);
}

void netif_creditlimit(netif_t *netif)
{
#if 0
	/* Set the credit limit (reset remaining credit to new limit). */
	netif->credit_bytes     = creditlimit->credit_bytes;
	netif->remaining_credit = creditlimit->credit_bytes;
	netif->credit_usec      = creditlimit->period_usec;

	if (netif->status == CONNECTED) {
		/*
		 * Schedule work so that any packets waiting under previous
		 * credit limit are dealt with (acts as a replenishment point).
		 */
		netif->credit_timeout.expires = jiffies;
		netif_schedule_work(netif);
	}
#endif
}

void netif_disconnect(netif_t *netif)
{
	switch (netif->status) {
	case CONNECTED:
		rtnl_lock();
		netif->status = DISCONNECTING;
		wmb();
		if (netif_running(netif->dev))
			__netif_down(netif);
		rtnl_unlock();
		netif_put(netif);
		break;
	case DISCONNECTED:
		BUG_ON(atomic_read(&netif->refcnt) != 0);
		free_netif(netif);
		break;
	default:
		BUG();
	}
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
