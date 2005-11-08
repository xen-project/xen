/******************************************************************************
 * arch/xen/drivers/netif/backend/interface.c
 * 
 * Network-device interface management.
 * 
 * Copyright (c) 2004-2005, Keir Fraser
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

	op.host_addr = (unsigned long)netif->comms_area->addr;
	op.flags     = GNTMAP_host_map;
	op.ref       = tx_ring_ref;
	op.dom       = netif->domid;
    
	lock_vm_area(netif->comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
	unlock_vm_area(netif->comms_area);
	BUG_ON(ret);

	if (op.handle < 0) { 
		DPRINTK(" Gnttab failure mapping tx_ring_ref!\n");
		return op.handle;
	}

	netif->tx_shmem_ref    = tx_ring_ref;
	netif->tx_shmem_handle = op.handle;

	op.host_addr = (unsigned long)netif->comms_area->addr + PAGE_SIZE;
	op.flags     = GNTMAP_host_map;
	op.ref       = rx_ring_ref;
	op.dom       = netif->domid;

	lock_vm_area(netif->comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
	unlock_vm_area(netif->comms_area);
	BUG_ON(ret);

	if (op.handle < 0) { 
		DPRINTK(" Gnttab failure mapping rx_ring_ref!\n");
		return op.handle;
	}

	netif->rx_shmem_ref    = rx_ring_ref;
	netif->rx_shmem_handle = op.handle;

	return 0;
}

static void unmap_frontend_pages(netif_t *netif)
{
	struct gnttab_unmap_grant_ref op;
	int ret;

	op.host_addr    = (unsigned long)netif->comms_area->addr;
	op.handle       = netif->tx_shmem_handle;
	op.dev_bus_addr = 0;

	lock_vm_area(netif->comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
	unlock_vm_area(netif->comms_area);
	BUG_ON(ret);

	op.host_addr    = (unsigned long)netif->comms_area->addr + PAGE_SIZE;
	op.handle       = netif->rx_shmem_handle;
	op.dev_bus_addr = 0;

	lock_vm_area(netif->comms_area);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
	unlock_vm_area(netif->comms_area);
	BUG_ON(ret);
}

int netif_map(netif_t *netif, unsigned long tx_ring_ref,
	      unsigned long rx_ring_ref, unsigned int evtchn)
{
	int err;
	evtchn_op_t op = {
		.cmd = EVTCHNOP_bind_interdomain,
		.u.bind_interdomain.remote_dom = netif->domid,
		.u.bind_interdomain.remote_port = evtchn };

	/* Already connected through? */
	if (netif->irq)
		return 0;

	netif->comms_area = alloc_vm_area(2*PAGE_SIZE);
	if (netif->comms_area == NULL)
		return -ENOMEM;

	err = map_frontend_pages(netif, tx_ring_ref, rx_ring_ref);
	if (err) {
		free_vm_area(netif->comms_area);
		return err;
	}

	err = HYPERVISOR_event_channel_op(&op);
	if (err) {
		unmap_frontend_pages(netif);
		free_vm_area(netif->comms_area);
		return err;
	}

	netif->evtchn = op.u.bind_interdomain.local_port;

	netif->irq = bind_evtchn_to_irqhandler(
		netif->evtchn, netif_be_int, 0, netif->dev->name, netif);
	disable_irq(netif->irq);

	netif->tx = (netif_tx_interface_t *)netif->comms_area->addr;
	netif->rx = (netif_rx_interface_t *)
		((char *)netif->comms_area->addr + PAGE_SIZE);
	netif->tx->resp_prod = netif->rx->resp_prod = 0;
	netif_get(netif);
	wmb(); /* Other CPUs see new state before interface is started. */

	rtnl_lock();
	netif->status = CONNECTED;
	wmb();
	if (netif_running(netif->dev))
		__netif_up(netif);
	rtnl_unlock();

	return 0;
}

static void free_netif_callback(void *arg)
{
	netif_t *netif = (netif_t *)arg;

	/* Already disconnected? */
	if (!netif->irq)
		return;

	unbind_from_irqhandler(netif->irq, netif);
	netif->irq = 0;

	unregister_netdev(netif->dev);

	if (netif->tx) {
		unmap_frontend_pages(netif);
		free_vm_area(netif->comms_area);
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

int netif_disconnect(netif_t *netif)
{

	if (netif->status == CONNECTED) {
		rtnl_lock();
		netif->status = DISCONNECTING;
		wmb();
		if (netif_running(netif->dev))
			__netif_down(netif);
		rtnl_unlock();
		netif_put(netif);
		return 0; /* Caller should not send response message. */
	}

	return 1;
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
