/******************************************************************************
 * netback/loopback.c
 * 
 * A two-interface loopback device to emulate a local netfront-netback
 * connection. This ensures that local packet delivery looks identical
 * to inter-domain delivery. Most importantly, packets delivered locally
 * originating from other domains will get *copied* when they traverse this
 * driver. This prevents unbounded delays in socket-buffer queues from
 * causing the netback driver to "seize up".
 * 
 * This driver creates a symmetric pair of loopback interfaces with names
 * vif0.0 and veth0. The intention is that 'vif0.0' is bound to an Ethernet
 * bridge, just like a proper netback interface, while a local IP interface
 * is configured on 'veth0'.
 * 
 * As with a real netback interface, vif0.0 is configured with a suitable
 * dummy MAC address. No default is provided for veth0: a reasonable strategy
 * is to transfer eth0's MAC address to veth0, and give eth0 a dummy address
 * (to avoid confusing the Etherbridge).
 * 
 * Copyright (c) 2005 K A Fraser
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
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/dst.h>

static int nloopbacks = 8;
module_param(nloopbacks, int, 0);
MODULE_PARM_DESC(nloopbacks, "Number of netback-loopback devices to create");

struct net_private {
	struct net_device *loopback_dev;
	struct net_device_stats stats;
};

static int loopback_open(struct net_device *dev)
{
	struct net_private *np = netdev_priv(dev);
	memset(&np->stats, 0, sizeof(np->stats));
	netif_start_queue(dev);
	return 0;
}

static int loopback_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static int loopback_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_private *np = netdev_priv(dev);

	dst_release(skb->dst);
	skb->dst = NULL;

	skb_orphan(skb);

	np->stats.tx_bytes += skb->len;
	np->stats.tx_packets++;

	/* Switch to loopback context. */
	dev = np->loopback_dev;
	np  = netdev_priv(dev);

	np->stats.rx_bytes += skb->len;
	np->stats.rx_packets++;

	if (skb->ip_summed == CHECKSUM_HW) {
		/* Defer checksum calculation. */
		skb->proto_csum_blank = 1;
		/* Must be a local packet: assert its integrity. */
		skb->proto_data_valid = 1;
	}

	skb->ip_summed = skb->proto_data_valid ?
		CHECKSUM_UNNECESSARY : CHECKSUM_NONE;

	skb->pkt_type = PACKET_HOST; /* overridden by eth_type_trans() */
	skb->protocol = eth_type_trans(skb, dev);
	skb->dev      = dev;
	dev->last_rx  = jiffies;
	netif_rx(skb);

	return 0;
}

static struct net_device_stats *loopback_get_stats(struct net_device *dev)
{
	struct net_private *np = netdev_priv(dev);
	return &np->stats;
}

static struct ethtool_ops network_ethtool_ops =
{
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = ethtool_op_set_tx_csum,
};

static void loopback_construct(struct net_device *dev, struct net_device *lo)
{
	struct net_private *np = netdev_priv(dev);

	np->loopback_dev     = lo;

	dev->open            = loopback_open;
	dev->stop            = loopback_close;
	dev->hard_start_xmit = loopback_start_xmit;
	dev->get_stats       = loopback_get_stats;

	dev->tx_queue_len    = 0;

	dev->features        = (NETIF_F_HIGHDMA |
				NETIF_F_LLTX |
				NETIF_F_IP_CSUM);

	SET_ETHTOOL_OPS(dev, &network_ethtool_ops);

	/*
	 * We do not set a jumbo MTU on the interface. Otherwise the network
	 * stack will try to send large packets that will get dropped by the
	 * Ethernet bridge (unless the physical Ethernet interface is
	 * configured to transfer jumbo packets). If a larger MTU is desired
	 * then the system administrator can specify it using the 'ifconfig'
	 * command.
	 */
	/*dev->mtu             = 16*1024;*/
}

static int __init make_loopback(int i)
{
	struct net_device *dev1, *dev2;
	char dev_name[IFNAMSIZ];
	int err = -ENOMEM;

	sprintf(dev_name, "vif0.%d", i);
	dev1 = alloc_netdev(sizeof(struct net_private), dev_name, ether_setup);
	if (!dev1)
		return err;

	sprintf(dev_name, "veth%d", i);
	dev2 = alloc_netdev(sizeof(struct net_private), dev_name, ether_setup);
	if (!dev2)
		goto fail_netdev2;

	loopback_construct(dev1, dev2);
	loopback_construct(dev2, dev1);

	/*
	 * Initialise a dummy MAC address for the 'dummy backend' interface. We
	 * choose the numerically largest non-broadcast address to prevent the
	 * address getting stolen by an Ethernet bridge for STP purposes.
	 */
	memset(dev1->dev_addr, 0xFF, ETH_ALEN);
	dev1->dev_addr[0] &= ~0x01;

	if ((err = register_netdev(dev1)) != 0)
		goto fail;

	if ((err = register_netdev(dev2)) != 0) {
		unregister_netdev(dev1);
		goto fail;
	}

	return 0;

 fail:
	free_netdev(dev2);
 fail_netdev2:
	free_netdev(dev1);
	return err;
}

static void __init clean_loopback(int i)
{
	struct net_device *dev1, *dev2;
	char dev_name[IFNAMSIZ];

	sprintf(dev_name, "vif0.%d", i);
	dev1 = dev_get_by_name(dev_name);
	sprintf(dev_name, "veth%d", i);
	dev2 = dev_get_by_name(dev_name);
	if (dev1 && dev2) {
		unregister_netdev(dev2);
		unregister_netdev(dev1);
		free_netdev(dev2);
		free_netdev(dev1);
	}
}

static int __init loopback_init(void)
{
	int i, err = 0;

	for (i = 0; i < nloopbacks; i++)
		if ((err = make_loopback(i)) != 0)
			break;

	return err;
}

module_init(loopback_init);

static void __exit loopback_exit(void)
{
	int i;

	for (i = nloopbacks; i-- > 0; )
		clean_loopback(i);
}

module_exit(loopback_exit);

MODULE_LICENSE("Dual BSD/GPL");

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
