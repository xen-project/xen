/******************************************************************************
 * dummy.c
 * 
 * A cut down version of Linux's dummy network driver. GPLed and all that.
 */

#include <xen/config.h>
#include <xen/module.h>
#include <xen/kernel.h>
#include <xen/netdevice.h>
#include <xen/init.h>

static int dummy_xmit(struct sk_buff *skb, struct net_device *dev);
static struct net_device_stats *dummy_get_stats(struct net_device *dev);

static int __init dummy_init(struct net_device *dev)
{
    dev->priv = kmalloc(sizeof(struct net_device_stats), GFP_KERNEL);
    if ( dev->priv == NULL )
        return -ENOMEM;
    memset(dev->priv, 0, sizeof(struct net_device_stats));

    dev->get_stats       = dummy_get_stats;
    dev->hard_start_xmit = dummy_xmit;

    ether_setup(dev);
    dev->flags          |= IFF_NOARP;
    dev->features        = NETIF_F_SG | NETIF_F_HIGHDMA;

    return 0;
}

static int dummy_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct net_device_stats *stats = dev->priv;

    stats->tx_packets++;
    stats->tx_bytes += skb->len;

    dev_kfree_skb(skb);

    return 0;
}

static struct net_device_stats *dummy_get_stats(struct net_device *dev)
{
    return dev->priv;
}

static struct net_device dev_dummy;

static int __init dummy_init_module(void)
{
    int err;

    dev_dummy.init = dummy_init;
    SET_MODULE_OWNER(&dev_dummy);

    if ( (err = dev_alloc_name(&dev_dummy,"dummy")) < 0 )
        return err;
    
    if ( (err = register_netdev(&dev_dummy)) < 0 )
        return err;

    return 0;
}

static void __exit dummy_cleanup_module(void)
{
    unregister_netdev(&dev_dummy);
    kfree(dev_dummy.priv);

    memset(&dev_dummy, 0, sizeof(dev_dummy));
    dev_dummy.init = dummy_init;
}

module_init(dummy_init_module);
module_exit(dummy_cleanup_module);
MODULE_LICENSE("GPL");
