/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the 
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free software Foundation, Inc.,
 * 59 Temple Place, suite 330, Boston, MA 02111-1307 USA
 *
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/ip.h>
#include <net/protocol.h>

#include <linux/if_arp.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/arcdevice.h>
#include <linux/if_bridge.h>

#include <etherip.h>
#include <vnet.h>
#include <varp.h>
#include <vif.h>
#include <vnet_dev.h>

#define MODULE_NAME "VNET"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

#define VNETIF_FMT "vnetif%u"
#define VNETBR_FMT "vnet%u"

#ifndef CONFIG_BRIDGE
#error Must configure ethernet bridging in Network Options
#endif

#include <linux/../../net/bridge/br_private.h>
#define dev_bridge(_dev) ((struct net_bridge *)(_dev)->priv)

static void vnet_dev_destructor(struct net_device *dev){
    dprintf(">\n");
    dev->open                 = NULL;
    dev->stop                 = NULL;
    dev->uninit               = NULL;
    dev->destructor           = NULL;
    dev->hard_start_xmit      = NULL;
    dev->get_stats            = NULL;
    dev->do_ioctl             = NULL;
    dev->change_mtu           = NULL;

    dev->tx_timeout           = NULL;
    dev->set_multicast_list   = NULL;
    dev->flags                = 0;

    dev->priv                 = NULL;
}

static void vnet_dev_uninit(struct net_device *dev){
    //Vnet *vnet = dev->priv;
    dprintf(">\n");
    //dev_put(dev);
    dprintf("<\n");
}

static struct net_device_stats *vnet_dev_get_stats(struct net_device *dev){
    Vnet *vnet = dev->priv;
    //dprintf(">\n");
    return &vnet->stats;
}

static int vnet_dev_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd){
    int err = 0;
    
    dprintf(">\n");
    return err;
}

static int vnet_dev_change_mtu(struct net_device *dev, int mtu){
    int err = 0;
    Vnet *vnet = dev->priv;
    if (mtu < 68 || mtu > 1500 - vnet->header_n){
        err = -EINVAL;
        goto exit;
    }
    dev->mtu = mtu;
  exit:
    return err;
}

static int vnet_dev_set_name(struct net_device *dev){
    int err = 0;
    Vnet *vnet = (void*)dev->priv;

    dprintf(">\n");
    dprintf("> vnet=%d\n", vnet->vnet);
    snprintf(dev->name, IFNAMSIZ - 1, VNETIF_FMT, vnet->vnet);
    if(__dev_get_by_name(dev->name)){
        err = -ENOMEM;
    }
    dprintf("< err=%d\n", err);
    return err;
}

//============================================================================
#ifdef CONFIG_VNET_BRIDGE

#define BRIDGE DEVICE

void vnet_bridge_fini(Vnet *vnet){
    if(!vnet) return;
    if(vnet->bridge){
        br_del_bridge(vnet->bridge->name);
        vnet->bridge = NULL;
    }
}

/** Create the bridge for a vnet, and add the
 * vnet interface to it.
 *
 * @param vnet vnet
 * @return 0 on success, error code otherwise
 */
int vnet_bridge_init(Vnet *vnet){
    int err = 0;
    char bridge[IFNAMSIZ] = {};
    struct net_bridge *br;
    vnet->bridge = NULL;
    snprintf(bridge, IFNAMSIZ - 1, VNETBR_FMT, vnet->vnet);
    rtnl_lock();
    err = br_add_bridge(bridge);
    rtnl_unlock();
    if(err){
        dprintf("> Error creating vnet bridge %s: err=%d\n", bridge, err);
        goto exit;
    }
    vnet->bridge = __dev_get_by_name(bridge);
    if(!vnet->bridge){
        wprintf("> Vnet bridge %s is null!\n", bridge);
        err = -EINVAL;
        goto exit;
    }
    br = dev_bridge(vnet->bridge);
    br->stp_enabled = 0;
    br->bridge_hello_time = 0;
    br->hello_time = 0;
    br->bridge_forward_delay = 0;
    br->forward_delay = 0;
    rtnl_lock();
    err = br_add_if(br, vnet->dev);
    rtnl_unlock();
    if(err){
        dprintf("> Error adding vif %s to vnet bridge %s: err=%d\n",
                vnet->dev->name, bridge, err);
        goto exit;
    }
    rtnl_lock();
    dev_open(vnet->dev);
    dev_open(vnet->bridge);
    rtnl_unlock();
  exit:
    if(err){
        if(vnet->bridge){
            rtnl_lock();
            br_del_bridge(bridge);
            rtnl_unlock();
            vnet->bridge = NULL;
        }
    }
    return err;
}


/** Add an interface to the bridge for a vnet.
 *
 * @param vnet vnet
 * @param dev interface
 * @return 0 on success, error code otherwise
 */
int vnet_add_if(Vnet *vnet, struct net_device *dev){
    int err = 0;
    struct net_device *brdev;

    dprintf(">\n");
    if(!vnet->bridge){
        err = -EINVAL;
        goto exit;
    }
    // Delete the interface from the default bridge.
    // todo: Really want to delete it from any bridge it's in.
    if(!vnet_get_device(BRIDGE, &brdev)){
        rtnl_lock();
        br_del_if(dev_bridge(brdev), dev);
        rtnl_unlock();
    }
    dprintf("> br_add_if %s %s\n", vnet->bridge->name, dev->name);
    rtnl_lock();
    dev_open(dev);
    dev_open(vnet->bridge);
    err = br_add_if(dev_bridge(vnet->bridge), dev);
    rtnl_unlock();
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

int vnet_del_if(Vnet *vnet, struct net_device *dev){
    int err = 0;

    dprintf(">\n");
    if(!vnet->bridge){
        err = -EINVAL;
        goto exit;
    }
    rtnl_lock();
    br_del_if(dev_bridge(vnet->bridge), dev);
    rtnl_unlock();
  exit:
    dprintf("< err=%d\n", err);
    return err;
}
    

/** Create the bridge and virtual interface for a vnet.
 *
 * @param info vnet
 * @return 0 on success, error code otherwise
 */
int Vnet_create(Vnet *info){
    int err = 0;

    dprintf("> %u\n", info->vnet);
    err = vnet_dev_add(info);
    if(err) goto exit;
    dprintf("> vnet_bridge_init\n");
    err = vnet_bridge_init(info);
    if(err) goto exit;
    dprintf("> Vnet_add...\n");
    err = Vnet_add(info);
  exit:
    if(err){
        dprintf("> vnet_bridge_fini...\n");
        vnet_bridge_fini(info);
    }
    dprintf("< err=%d\n", err);
    return err;
}
    


/** Remove the net device for a vnet.
 * Clears the dev field of the vnet.
 * Safe to call if the vnet or its dev are null.
 *
 * @param vnet vnet
 */
void vnet_dev_remove(Vnet *vnet){
    if(!vnet) return;
    dprintf("> vnet=%u\n", vnet->vnet);
    if(vnet->bridge){
        dprintf("> br_del_bridge(%s)\n", vnet->bridge->name);
        rtnl_lock();
        br_del_bridge(vnet->bridge->name);
        rtnl_unlock();
        vnet->bridge = NULL;
    }
    if(vnet->dev){
        //dev_put(vnet->dev);
        dprintf("> unregister_netdev(%s)\n", vnet->dev->name);
        unregister_netdev(vnet->dev);
        vnet->dev = NULL;
    }
    dprintf("<\n");
}

//============================================================================
#else
//============================================================================

/** Create the virtual interface for a vnet.
 *
 * @param info vnet
 * @return 0 on success, error code otherwise
 */
int Vnet_create(Vnet *info){
    int err = 0;

    dprintf("> %u\n", info->vnet);
    err = vnet_dev_add(info);
    if(err) goto exit;
    dprintf("> Vnet_add...\n");
    err = Vnet_add(info);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}
    
int vnet_add_if(Vnet *vnet, struct net_device *dev){
    int err = -ENOSYS;
    return err;
}


int vnet_del_if(Vnet *vnet, struct net_device *dev){
    int err = 0;
    return err;
}

/** Remove the net device for a vnet.
 * Clears the dev field of the vnet.
 * Safe to call if the vnet or its dev are null.
 *
 * @param vnet vnet
 */
void vnet_dev_remove(Vnet *vnet){
    if(!vnet) return;
    dprintf("> vnet=%u\n", vnet->vnet);
    if(vnet->dev){
        //dev_put(vnet->dev);
        dprintf("> unregister_netdev(%s)\n", vnet->dev->name);
        unregister_netdev(vnet->dev);
        vnet->dev = NULL;
    }
    dprintf("<\n");
}
#endif
//============================================================================

static int vnet_dev_open(struct net_device *dev){
    int err = 0;
    dprintf(">\n");
    netif_start_queue(dev);
    dprintf("<\n");
    return err;
}

static int vnet_dev_stop(struct net_device *dev){
    int err = 0;
    dprintf(">\n");
    netif_stop_queue(dev);
    dprintf("<\n");
    return err;
}

static int vnet_dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev){
    int err = 0;
    Vnet *vnet = dev->priv;

    dprintf("> skb=%p\n", skb);
    if(vnet->recursion++) {
        vnet->stats.collisions++;
	vnet->stats.tx_errors++;
        wprintf("> recursion!\n");
	dev_kfree_skb(skb);
        goto exit;
    }
    if(!skb){
        err = -EINVAL;
        wprintf("> skb NULL!\n");
        goto exit;
    }
    dprintf("> skb->data=%p skb->mac.raw=%p\n", skb->data, skb->mac.raw);
    if(skb->mac.raw < skb->data || skb->mac.raw > skb->nh.raw){
        wprintf("> skb mac duff!\n");
        skb->mac.raw = skb->data;
    }
    //dev->trans_start = jiffies;
    err = vnet_skb_send(skb, vnet->vnet);
    if(err < 0){
        vnet->stats.tx_errors++;
    } else {
        vnet->stats.tx_packets++;
        vnet->stats.tx_bytes += skb->len;
    }
  exit:
    vnet->recursion--;
    dprintf("<\n");
    return 0;
}

void vnet_dev_tx_timeout(struct net_device *dev){
    dprintf(">\n");
    //dev->trans_start = jiffies;
    //netif_wake_queue(dev);
}

void vnet_dev_set_multicast_list(struct net_device *dev){
    dprintf(">\n");
}

static int (*eth_hard_header)(struct sk_buff *skb,
                              struct net_device *dev, unsigned short type,
                              void *daddr, void *saddr, unsigned len) = NULL;

static int vnet_dev_hard_header(struct sk_buff *skb,
                                struct net_device *dev, unsigned short type,
                                void *daddr, void *saddr, unsigned len){
    int err = 0;
    dprintf("> skb=%p ethhdr=%p dev=%s len=%u\n",
            skb, skb->mac.raw, dev->name, len);
    if(saddr){
        dprintf("> saddr=" MACFMT "\n", MAC6TUPLE((unsigned char*)saddr));
    } else {
        dprintf("> saddr=NULL\n");
    }
    if(daddr){
        dprintf("> daddr=" MACFMT "\n", MAC6TUPLE((unsigned char*)daddr));
    } else {
        dprintf("> daddr=NULL\n");
    }
    err = eth_hard_header(skb, dev, type, daddr, saddr, len);
    dprintf("> eth_hard_header=%d\n", err);
    skb->mac.raw = skb->data;
    dprintf("> src=" MACFMT " dst=" MACFMT "\n",
            MAC6TUPLE(skb->mac.ethernet->h_source),
            MAC6TUPLE(skb->mac.ethernet->h_dest));
    dprintf("< err=%d\n", err);
    return err;
}

void vnet_dev_mac(unsigned char *mac){
    static unsigned val = 1;
    struct net_device *dev;

    if(vnet_get_device(DEVICE, &dev)){
        mac[0] = 0xAA;
        mac[1] = 0xFF;
        mac[2] = (unsigned char)((val >> 24) & 0xff);
        mac[3] = (unsigned char)((val >> 16) & 0xff);
        mac[4] = (unsigned char)((val >>  8) & 0xff);
        mac[5] = (unsigned char)((val      ) & 0xff);
        val++;
    } else {
        memcpy(mac, dev->dev_addr, ETH_ALEN);
        dev_put(dev);
    }
}

static int vnet_dev_init(struct net_device *dev){
    int err = 0;
    Vnet *vnet = (void*)dev->priv;
 
    dprintf(">\n");
    ether_setup(dev);

    if(!eth_hard_header) eth_hard_header = dev->hard_header;
    dev->hard_header          = vnet_dev_hard_header;

    dev->open                 = vnet_dev_open;
    dev->stop                 = vnet_dev_stop;
    dev->uninit               = vnet_dev_uninit;
    dev->destructor           = vnet_dev_destructor;
    dev->hard_start_xmit      = vnet_dev_hard_start_xmit;
    dev->get_stats            = vnet_dev_get_stats;
    dev->do_ioctl             = vnet_dev_do_ioctl;
    dev->change_mtu           = vnet_dev_change_mtu;

    dev->tx_timeout           = vnet_dev_tx_timeout;
    dev->watchdog_timeo       = TX_TIMEOUT;
    dev->set_multicast_list   = vnet_dev_set_multicast_list;
    
    dev->hard_header_len      += vnet->header_n;
    dev->mtu                  -= vnet->header_n;

    vnet_dev_mac(dev->dev_addr);

    dev->flags |= IFF_DEBUG;
    dev->flags |= IFF_PROMISC;
    dev->flags |= IFF_ALLMULTI;

    dprintf("<\n");
    return err;
}

/** Add the interface (net device) for a vnet.
 * Sets the dev field of the vnet on success.
 * Does nothing if the vif already has an interface.
 *
 * @param vif vif
 * @return 0 on success, error code otherwise
 */
int vnet_dev_add(Vnet *vnet){
    int err = 0;
    struct net_device *dev = NULL;

    dprintf("> vnet=%p\n", vnet);
    if(vnet->dev) goto exit;
    vnet->header_n = sizeof(struct iphdr) + sizeof(struct etheriphdr);
    dev = kmalloc(sizeof(struct net_device), GFP_ATOMIC);
    if(!dev){ err = -ENOMEM; goto exit; }
    *dev = (struct net_device){};
    dev->priv = vnet;
    vnet->dev = dev;

    err = vnet_dev_set_name(dev);
    if(err) goto exit;
    vnet_dev_init(dev);
    dprintf("> name=%s, register_netdev...\n", dev->name);
    err = register_netdev(dev);
    dprintf("> register_netdev=%d\n", err);
    if(err) goto exit;
    rtnl_lock();
    dev_open(dev);
    rtnl_unlock();

    //dev_hold(dev);
  exit:
    if(err){
        if(dev) kfree(dev);
        vnet->dev = NULL;
    }
    dprintf("< err=%d\n", err);
    return err;
}
