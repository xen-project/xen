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
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/errno.h>

#include <linux/string.h>

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

#include <linux/etherdevice.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/checksum.h>

#include <tunnel.h>
#include <sa.h>
#include <varp.h>
#include <if_varp.h>
#include <esp.h>
#include <etherip.h>
#include <random.h>
#include <tunnel.h>

#include <skb_util.h>
#include <vnet_dev.h>
#include <vnet.h>
#include <vif.h>
#include <vnet_ioctl.h>
#include <sa_algorithm.h>

#include "allocate.h"
#include "hash_table.h"
#include "sys_net.h"
#include "sys_string.h"

#define MODULE_NAME "VNET"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

/** Default vnet security level.
 */
int vnet_security_default = SA_AUTH ; //| SA_CONF;

/** Key for entries in the vnet address table. */
typedef struct VnetAddrKey {
    /** Vnet id. */
    VnetId vnet;
    /** MAC address. */
    unsigned char mac[ETH_ALEN];
} VnetAddrKey;

/** The physical vnet. */
Vnet *vnet_physical = NULL;

/** Table of vnets indexed by id. */
static HashTable *vnet_table = NULL;

/** Decrement reference count, freeing if zero.
 *
 * @param info vnet (OK if null)
 */
void Vnet_decref(Vnet *info){
    if(!info) return;
    if(atomic_dec_and_test(&info->refcount)){
        vnet_dev_remove(info);
        deallocate(info);
    }
}

/** Increment reference count.
 *
 * @param info vnet (OK if null)
 */
void Vnet_incref(Vnet *info){
    if(!info) return;
    atomic_inc(&info->refcount);
}

void Vnet_print(Vnet *info)
{
    char vnetbuf[VNET_ID_BUF];

    printk(KERN_INFO "VNET(vnet=%s device=%s security=%c%c)\n",
           VnetId_ntoa(&info->vnet, vnetbuf),
           info->device,
           ((info->security & SA_AUTH) ? 'a' : '-'),
           ((info->security & SA_CONF) ? 'c' : '-'));
}

void vnet_print(void)
{
    HashTable_for_decl(entry);
    Vnet *info;
    
    HashTable_for_each(entry, vnet_table){
        info = entry->value;
        Vnet_print(info);
    }
}

/** Allocate a vnet, setting reference count to 1.
 *
 * @param info return parameter for vnet
 * @return 0 on success, error code otherwise
 */
int Vnet_alloc(Vnet **info){
    int err = 0;
    *info = ALLOCATE(Vnet);
    if(*info){
        atomic_set(&(*info)->refcount, 1);
    } else {
        err = -ENOMEM;
    }
    return err;
}

/** Add a vnet to the table under its vnet id.
 *
 * @param info vnet to add
 * @return 0 on success, error code otherwise
 */
int Vnet_add(Vnet *info){
    int err = 0;
    HTEntry *entry = NULL;
    // Vnet_del(info->vnet); //todo: Delete existing vnet info?
    Vnet_incref(info);
    entry = HashTable_add(vnet_table, &info->vnet, info);
    if(!entry){
        err = -ENOMEM;
        Vnet_decref(info);
    }
    return err;
}

/** Remove a vnet from the table.
 *
 * @param vnet id of vnet to remove
 * @return number of vnets removed
 */
int Vnet_del(VnetId *vnet){
    return HashTable_remove(vnet_table, vnet);
}

/** Lookup a vnet by id.
 * References the vnet on success - the caller must decref.
 *
 * @param vnet vnet id
 * @param info return parameter for vnet
 * @return 0 on sucess, -ENOENT if no vnet found
 */
int Vnet_lookup(VnetId *vnet, Vnet **info){
    int err = 0;
    *info = HashTable_get(vnet_table, vnet);
    if(*info){
        Vnet_incref(*info);
    } else {
        err = -ENOENT;
    }
    return err;
}

/** Free an entry in the vnet table.
 *
 * @param table containing table
 * @param entry to free
 */
static void vnet_entry_free_fn(HashTable *table, HTEntry *entry){
    Vnet *info;
    if(!entry) return;
    info = entry->value;
    if(info){
        vnet_dev_remove(info);
        Vnet_decref(info);
    }
    HTEntry_free(entry);
}

/** Setup some vnet entries (for testing).
 * Vnet 1 is physical, vnets 2 to 10 are insecure, vnets above
 * 10 are secure.
 *
 * @return 0 on success, negative error code otherwise
 */
static int vnet_setup(void){
    int err = 0;
    int i, n = 3;
    int security = vnet_security_default;
    uint32_t vnetid;
    Vnet *vnet;

    for(i=0; i<n; i++){
        err = Vnet_alloc(&vnet);
        if(err) break;
        vnetid = VNET_VIF + i;
        vnet->vnet = toVnetId(vnetid);
        sprintf(vnet->device, "vnif%04x", vnetid);
        vnet->security = (vnetid > 10 ? security : 0);
        err = Vnet_create(vnet);
        if(err) break;
    }
    return err;
}

int vnet_key_equal_fn(void *k1, void *k2){
    VnetId *key1 = k1;
    VnetId *key2 = k2;
    return VnetId_eq(key1, key2);
}

Hashcode vnet_key_hash_fn(void *k){
    VnetId *key = k;
    return VnetId_hash(0, key);
}

/** Initialize the vnet table and the physical vnet.
 *
 * @return 0 on success, error code otherwise
 */
int vnet_init(void){
    int err = 0;

    vnet_table = HashTable_new(0);
    if(!vnet_table){
        err = -ENOMEM;
        goto exit;
    }
    vnet_table->key_equal_fn = vnet_key_equal_fn;
    vnet_table->key_hash_fn = vnet_key_hash_fn;
    vnet_table->entry_free_fn = vnet_entry_free_fn;

    err = Vnet_alloc(&vnet_physical);
    if(err) goto exit;
    vnet_physical->vnet = toVnetId(VNET_PHYS);
    vnet_physical->security = 0;
    err = Vnet_add(vnet_physical);
    if(err) goto exit;
    err = vnet_setup();
    if(err) goto exit;
    err = varp_init();
    if(err) goto exit;
    err = vif_init();
  exit:
    return err;
}

void vnet_exit(void){
    vif_exit();
    varp_exit();
    HashTable_free(vnet_table);
    vnet_table = NULL;
}

inline int skb_xmit(struct sk_buff *skb){
    int err = 0;
    struct rtable *rt = NULL;

    dprintf(">\n");
    skb->protocol = htons(ETH_P_IP);
    err = skb_route(skb, &rt);
    if(err){
        wprintf("> skb_route=%d\n", err);
        wprintf("> dev=%s idx=%d src=%u.%u.%u.%u dst=%u.%u.%u.%u tos=%d\n",
                (skb->dev ? skb->dev->name : "???"),
                (skb->dev ? skb->dev->ifindex : -1),
                NIPQUAD(skb->nh.iph->saddr),
                NIPQUAD(skb->nh.iph->daddr),
                skb->nh.iph->tos);
                
        goto exit;
    }
    skb->dst = &rt->u.dst;
    if(!skb->dev){
        skb->dev = rt->u.dst.dev;
    }

    ip_select_ident(skb->nh.iph, &rt->u.dst, NULL);

    if(skb->nh.iph->saddr == 0){
        skb->nh.iph->saddr = rt->rt_src;
    }

    skb->nh.iph->check = 0;
    skb->nh.iph->check = ip_compute_csum(skb->nh.raw, (skb->nh.iph->ihl << 2));

    err = neigh_compat_output(skb);

  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Called when a vif sends a packet to the network.
 * Encapsulates the packet for its vnet and forwards it.
 *
 * @param skb packet
 * @return 0 on success, error code otherwise
 *
 * @todo fixme
 */
int vnet_skb_send(struct sk_buff *skb, VnetId *vnet){
    int err = 0;
    VnetId vnet_phys = toVnetId(VNET_PHYS);

    dprintf(">\n");
    skb->dev = NULL;
    if(!vnet || VnetId_eq(vnet, &vnet_phys)){
        // No vnet or physical vnet, send direct to the network. 
        skb_xmit(skb);
    } else {
        err = varp_output(skb, vnet);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Receive an skb for a vnet.
 * We make the skb come out of the vif for the vnet, and
 * let ethernet bridging forward it to related interfaces.
 * If the dest is broadcast, goes to all vifs on the vnet.
 * If the dest is unicast, goes to the addressed vif on the vnet.
 *
 * The packet must have skb->mac.raw set and skb->data must point
 * after the device (ethernet) header.
 *
 * @param skb packet
 * @param vnet packet vnet
 * @param vmac packet vmac
 * @return 0 on success, error code otherwise
 */
int vnet_skb_recv(struct sk_buff *skb, VnetId *vnet, Vmac *vmac){
    int err = 0;
    Vnet *info = NULL;

    err = Vnet_lookup(vnet, &info);
    if(err) goto exit;
    skb->dev = info->dev;
    netif_rx(skb);
  exit:
    if(info) Vnet_decref(info);
    if(err){
        kfree_skb(skb);
    }
    return err;
}

/** Determine ESP security mode for a new SA.
 *
 * @param spi incoming spi
 * @param protocol incoming protocol
 * @param addr source address
 * @return security level or negative error code
 *
 * @todo Need to check spi, and do some lookup for security params.
 */
int vnet_sa_security(u32 spi, int protocol, u32 addr){
    int security = vnet_security_default;
    dprintf("< security=%x\n", security);
    return security;
}

/** Create a new SA for incoming traffic.
 *
 * @param spi incoming spi
 * @param protocol incoming protocol
 * @param addr source address
 * @param sa return parameter for SA
 * @return 0 on success, error code otherwise
 */
int vnet_sa_create(u32 spi, int protocol, u32 addr, SAState **sa){
    int err = 0;
    int security = vnet_sa_security(spi, protocol, addr);
    if(security < 0){
        err = security;
        goto exit;
    }
    err = sa_create(security, spi, protocol, addr, sa);
  exit:
    return err;
}

/** Check that a context has the correct properties w.r.t. a vnet.
 * The context must be secure if the vnet requires security.
 *
 * @param vnet vnet id
 * @param context context
 * @return 0 on success, error code otherwise
 *
 * @todo Need to check that the sa provides the correct security level.
 */
int vnet_check_context(VnetId *vnet, SkbContext *context, Vnet **val){
    int err = 0;
    Vnet *info = NULL;
    SAState *sa = NULL;
    
    err = Vnet_lookup(vnet, &info);
    if(err){
        goto exit;
    }
    if(!info->security) goto exit;
    err = -EINVAL;
    if(!context){
        wprintf("> No security context\n");
        goto exit;
    }
    if(context->protocol != IPPROTO_ESP){
        wprintf("> Invalid protocol: wanted %d, got %d\n",
                IPPROTO_ESP, context->protocol);
        goto exit;
    }
    sa = context->data;
    //todo: Check security properties of the SA are correct w.r.t. the vnet.
    //Something like  sa->security == info->security;
    err = 0;
  exit:
    *val = info;
    return err;
}

/** Open function for SA tunnels.
 *
 * @param tunnel to open
 * @return 0 on success, error code otherwise
 */
static int sa_tunnel_open(Tunnel *tunnel){
    int err = 0;
    //dprintf(">\n");
    //dprintf("< err=%d\n", err);
    return err;
}

/** Close function for SA tunnels.
 *
 * @param tunnel to close (OK if null)
 */
static void sa_tunnel_close(Tunnel *tunnel){
    SAState *sa;
    if(!tunnel) return;
    sa = tunnel->data;
    if(!sa) return;
    SAState_decref(sa);
    tunnel->data = NULL;
}

/** Packet send function for SA tunnels.
 *
 * @param tunnel to send on
 * @param skb packet to send
 * @return 0 on success, negative error code on error
 */
static int sa_tunnel_send(Tunnel *tunnel, struct sk_buff *skb){
    int err = -EINVAL;
    SAState *sa;
    if(!tunnel){
        wprintf("> Null tunnel!\n");
        goto exit;
    }
    sa = tunnel->data;
    if(!sa){
        wprintf("> Null SA!\n");
        goto exit;
    }
    err = SAState_send(sa, skb, tunnel->base);
  exit:
    return err;
}

/** Functions used by SA tunnels. */
static TunnelType _sa_tunnel_type = {
    .name	= "SA",
    .open	= sa_tunnel_open,
    .close	= sa_tunnel_close,
    .send 	= sa_tunnel_send
};

/** Functions used by SA tunnels. */
TunnelType *sa_tunnel_type = &_sa_tunnel_type;

/** Open a tunnel for a vnet to a given address.
 *
 * @param vnet vnet id
 * @param addr destination address
 * @param tunnel return parameter
 * @return 0 on success, error code otherwise
 */
int vnet_tunnel_open(VnetId *vnet, VarpAddr *addr, Tunnel **tunnel){
    extern TunnelType *etherip_tunnel_type;
    int err = 0;
    Vnet *info = NULL;
    Tunnel *base_tunnel = NULL;
    Tunnel *sa_tunnel = NULL;
    Tunnel *etherip_tunnel = NULL;

    err = Vnet_lookup(vnet, &info);
    if(err) goto exit;
    if(info->security){
        SAState *sa = NULL;
        //FIXME: Assuming IPv4 for now.
        u32 ipaddr = addr->u.ip4.s_addr;
        err = Tunnel_create(sa_tunnel_type, vnet, addr, base_tunnel, &sa_tunnel);
        if(err) goto exit;
        err = sa_create(info->security, 0, IPPROTO_ESP, ipaddr, &sa);
        if(err) goto exit;
        sa_tunnel->data = sa;
        base_tunnel = sa_tunnel;
    }
    err = Tunnel_create(etherip_tunnel_type, vnet, addr, base_tunnel, &etherip_tunnel);
    if(err) goto exit;
    err = Tunnel_add(etherip_tunnel);
  exit:
    Tunnel_decref(sa_tunnel);
    Vnet_decref(info);
    if(err){
        *tunnel = NULL;
    } else {
        *tunnel = etherip_tunnel;
    }
    return err;
}

/** Lookup a tunnel for a vnet to a given address.
 * Uses an existing tunnel if there is one.
 *
 * @param vnet vnet id
 * @param addr care-of address
 * @param tunnel return parameter
 * @return 0 on success, error code otherwise
 */
int vnet_tunnel_lookup(VnetId *vnet, VarpAddr *addr, Tunnel **tunnel){
    int err = 0;
    *tunnel = Tunnel_lookup(vnet, addr);
    if(!*tunnel){
        err = vnet_tunnel_open(vnet, addr, tunnel);
    }
    return err;
}

/** Send a packet on the appropriate tunnel.
 *
 * @param vnet vnet
 * @param addr tunnel endpoint
 * @param skb packet
 * @return 0 on success, error code otherwise
 */
int vnet_tunnel_send(VnetId *vnet, VarpAddr *addr, struct sk_buff *skb){
    int err = 0;
    Tunnel *tunnel = NULL;
    err = vnet_tunnel_lookup(vnet, addr, &tunnel);
    if(err) goto exit;
    err = Tunnel_send(tunnel, skb);
    Tunnel_decref(tunnel);
  exit:
    return err;
}

static void __exit vnet_module_exit(void){
    ProcFS_exit();
    sa_table_exit();
    vnet_exit();
    esp_module_exit();
    etherip_module_exit();
    tunnel_module_exit();
    random_module_exit();
}

/** Initialize the vnet module.
 * Failure is fatal.
 *
 * @return 0 on success, error code otherwise
 */
static int __init vnet_module_init(void){
    int err = 0;

    dprintf(">\n");
    err = random_module_init();
    if(err) wprintf("> random_module_init err=%d\n", err);
    if(err) goto exit;
    err = tunnel_module_init();
    if(err) wprintf("> tunnel_module_init err=%d\n", err);
    if(err) goto exit;
    err = etherip_module_init();
    if(err) wprintf("> etherip_module_init err=%d\n", err);
    if(err) goto exit;
    err = esp_module_init();
    if(err) wprintf("> esp_module_init err=%d\n", err);
    if(err) goto exit;
    err = vnet_init();
    if(err) wprintf("> vnet_init err=%d\n", err);
    if(err) goto exit;
    sa_algorithm_probe_all();
    err = sa_table_init();
    if(err) wprintf("> sa_table_init err=%d\n", err);
    if(err) goto exit;
    ProcFS_init();
  exit:
    if(err < 0){
        vnet_module_exit();
        wprintf("< err=%d\n", err);
    }
    return err;
}

module_init(vnet_module_init);
module_exit(vnet_module_exit);
MODULE_LICENSE("GPL");
