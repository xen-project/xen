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
#include <linux/init.h>

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>

#include <tunnel.h>
#include <vnet.h>
#include <varp.h>
#include "hash_table.h"

#define MODULE_NAME "VNET"
//#define DEBUG 1
#undef DEBUG
#include "debug.h"

void Tunnel_print(Tunnel *tunnel){
    if(tunnel){
        printk("Tunnel<%p base=%p ref=%02d type=%s>\n",
               tunnel,
               tunnel->base,
               atomic_read(&tunnel->refcount),
               tunnel->type->name);
        if(tunnel->base){
            Tunnel_print(tunnel->base);
        }
    } else {
        printk("Tunnel<%p base=%p ref=%02d type=%s>\n",
               NULL, NULL, 0, "ip");
    }
}

int Tunnel_create(TunnelType *type, u32 vnet, u32 addr, Tunnel *base, Tunnel **val){
    int err = 0;
    Tunnel *tunnel = NULL;
    dprintf("> type=%s vnet=%d addr=" IPFMT " base=%s\n",
            type->name, vnet, NIPQUAD(addr), (base ? base->type->name : "ip"));
    if(!type || !type->open || !type->send || !type->close){
        err = -EINVAL;
        goto exit;
    }
    tunnel = kmalloc(sizeof(Tunnel), GFP_ATOMIC);
    if(!tunnel){
        err = -ENOMEM;
        goto exit;
    }
    atomic_set(&tunnel->refcount, 1);
    tunnel->key.vnet = vnet;
    tunnel->key.addr = addr;
    tunnel->type = type;
    tunnel->data = NULL;
    tunnel->send_stats = (TunnelStats){};
    Tunnel_incref(base);
    tunnel->base = base;
    err = type->open(tunnel);
  exit:
    if(err && tunnel){
        Tunnel_decref(tunnel);
        tunnel = NULL;
    }
    *val = tunnel;
    dprintf("< err=%d\n", err);
    return err;
}

int Tunnel_open(TunnelType *type, u32 vnet, u32 addr, Tunnel *base, Tunnel **tunnel){
    int err = 0;

    dprintf(">\n");
    err = Tunnel_create(type, vnet, addr, base, tunnel);
    if(err) goto exit;
    err = Tunnel_add(*tunnel);
  exit:
    if(err){
        Tunnel_decref(*tunnel);
        *tunnel = NULL;
    }
    dprintf("< err=%d\n", err);
    return err;
}

void TunnelStats_update(TunnelStats *stats, int len, int err){
    dprintf(">len=%d  err=%d\n", len, err);
    if(err){
        stats->dropped_bytes += len;
        stats->dropped_packets++;
    } else {
        stats->bytes += len;
        stats->packets++;
    }
    dprintf("<\n");
}

/** Table of tunnels, indexed by vnet and addr. */
HashTable *tunnel_table = NULL;

static inline Hashcode tunnel_table_key_hash_fn(void *k){
    TunnelKey *key = k;
    Hashcode h = 0;
    h = hash_2ul(key->vnet, key->addr);
    return h;
}

static int tunnel_table_key_equal_fn(void *k1, void *k2){
    TunnelKey *key1 = k1;
    TunnelKey *key2 = k2;
    return (key1->vnet == key2->vnet)
        && (key1->addr == key2->addr);
}

static void tunnel_table_entry_free_fn(HashTable *table, HTEntry *entry){
    Tunnel *tunnel;
    if(!entry) return;
    tunnel = entry->value;
    //dprintf(">\n"); Tunnel_print(tunnel);
    Tunnel_decref(tunnel);
    HTEntry_free(entry);
}

int Tunnel_init(void){
    int err = 0;
    dprintf(">\n");
    tunnel_table = HashTable_new(0);
    if(!tunnel_table){
        err = -ENOMEM;
        goto exit;
    }
    tunnel_table->entry_free_fn = tunnel_table_entry_free_fn;
    tunnel_table->key_hash_fn = tunnel_table_key_hash_fn;
    tunnel_table->key_equal_fn = tunnel_table_key_equal_fn;
  exit:
    dprintf("< err=%d\n", err);
    return err;
}
    
/** Lookup tunnel state by vnet and destination.
 *
 * @param vnet vnet
 * @param addr destination address
 * @return tunnel state or NULL
 */
Tunnel * Tunnel_lookup(u32 vnet, u32 addr){
    Tunnel *tunnel = NULL;
    TunnelKey key = {.vnet = vnet, .addr = addr };
    dprintf(">\n");
    tunnel = HashTable_get(tunnel_table, &key);
    Tunnel_incref(tunnel);
    dprintf("< tunnel=%p\n", tunnel);
    return tunnel;
}

int Tunnel_add(Tunnel *tunnel){
    int err = 0;
    dprintf(">\n");
    if(HashTable_add(tunnel_table, tunnel, tunnel)){
        Tunnel_incref(tunnel);   
    } else {
        err = -ENOMEM;
    }
    dprintf("< err=%d\n", err);
    return err;
}

int Tunnel_del(Tunnel *tunnel){
    return HashTable_remove(tunnel_table, tunnel);
}

/** Do tunnel send processing on a packet.
 *
 * @param tunnel tunnel state
 * @param skb packet
 * @return 0 on success, error code otherwise
 */
int Tunnel_send(Tunnel *tunnel, struct sk_buff *skb){
    int err = 0;
    int len;
    dprintf("> tunnel=%p skb=%p\n", tunnel, skb);
    len = skb->len;
    if(tunnel){
        dprintf("> type=%s type->send...\n", tunnel->type->name);
        err = tunnel->type->send(tunnel, skb);
        // Must not refer to skb after sending - might have been freed.
        TunnelStats_update(&tunnel->send_stats, len, err);
    } else {
        struct net_device *dev = NULL;
        err = vnet_get_device(DEVICE, &dev);
        if(err) goto exit;
        skb->dev = dev;
        err = skb_xmit(skb);
        dev_put(dev);
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

int __init tunnel_module_init(void){
    return Tunnel_init();
}

void __exit tunnel_module_exit(void){
}
