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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/version.h>

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/udp.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <asm/semaphore.h>

#include <tunnel.h>
#include <vnet.h>
#include <vif.h>
#include <varp.h>
#include <if_varp.h>

#include "allocate.h"
#include "hash_table.h"
#include "sys_net.h"
#include "sys_string.h"

#define MODULE_NAME "VARP"
//#define DEBUG 1
#undef DEBUG
#include "debug.h"


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
// The 'ethernet' field in the skb->mac union went away.
#define MAC_ETH(_skb) ((struct ethhdr *)(_skb)->mac.raw)
#else
#define MAC_ETH(_skb) ((_skb)->mac.ethernet)
#endif

/** @file VARP: Virtual ARP.
 *
 * Handles virtual ARP requests for vnet/vmac.
 */

/*

Varp uses UDP on port 1798.

on domain up: ?
  send varp.announce { id, vmac, vnet, coa } for each vif
  that haven't announced before, or has changed.
  install vif entries in local table.

on varp.announce{ id, vmac, vnet, coa }:
  update VARP entry for vmac x vnet if have one, reset ttl.

on varp.request { id, vmac, vnet }:
  if have a vif for the requested vmac/vnet,
  reply with varp.announce{ id, vmac, vnet, coa }

on timer:
  traverse VARP table, flush old entries.

on probe timer:
  probe again if not out of tries.
  if out of tries invalidate entry.

*/

/** Time-to-live of varp entries (in jiffies).*/
#define VARP_ENTRY_TTL      (60*HZ)

/** Maximum number of varp probes to make. */
#define VARP_PROBE_MAX      5

/** Interval between varp probes (in jiffies). */
#define VARP_PROBE_INTERVAL (3*HZ)

/** Maximum number of queued skbs for a varp entry. */
#define VARP_QUEUE_MAX      16

/** Number of buckets in the varp table (must be prime). */
#define VARP_TABLE_BUCKETS  3001

/** Varp entry states. */
enum {
    VARP_STATE_INCOMPLETE = 1,
    VARP_STATE_REACHABLE = 2,
    VARP_STATE_FAILED = 3
};

/** Varp entry flags. */
enum {
    VARP_FLAG_PROBING = 1,
    VARP_FLAG_PERMANENT = 2,
};

/** Key for varp entries. */
typedef struct VarpKey {
    /** Vnet id (host order). */
    u32 vnet;
    /** Virtual MAC address. */
    Vmac vmac;
} VarpKey;

/** An entry in the varp cache. */
typedef struct VarpEntry {
    /** Key for the entry. */
    VarpKey key;
    /** Care-of address for the key. */
    u32 addr;
    /** Last-updated timestamp. */
    unsigned long timestamp;
    /** State. */
    short state;
    /** Flags. */
    short flags;
    /** Reference count. */
    atomic_t refcount;
    /** Lock. */
    rwlock_t lock;
    /** How many probes have been made. */
    atomic_t probes;
    /** Probe timer. */
    struct timer_list timer;
    void (*error)(struct VarpEntry *ventry, struct sk_buff *skb);
    /** Outbound skb queue. */
    struct sk_buff_head queue;
    /** Maximum size of the queue. */
    int queue_max;

    int locks;
} VarpEntry;

/** The varp cache. Varp entries indexed by VarpKey. */
typedef struct VarpTable {

    HashTable *table;

    /** Sweep timer. */
    struct timer_list timer;

    /** Lock. Need to use a semaphore instead of a spinlock because
     * some operations under the varp table lock can schedule - and
     * you mustn't hold a spinlock when scheduling.
     */
    struct semaphore lock;

} VarpTable;

/** The varp cache. */
static VarpTable *varp_table = NULL;

/** Module parameter for the multicast address. */
static char *varp_mcaddr = NULL;

/** Multicast address (network order). */
u32 varp_mcast_addr = 0;

/** Unicast address (network order). */
u32 varp_ucast_addr = 0;

/** UDP port (network order). */
u16 varp_port = 0;

/** Network device to use. */
char *varp_device = DEVICE;

#define VarpTable_read_lock(z, flags)    do{ (flags) = 0; down(&(z)->lock); } while(0)
#define VarpTable_read_unlock(z, flags)  do{ (flags) = 0; up(&(z)->lock); } while(0)
#define VarpTable_write_lock(z, flags)   do{ (flags) = 0; down(&(z)->lock); } while(0)
#define VarpTable_write_unlock(z, flags) do{ (flags) = 0; up(&(z)->lock); } while(0)

#define VarpEntry_lock(ventry, flags)    write_lock_irqsave(&(ventry)->lock, (flags))
#define VarpEntry_unlock(ventry, flags)  write_unlock_irqrestore(&(ventry)->lock, (flags))

void VarpTable_sweep(VarpTable *z, int all);
void VarpTable_print(VarpTable *z);

/** Print the varp cache (if debug on).
 */
void varp_dprint(void){
#ifdef DEBUG
    VarpTable_print(varp_table);
#endif
} 

/** Print varp info and the varp cache.
 */
void varp_print(void){
    printk(KERN_INFO "=== VARP ===============================================================\n");
    printk(KERN_INFO "varp_device     %s\n", varp_device);
    printk(KERN_INFO "varp_mcast_addr " IPFMT "\n", NIPQUAD(varp_mcast_addr));
    printk(KERN_INFO "varp_ucast_addr " IPFMT "\n", NIPQUAD(varp_ucast_addr));
    printk(KERN_INFO "varp_port       %d\n", ntohs(varp_port));
    VarpTable_print(varp_table);
    printk(KERN_INFO "========================================================================\n");
}

/** Lookup a network device by name.
 *
 * @param name device name
 * @param dev return parameter for the device
 * @return 0 on success, error code otherwise
 */
int vnet_get_device(const char *name, struct net_device **dev){
    int err = 0;
    *dev = dev_get_by_name(name);
    if(!*dev){
        err = -ENETDOWN;
    }
    return err;
}

/** Get the source address from a device.
 *
 * @param dev device
 * @param addr return parameter for address
 * @return 0 on success, error code otherwise
 */
int vnet_get_device_address(struct net_device *dev, u32 *addr){
    int err = 0;
    struct in_device *in_dev;

    //printk("%s>\n", __FUNCTION__);
    in_dev = in_dev_get(dev);
    if(!in_dev){
        err = -EIO;
        goto exit;
    }
    *addr = in_dev->ifa_list->ifa_address;
    in_dev_put(in_dev);
  exit:
    //printk("%s< err=%d\n", __FUNCTION__, err);
    return err;
}

#ifndef LL_RESERVED_SPACE
#define HH_DATA_MOD	16
#define LL_RESERVED_SPACE(dev) \
        ((dev->hard_header_len & ~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#endif

/** Send a varp protocol message.
 *
 * @param opcode varp opcode (host order)
 * @param dev device (may be null)
 * @param skb skb being replied to (may be null)
 * @param vnet vnet id (in host order)
 * @param vmac vmac (in network order)
 * @return 0 on success, error code otherwise
 */
int varp_send(u16 opcode, struct net_device *dev, struct sk_buff *skbin,
              u32 vnet, Vmac *vmac){
    int err = 0;
    int link_n = 0;
    int ip_n = sizeof(struct iphdr);
    int udp_n = sizeof(struct udphdr);
    int varp_n = sizeof(VarpHdr);
    struct sk_buff *skbout = NULL;
    struct in_device *in_dev = NULL;
    VarpHdr *varph = NULL;
    u8 macbuf[6] = {};
    u8 *smac, *dmac;
    u32 saddr, daddr;
    u16 sport, dport;

    dmac = macbuf;
    dprintf("> opcode=%d vnet=%d vmac=" MACFMT "\n",
            opcode, ntohl(vnet), MAC6TUPLE(vmac->mac));
    if(!dev){
        //todo: should use routing for daddr to get device.
        err = vnet_get_device(varp_device, &dev);
        if(err) goto exit;
    }
    link_n = LL_RESERVED_SPACE(dev);
    in_dev = in_dev_get(dev);
    if(!in_dev) goto exit;

    smac = dev->dev_addr;
    saddr = in_dev->ifa_list->ifa_address;

    if(skbin){
        dmac = MAC_ETH(skbin)->h_source;
        sport = skbin->h.uh->dest;
        daddr = skbin->nh.iph->saddr;
        //dport = skbin->h.uh->source;
        dport = varp_port;
    } else {
        if(!in_dev) goto exit;
        if(MULTICAST(varp_mcast_addr)){
            daddr = varp_mcast_addr;
            ip_eth_mc_map(daddr, dmac);
        } else {
            daddr = in_dev->ifa_list->ifa_broadcast;
            dmac = dev->broadcast;
        }
        sport = varp_port;
        dport = varp_port;
    }
    in_dev_put(in_dev);

    dprintf("> smac=" MACFMT " dmac=" MACFMT "\n", MAC6TUPLE(smac), MAC6TUPLE(dmac));
    dprintf("> saddr=" IPFMT " daddr=" IPFMT "\n", NIPQUAD(saddr), NIPQUAD(daddr));
    dprintf("> sport=%u dport=%u\n", ntohs(sport), ntohs(dport));

    skbout = alloc_skb(link_n + ip_n + udp_n + varp_n, GFP_ATOMIC);
    if (!skbout){
        err = -ENOMEM;
        goto exit;
    }
    skbout->dev = dev;
    skb_reserve(skbout, link_n);
    skbout->protocol = htons(ETH_P_IP);

    // Device header. Pushes device header on front of skb.
    if (dev->hard_header){
        err = dev->hard_header(skbout, dev, ETH_P_IP, dmac, smac, skbout->len);
        if(err < 0) goto exit;
        skbout->mac.raw = skbout->data;
    }

    // IP header.
    skbout->nh.raw = skb_put(skbout, ip_n);
    skbout->nh.iph->version  = 4;
    skbout->nh.iph->ihl      = ip_n / 4;
    skbout->nh.iph->tos      = 0;
    skbout->nh.iph->tot_len  = htons(ip_n + udp_n + varp_n);
    skbout->nh.iph->id       = 0;
    skbout->nh.iph->frag_off = 0;
    skbout->nh.iph->ttl      = 64;
    skbout->nh.iph->protocol = IPPROTO_UDP;
    skbout->nh.iph->saddr    = saddr;
    skbout->nh.iph->daddr    = daddr;  
    skbout->nh.iph->check    = 0;

    // UDP header.
    skbout->h.raw = skb_put(skbout, udp_n);
    skbout->h.uh->source     = sport;
    skbout->h.uh->dest       = dport;
    skbout->h.uh->len        = htons(udp_n + varp_n);
    skbout->h.uh->check      = 0;

    // Varp header.
    varph = (void*)skb_put(skbout, varp_n);
    *varph = (VarpHdr){};
    varph->vnetmsghdr.id     = htons(VARP_ID);
    varph->vnetmsghdr.opcode = htons(opcode);
    varph->vnet              = htonl(vnet);
    varph->vmac              = *vmac;
    varph->addr              = saddr;

    err = skb_xmit(skbout);

  exit:
    if(err && skbout) kfree_skb(skbout);
    dprintf("< err=%d\n", err);
    return err;
}

/** Send a varp request for the vnet and destination mac of a packet.
 *
 * @param skb packet
 * @param vnet vnet (in host order)
 * @return 0 on success, error code otherwise
 */
int varp_solicit(struct sk_buff *skb, int vnet){
    int err = 0;
    dprintf("> skb=%p\n", skb);
    varp_dprint();
    err = varp_send(VARP_OP_REQUEST, NULL, NULL,
                    vnet, (Vmac*)MAC_ETH(skb)->h_dest);
    dprintf("< err=%d\n", err);
    return err;
}

/* Test some flags.
 *
 * @param z varp entry
 * @param flags to test
 * @return nonzero if flags set
 */
int VarpEntry_get_flags(VarpEntry *z, int flags){
    return z->flags & flags;
}

/** Set some flags.
 *
 * @param z varp entry
 * @param flags to set
 * @param set set flags on if nonzero, off if zero
 * @return new flags value
 */
int VarpEntry_set_flags(VarpEntry *z, int flags, int set){
    if(set){
        z->flags |= flags;
    } else {
        z->flags &= ~flags;
    }
    return z->flags;
}

/** Print a varp entry.
 *
 * @param ventry varp entry
 */
void VarpEntry_print(VarpEntry *ventry){
    if(ventry){
        char *c, *d;
        switch(ventry->state){
        case VARP_STATE_INCOMPLETE: c = "INC"; break;
        case VARP_STATE_REACHABLE:  c = "RCH"; break;
        case VARP_STATE_FAILED:     c = "FLD"; break;
        default:                    c = "UNK"; break;
        }
        d = (VarpEntry_get_flags(ventry, VARP_FLAG_PROBING) ? "P" : " ");

        printk(KERN_INFO "VENTRY(%p ref=%1d %s %s vnet=%d vmac=" MACFMT " addr=" IPFMT " q=%d t=%lu)\n",
               ventry,
               atomic_read(&ventry->refcount),
               c, d,
               ventry->key.vnet,
               MAC6TUPLE(ventry->key.vmac.mac),
               NIPQUAD(ventry->addr),
               skb_queue_len(&ventry->queue),
               ventry->timestamp);
    } else {
        printk("VENTRY: Null!\n");
    }
}

/** Free a varp entry.
 *
 * @param z varp entry
 */
void VarpEntry_free(VarpEntry *z){
    if(!z) return;
    deallocate(z);
}

/** Increment reference count.
 *
 * @param z varp entry (may be null)
 */
void VarpEntry_incref(VarpEntry *z){
    if(!z) return;
    atomic_inc(&z->refcount);
    //dprintf("> "); VarpEntry_print(z);
}

/** Decrement reference count, freeing if zero.
 *
 * @param z varp entry (may be null)
 */
void VarpEntry_decref(VarpEntry *z){
    if(!z) return;
    //dprintf("> "); VarpEntry_print(z);
    if(atomic_dec_and_test(&z->refcount)){
        //dprintf("> freeing %p...\n", z);
        VarpEntry_free(z);
    }
}

/** Call the error handler.
 *
 * @param ventry varp entry
 */
void VarpEntry_error(VarpEntry *ventry){
    struct sk_buff *skb;
    skb = skb_peek(&ventry->queue);
    if(!skb) return;
    if(ventry->error) ventry->error(ventry, skb);
    skb_queue_purge(&ventry->queue);
}

/** Schedule the varp entry timer.
 * Must increment the reference count before doing
 * this the first time, so the ventry won' be freed
 * before the timer goes off.
 *
 * @param ventry varp entry
 */
void VarpEntry_schedule(VarpEntry *ventry){
    unsigned long now = jiffies;
    ventry->timer.expires = now + VARP_PROBE_INTERVAL;
    add_timer(&ventry->timer);
}

/** Function called when a varp entry timer goes off.
 * If the entry is still incomplete, carries on probing.
 * Otherwise stops probing.
 *
 * @param arg ventry
 */
static void varp_timer_fn(unsigned long arg){
    unsigned long flags;
    VarpEntry *ventry = (VarpEntry *)arg;
    struct sk_buff *skb = NULL;
    int locked = 0, probing = 0;

    dprintf(">\n"); //VarpEntry_print(ventry);
    VarpEntry_lock(ventry, flags);
    locked = 1;
    if(ventry->state == VARP_STATE_REACHABLE){
        // Do nothing.
    } else {
        // Probe if haven't run out of tries, otherwise fail.
        if(atomic_read(&ventry->probes) < VARP_PROBE_MAX){
            probing = 1;
            VarpEntry_schedule(ventry);
            skb = skb_peek(&ventry->queue);
            if(skb){
                dprintf("> skbs in queue - solicit\n");
                atomic_inc(&ventry->probes);
                VarpEntry_unlock(ventry, flags);
                locked = 0;
                varp_solicit(skb, ventry->key.vnet);
            } else {
                dprintf("> empty queue.\n");
            }
        } else {
            dprintf("> Out of probes: FAILED\n");
            VarpEntry_error(ventry);
            ventry->state = VARP_STATE_FAILED;
        }
    }
    VarpEntry_set_flags(ventry, VARP_FLAG_PROBING, probing);
    if(locked) VarpEntry_unlock(ventry, flags);
    if(!probing) VarpEntry_decref(ventry);
    dprintf("<\n");
}

/** Default error function for varp entries.
 *
 * @param ventry varp entry
 * @param skb packet dropped because of error
 */
static void varp_error_fn(VarpEntry *ventry, struct sk_buff *skb){
}

/** Create a varp entry. Initializes the internal state.
 *
 * @param vnet vnet id
 * @param vmac virtual MAC address (copied)
 * @return ventry or null
 */
VarpEntry * VarpEntry_new(u32 vnet, Vmac *vmac){
    VarpEntry *z = ALLOCATE(VarpEntry);
    if(z){
        unsigned long now = jiffies;

        atomic_set(&z->refcount, 1);
        z->lock = RW_LOCK_UNLOCKED;
        z->state = VARP_STATE_INCOMPLETE;
        z->queue_max = VARP_QUEUE_MAX;
        skb_queue_head_init(&z->queue);
        init_timer(&z->timer);
        z->timer.data = (unsigned long)z;
        z->timer.function = varp_timer_fn;
        z->timestamp = now;
        z->error = varp_error_fn;

        z->key.vnet = vnet;
        z->key.vmac = *vmac;
    }
    return z;
}

/** Hash function for keys in the varp cache.
 * Hashes the vnet id and mac.
 *
 * @param k key (VarpKey)
 * @return hashcode
 */
Hashcode varp_key_hash_fn(void *k){
    VarpKey *key = k;
    Hashcode h;
    h = hash_2ul(key->vnet,
                 (key->vmac.mac[0] << 24) |
                 (key->vmac.mac[1] << 16) |
                 (key->vmac.mac[2] <<  8) |
                 (key->vmac.mac[3]      ));
    h = hash_hul(h, 
                 (key->vmac.mac[4] <<   8) |
                 (key->vmac.mac[5]       ));
    return h;
}

/** Test equality for keys in the varp cache.
 * Compares vnet and mac.
 *
 * @param k1 key to compare (VarpKey)
 * @param k2 key to compare (VarpKey)
 * @return 1 if equal, 0 otherwise
 */
int varp_key_equal_fn(void *k1, void *k2){
    VarpKey *key1 = k1;
    VarpKey *key2 = k2;
    return (key1->vnet == key2->vnet)
        && (memcmp(key1->vmac.mac, key2->vmac.mac, ETH_ALEN) == 0);
}

/** Free an entry in the varp cache.
 *
 * @param table containing table
 * @param entry entry to free
 */
static void varp_entry_free_fn(HashTable *table, HTEntry *entry){
    VarpEntry *ventry;
    if(!entry) return;
    ventry = entry->value;
    if(ventry) VarpEntry_decref(ventry);
    HTEntry_free(entry);
}

/** Free the whole varp cache.
 * Dangerous.
 *
 * @param z varp cache
 */
void VarpTable_free(VarpTable *z){
    unsigned long flags;
    if(!z) return;
    VarpTable_write_lock(z, flags);
    del_timer(&z->timer);
    z->timer.data = 0;
    if(z->table) HashTable_free(z->table); 
    VarpTable_write_unlock(z, flags);
    deallocate(z);
}

/** Schedule the varp table timer.
 *
 * @param z varp table
 */
void VarpTable_schedule(VarpTable *z){
    unsigned long now = jiffies;
    z->timer.expires = now + VARP_ENTRY_TTL;
    add_timer(&z->timer);
}

/** Function called when the varp table timer goes off.
 * Sweeps old varp cache entries and reschedules itself.
 *
 * @param arg varp table
 */
static void varp_table_timer_fn(unsigned long arg){
    VarpTable *z = (VarpTable *)arg;
    //dprintf("> z=%p\n", z);
    if(z){
        VarpTable_sweep(z, 0);
        VarpTable_schedule(z);
    }
    //dprintf("<\n");
}

/** Print a varp table.
 *
 * @param z table
 */
void VarpTable_print(VarpTable *z){
    HashTable_for_decl(entry);
    VarpEntry *ventry;
    unsigned long flags, vflags;

    //dprintf(">\n");
    VarpTable_read_lock(z, flags);
    HashTable_for_each(entry, varp_table->table){
        ventry = entry->value;
        VarpEntry_lock(ventry, vflags);
        VarpEntry_print(ventry);
        VarpEntry_unlock(ventry, vflags);
    }
    VarpTable_read_unlock(z, flags);
    //dprintf("<\n");
}

/** Create a varp table.
 *
 * @return new table or null
 */
VarpTable * VarpTable_new(void){
    int err = -ENOMEM;
    VarpTable *z = NULL;

    z = ALLOCATE(VarpTable);
    if(!z) goto exit;
    z->table = HashTable_new(VARP_TABLE_BUCKETS);
    if(!z->table) goto exit;
    z->table->key_equal_fn = varp_key_equal_fn;
    z->table->key_hash_fn = varp_key_hash_fn;
    z->table->entry_free_fn = varp_entry_free_fn;
    init_MUTEX(&z->lock);
    init_timer(&z->timer);
    z->timer.data = (unsigned long)z;
    z->timer.function = varp_table_timer_fn;
    VarpTable_schedule(z);
    err = 0;
  exit:
    if(err){
        VarpTable_free(z);
        z = NULL;
    }
    return z;
}

/** Add a new entry to the varp table.
 *
 * @param z table
 * @param vnet vnet id
 * @param vmac virtual MAC address (copied)
 * @return new entry or null
 */
VarpEntry * VarpTable_add(VarpTable *z, u32 vnet, Vmac *vmac){
    int err = -ENOMEM;
    VarpEntry *ventry;
    HTEntry *entry;
    unsigned long flags;

    ventry = VarpEntry_new(vnet, vmac);
    if(!ventry) goto exit;
    //dprintf("> "); VarpEntry_print(ventry);
    VarpTable_write_lock(z, flags);
    entry = HashTable_add(z->table, ventry, ventry);
    VarpTable_write_unlock(z, flags);
    if(!entry) goto exit;
    VarpEntry_incref(ventry);
    err = 0;
  exit:
    if(err){
        VarpEntry_free(ventry);
        ventry = NULL;
    }
    return ventry;
}

/** Remove an entry from the varp table.
 *
 * @param z table
 * @param ventry entry to remove
 * @return removed count
 */
int VarpTable_remove(VarpTable *z, VarpEntry *ventry){
    return HashTable_remove(z->table, ventry);
}

/** Lookup an entry in the varp table.
 *
 * @param z table
 * @param vnet vnet id
 * @param vmac virtual MAC addres
 * @return entry found or null
 */
VarpEntry * VarpTable_lookup(VarpTable *z, u32 vnet, Vmac *vmac){
    unsigned long flags;
    VarpKey key = { .vnet = vnet, .vmac = *vmac };
    VarpEntry *ventry;
    VarpTable_read_lock(z, flags);
    ventry = HashTable_get(z->table, &key);
    VarpTable_read_unlock(z, flags);
    if(ventry) VarpEntry_incref(ventry);
    return ventry;
}

/** Handle output for a reachable ventry.
 * Send the skb using the tunnel to the care-of address.
 *
 * @param ventry varp entry
 * @param skb skb to send
 * @return 0 on success, error code otherwise
 */
int VarpEntry_send(VarpEntry *ventry, struct sk_buff *skb){
    int err = 0;
    unsigned long flags = 0;
    u32 addr;

    dprintf("> skb=%p\n", skb);
    addr = ventry->addr;
    VarpEntry_unlock(ventry, flags);
    err = vnet_tunnel_send(ventry->key.vnet, addr, skb);
    VarpEntry_lock(ventry, flags);
    dprintf("< err=%d\n", err);
    return err;
}

/** Handle output for a non-reachable ventry. Send messages to complete it.
 * If the entry is still incomplete, queue the skb, otherwise
 * send it. If the queue is full, dequeue and free an old skb to
 * make room for the new one.
 *
 * @param ventry varp entry
 * @param skb skb to send
 * @return 0 on success, error code otherwise
 */
int VarpEntry_resolve(VarpEntry *ventry, struct sk_buff *skb){
    int err = 0;
    unsigned long flags = 0;

    dprintf("> skb=%p\n", skb); //VarpEntry_print(ventry);
    ventry->state = VARP_STATE_INCOMPLETE;
    atomic_set(&ventry->probes, 1);
    if(!VarpEntry_get_flags(ventry, VARP_FLAG_PROBING)){
        VarpEntry_set_flags(ventry, VARP_FLAG_PROBING, 1);
        VarpEntry_incref(ventry);
        VarpEntry_schedule(ventry);
    }
    VarpEntry_unlock(ventry, flags);
    varp_solicit(skb, ventry->key.vnet);
    VarpEntry_lock(ventry, flags);

    if(ventry->state == VARP_STATE_INCOMPLETE){
        if(skb_queue_len(&ventry->queue) >= ventry->queue_max){
            struct sk_buff *oldskb;
            oldskb = ventry->queue.next;
            __skb_unlink(oldskb, &ventry->queue);
            dprintf("> purging skb=%p\n", oldskb);
            kfree_skb(oldskb);
        }
        __skb_queue_tail(&ventry->queue, skb);
    } else {
        err = VarpEntry_send(ventry, skb);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Handle output for a ventry. Resolves the ventry
 * if necessary.
 *
 * @param ventry varp entry
 * @param skb skb to send
 * @return 0 on success, error code otherwise
 */
int VarpEntry_output(VarpEntry *ventry, struct sk_buff *skb){
    int err = 0;

    switch(ventry->state){
    case VARP_STATE_REACHABLE:
        err = VarpEntry_send(ventry, skb);
        break;
    default:
        err = VarpEntry_resolve(ventry, skb);
        break;
    }
    return err;
}

/** Process the output queue for a ventry.  Sends the queued skbs if
 * the ventry is reachable, otherwise drops them.
 *
 * @param ventry varp entry
 */
void VarpEntry_process_queue(VarpEntry *ventry){
    struct sk_buff *skb;
    for( ; ; ){
        if(ventry->state != VARP_STATE_REACHABLE) break;
        skb = __skb_dequeue(&ventry->queue);
        if(!skb) break;
        VarpEntry_output(ventry, skb);
    }
    skb_queue_purge(&ventry->queue);
}

/** Update a ventry. Sets the address and state to those given
 * and sets the timestamp to 'now'.
 *
 * @param ventry varp entry
 * @param addr care-of address
 * @param state state
 * @return 0 on success, error code otherwise
 */
int VarpEntry_update(VarpEntry *ventry, u32 addr, int state){
    int err = 0;
    unsigned long now = jiffies;
    unsigned long flags;

    dprintf("> addr=" IPFMT " state=%d\n", NIPQUAD(addr), state);
    //VarpEntry_print(ventry);
    VarpEntry_lock(ventry, flags);
    if(VarpEntry_get_flags(ventry, VARP_FLAG_PERMANENT)) goto exit;
    ventry->addr = addr;
    ventry->timestamp = now;
    ventry->state = state;
    VarpEntry_process_queue(ventry);
  exit:
    //dprintf("> "); VarpEntry_print(ventry);
    VarpEntry_unlock(ventry, flags);
    dprintf("< err=%d\n", err);
    return err;
}
    
int VarpTable_update(VarpTable *z, int vnet, Vmac *vmac, u32 addr,
                     int state, int force){
    int err = 0;
    VarpEntry *ventry;
    
    dprintf("> vnet=%d mac=" MACFMT " addr=" IPFMT " state=%d force=%d\n",
            vnet, MAC6TUPLE(vmac->mac), NIPQUAD(addr), state, force);
    ventry = VarpTable_lookup(z, vnet, vmac);
    if(force && !ventry){
        dprintf("> No entry, adding\n");
        ventry = VarpTable_add(z, vnet, vmac);
    }
    if(ventry){
        dprintf("> Updating\n");
        err = VarpEntry_update(ventry, addr, state);
        VarpEntry_decref(ventry);
    } else {
        dprintf("> No entry found\n");
        err = -ENOENT;
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Update the ventry corresponding to the given varp header.
 *
 * @param z table
 * @param varph varp header
 * @param state state
 * @return 0 on success, -ENOENT if no entry found
 */
int VarpTable_update_entry(VarpTable *z, VarpHdr *varph, int state){
    return VarpTable_update(z, ntohl(varph->vnet), &varph->vmac, varph->addr, state, 0);
}

int varp_update(int vnet, unsigned char *vmac, u32 addr){
    if(!varp_table){
        return -ENOSYS;
    }
    return VarpTable_update(varp_table, vnet, (Vmac*)vmac, addr,
                            VARP_STATE_REACHABLE, 1);
}

/** Put old varp entries into the incomplete state.
 * Permanent entries are not changed.
 * If 'all' is non-zero, all non-permanent entries
 * are put into the incomplete state, regardless of age.
 *
 * @param z table
 * @param all reset all entries if non-zero
 */
void VarpTable_sweep(VarpTable *z, int all){
    HashTable_for_decl(entry);
    VarpEntry *ventry;
    unsigned long now = jiffies;
    unsigned long old = now - VARP_ENTRY_TTL;
    unsigned long flags, vflags;

    //dprintf(">\n");
    VarpTable_read_lock(z, flags);
    HashTable_for_each(entry, varp_table->table){
        ventry = entry->value;
        VarpEntry_lock(ventry, vflags);
        if(!VarpEntry_get_flags(ventry, VARP_FLAG_PERMANENT) &&
           (all || (ventry->timestamp < old))){
            VarpEntry_process_queue(ventry);
            ventry->state = VARP_STATE_INCOMPLETE;
        }
        VarpEntry_unlock(ventry, vflags);
    }
    VarpTable_read_unlock(z, flags);
    //dprintf("<\n");
}

/** Handle a varp request. Look for a vif with the requested 
 * vnet and vmac. If find one, reply with the vnet, vmac and our
 * address. Otherwise do nothing.
 *
 * @param skb incoming message
 * @param varph varp message
 * @return 0 if ok, -ENOENT if no matching vif, or error code
 */
int varp_handle_request(struct sk_buff *skb, VarpHdr *varph){
    int err = -ENOENT;
    u32 vnet;
    Vmac *vmac;
    Vif *vif = NULL;

    dprintf(">\n");
    vnet = ntohl(varph->vnet);
    vmac = &varph->vmac;
    dprintf("> vnet=%d vmac=" MACFMT "\n", vnet, MAC6TUPLE(vmac->mac));
    if(vif_lookup(vnet, vmac, &vif)) goto exit;
    varp_send(VARP_OP_ANNOUNCE, skb->dev, skb, vnet, vmac);
    vif_decref(vif);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Announce the vnet and vmac of a vif (gratuitous varp).
 *
 * @param dev device to send on (may be null)
 * @param vif vif
 * @return 0 on success, error code otherwise
 */
int varp_announce_vif(struct net_device *dev, Vif *vif){
    int err = 0;
    dprintf(">\n");
    if(!varp_table){
        err = -ENOSYS;
        goto exit;
    }
    err = varp_send(VARP_OP_ANNOUNCE, dev, NULL, vif->vnet, &vif->vmac);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Handle a varp announce message.
 * Update the matching ventry if we have one.
 *
 * @param skb incoming message
 * @param varp message
 * @return 0 if OK, -ENOENT if no matching entry
 */
int varp_handle_announce(struct sk_buff *skb, VarpHdr *varph){
    int err = 0;

    dprintf(">\n");
    err = VarpTable_update_entry(varp_table, varph, VARP_STATE_REACHABLE);
    dprintf("< err=%d\n", err);
    return err;
}

/** Handle an incoming varp message.
 *
 * @param skb incoming message
 * @return 0 if OK, error code otherwise
 */
int varp_handle_message(struct sk_buff *skb){
    // Assume h. nh set, skb->data point after udp hdr (at varphdr).
    int err = -EINVAL, mine = 0;
    VarpHdr *varph = (void*)(skb->h.uh + 1);

    dprintf(">\n");
    if(!varp_table){
        err = -ENOSYS;
        goto exit;
    }
    if(MULTICAST(skb->nh.iph->daddr) &&
       (skb->nh.iph->daddr != varp_mcast_addr)){
        // Ignore multicast packets not addressed to us.
        err = 0;
        dprintf("> daddr=" IPFMT " mcaddr=" IPFMT "\n",
                NIPQUAD(skb->nh.iph->daddr), NIPQUAD(varp_mcast_addr));
        goto exit;
    }
    if(skb->len < sizeof(*varph)){
        wprintf("> Varp msg too short: %d < %d\n", skb->len, sizeof(*varph));
        goto exit;
    }
    mine = 1;
    if(varph->vnetmsghdr.id != htons(VARP_ID)){
        // It's not varp at all - ignore it.
        wprintf("> Unknown id: %d \n", ntohs(varph->vnetmsghdr.id));
        goto exit;
    }
    if(1){
        dprintf("> saddr=" IPFMT " daddr=" IPFMT "\n",
                NIPQUAD(skb->nh.iph->saddr), NIPQUAD(skb->nh.iph->daddr));
        dprintf("> sport=%u dport=%u\n", ntohs(skb->h.uh->source), ntohs(skb->h.uh->dest));
        dprintf("> opcode=%d vnet=%u vmac=" MACFMT " addr=" IPFMT "\n",
                ntohs(varph->vnetmsghdr.opcode),
                ntohl(varph->vnet),
                MAC6TUPLE(varph->vmac.mac),
                NIPQUAD(varph->addr));
        varp_dprint();
    }
    switch(ntohs(varph->vnetmsghdr.opcode)){
    case VARP_OP_REQUEST:
        err = varp_handle_request(skb, varph);
        break;
    case VARP_OP_ANNOUNCE:
        err = varp_handle_announce(skb, varph);
        break;
    default:
        wprintf("> Unknown opcode: %d \n", ntohs(varph->vnetmsghdr.opcode));
       break;
    }
  exit:
    if(mine) err = 1;
    dprintf("< err=%d\n", err);
    return err;
}

/** Send an outgoing packet on the appropriate vnet tunnel.
 *
 * @param skb outgoing message
 * @param vnet vnet (host order)
 * @return 0 on success, error code otherwise
 */
int varp_output(struct sk_buff *skb, u32 vnet){
    int err = 0;
    unsigned char *mac = NULL;
    Vmac *vmac = NULL;
    VarpEntry *ventry = NULL;

    dprintf("> skb=%p vnet=%u\n", skb, vnet);
    if(!varp_table){
        err = -ENOSYS;
        goto exit;
    }
    dprintf("> skb.mac=%p\n", skb->mac.raw);
    if(!skb->mac.raw){
        wprintf("> No ethhdr in skb!\n");
        err = -EINVAL;
        goto exit;
    }
    mac = MAC_ETH(skb)->h_dest;
    vmac = (Vmac*)mac;
    if(mac_is_multicast(mac)){
        err = vnet_tunnel_send(vnet, varp_mcast_addr, skb);
    } else {
        ventry = VarpTable_lookup(varp_table, vnet, vmac);
        if(!ventry){
            ventry = VarpTable_add(varp_table, vnet, vmac);
        }
        if(ventry){
            unsigned long flags;
            VarpEntry_lock(ventry, flags);
            err = VarpEntry_output(ventry, skb);
            VarpEntry_unlock(ventry, flags);
            VarpEntry_decref(ventry);
        } else {
            err = -ENOMEM;
        }
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Set the varp multicast address (after initialization).
 *
 * @param addr address (network order)
 * @return 0 on success, error code otherwise
 */
int varp_set_mcast_addr(uint32_t addr){
    int err = 0;
    varp_close();
    varp_mcast_addr = addr;
    err = varp_open(varp_mcast_addr, varp_ucast_addr, varp_port);
    return err;
}

/** Initialize the varp multicast address from a module parameter.
 *
 * @param s address in IPv4 notation
 * @return 0 on success, error code otherwise
 */
static void varp_init_mcast_addr(char *s){
    unsigned long v = 0;

    dprintf("> %s\n", s);
    if(s && (get_inet_addr(s, &v) >= 0)){
        varp_mcast_addr = (u32)v;
    } else {
        varp_mcast_addr = htonl(VARP_MCAST_ADDR);
    }
}

/** Initialize the varp cache.
 *
 * @return 0 on success, error code otherwise
 */
int varp_init(void){
    int err = 0;
    struct net_device *dev = NULL;
    
    dprintf(">\n");
    varp_table = VarpTable_new();
    if(!varp_table){
        err = -ENOMEM;
        goto exit;
    }
    varp_init_mcast_addr(varp_mcaddr);
    err = vnet_get_device(varp_device, &dev);
    dprintf("> vnet_get_device(%s)=%d\n", varp_device, err);
    if(err) goto exit;
    err = vnet_get_device_address(dev, &varp_ucast_addr);
    dprintf("> vnet_get_device_address()=%d\n", err);
    if(err) goto exit;
    varp_port = htons(VARP_PORT);

    err = varp_open(varp_mcast_addr, varp_ucast_addr, varp_port);
    dprintf("> varp_open()=%d\n", err);
  exit:
    if(dev) dev_put(dev);
    dprintf("< err=%d\n", err);
    return err;
}

/** Close the varp cache.
 */
void varp_exit(void){
    dprintf(">\n");
    varp_close();
    if(varp_table){
        VarpTable *z = varp_table;
        varp_table = NULL;
        VarpTable_free(z);
    }
    dprintf("<\n");
}

MODULE_PARM(varp_mcaddr, "s");
MODULE_PARM_DESC(varp_mcaddr, "VARP multicast address");

MODULE_PARM(varp_device, "s");
MODULE_PARM_DESC(varp_device, "VARP network device");
