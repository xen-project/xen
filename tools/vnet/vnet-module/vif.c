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

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/udp.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>

#include <etherip.h>
#include <if_varp.h>
#include <vnet_dev.h>
#include <vif.h>
#include "allocate.h"
#include "hash_table.h"
#include "sys_net.h"
#include "sys_string.h"

#define MODULE_NAME "VNET"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

/** Table of vifs indexed by VifKey. */
HashTable *vif_table = NULL;

void vif_decref(Vif *vif){
    if(!vif) return;
    if(atomic_dec_and_test(&vif->refcount)){
        kfree(vif);
    }
}

void vif_incref(Vif *vif){
    if(!vif) return;
    atomic_inc(&vif->refcount);
}

/** Hash function for keys in the vif table.
 * Hashes the vnet id and mac.
 *
 * @param k key (VifKey)
 * @return hashcode
 */
Hashcode vif_key_hash_fn(void *k){
    VifKey *key = k;
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


/** Test equality for keys in the vif table.
 * Compares vnet and mac.
 *
 * @param k1 key to compare (VifKey)
 * @param k2 key to compare (VifKey)
 * @return 1 if equal, 0 otherwise
 */
int vif_key_equal_fn(void *k1, void *k2){
    VifKey *key1 = k1;
    VifKey *key2 = k2;
    return (key1->vnet == key2->vnet) && (memcmp(key1->vmac.mac, key2->vmac.mac, ETH_ALEN) == 0);
}

/** Free an entry in the vif table.
 *
 * @param table containing table
 * @param entry entry to free
 */
static void vif_entry_free_fn(HashTable *table, HTEntry *entry){
    Vif *vif;
    if(!entry) return;
    vif = entry->value;
    if(vif){
        vif_decref(vif);
    }
    HTEntry_free(entry);
}

/** Lookup a vif.
 *
 * @param vnet vnet id
 * @param mac MAC address
 * @return 0 on success, -ENOENT otherwise
 */
int vif_lookup(int vnet, Vmac *vmac, Vif **vif){
    int err = 0;
    VifKey key = {};
    HTEntry *entry = NULL;
    
    key.vnet = vnet;
    key.vmac = *vmac;
    entry = HashTable_get_entry(vif_table, &key);
    if(entry){
        *vif = entry->value;
        vif_incref(*vif);
    } else {
        *vif = NULL;
        err = -ENOENT;
    }
    //dprintf("< err=%d addr=" IPFMT "\n", err, NIPQUAD(*coaddr));
    return err;
}

/** Create a new vif.
 *
 * @param vnet vnet id
 * @param mac MAC address
 * @return 0 on success, negative error code otherwise
 */
int vif_add(int vnet, Vmac *vmac, Vif **val){
    int err = 0;
    Vif *vif = NULL;
    HTEntry *entry;
    dprintf("> vnet=%d\n", vnet);
    vif = ALLOCATE(Vif);
    if(!vif){
        err = -ENOMEM;
        goto exit;
    }
    atomic_set(&vif->refcount, 1);
    vif->vnet = vnet;
    vif->vmac = *vmac;
    entry = HashTable_add(vif_table, vif, vif);
    if(!entry){
        err = -ENOMEM;
        deallocate(vif);
        vif = NULL;
        goto exit;
    }
    vif_incref(vif);
  exit:
    *val = (err ? NULL : vif);
    dprintf("< err=%d\n", err);
    return err;
}

/** Delete an entry.
 *
 * @param vnet vnet id
 * @param mac MAC address
 * @param coaddr return parameter for care-of address
 * @return number of entries deleted, or negative error code
 */
int vif_remove(int vnet, Vmac *vmac){
    int err = 0;
    VifKey key = { .vnet = vnet, .vmac = *vmac };
    //dprintf("> vnet=%d addr=%u.%u.%u.%u\n", vnet, NIPQUAD(coaddr));
    err = HashTable_remove(vif_table, &key);
    //dprintf("< err=%d\n", err);
    return err;
}

int vif_find(int vnet, Vmac *vmac, int create, Vif **vif){
    int err = 0;

    err = vif_lookup(vnet, vmac, vif);
    if(err && create){
        err = vif_add(vnet, vmac, vif);
    }
    return err;
}

void vif_purge(void){
    HashTable_clear(vif_table);
}

int vif_create(int vnet, Vmac *vmac, Vif **vif){
    int err = 0;

    dprintf(">\n");
    if(!vif_lookup(vnet, vmac, vif)){
        err = -EEXIST;
        goto exit;
    }
    dprintf("> vif_add...\n");
    err = vif_add(vnet, vmac, vif);
  exit:
    if(err){
        *vif = NULL;
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Create a vif.
 *
 * @param vnet vnet id
 * @param mac mac address (as a string)
 * @return 0 on success, error code otherwise
 */
int mkvif(int vnet, char *mac){
    int err = 0;
    Vmac vmac = {};
    Vif *vif = NULL;
    dprintf("> vnet=%d mac=%s\n", vnet, mac);
    err = mac_aton(mac, vmac.mac);
    if(err) goto exit;
    err = vif_create(vnet, &vmac, &vif);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Initialize the vif table.
 *
 * @return 0 on success, error code otherwise
 */
int vif_init(void){
    int err = 0;
    dprintf(">\n");
    vif_table = HashTable_new(0);
    if(!vif_table){
        err = -ENOMEM;
        goto exit;
    }
    vif_table->entry_free_fn = vif_entry_free_fn;
    vif_table->key_hash_fn = vif_key_hash_fn;
    vif_table->key_equal_fn = vif_key_equal_fn;

    // Some vifs for testing.
    //mkvif(1, "aa:00:00:00:20:11");
    //mkvif(2, "aa:00:00:00:20:12");
  exit:
    if(err < 0) wprintf("< err=%d\n", err);
    dprintf("< err=%d\n", err);
    return err;
}

void vif_exit(void){
    HashTable_free(vif_table);
}
