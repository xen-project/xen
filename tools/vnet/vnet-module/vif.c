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

#include <etherip.h>
#include <if_varp.h>
#include <vnet_dev.h>
#include <vif.h>
#include <varp.h>

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
rwlock_t vif_table_lock = RW_LOCK_UNLOCKED;

#define vif_read_lock(flags)    read_lock_irqsave(&vif_table_lock, (flags))
#define vif_read_unlock(flags)  read_unlock_irqrestore(&vif_table_lock, (flags))
#define vif_write_lock(flags)   write_lock_irqsave(&vif_table_lock, (flags))
#define vif_write_unlock(flags) write_unlock_irqrestore(&vif_table_lock, (flags))

void vif_print(void){
    HashTable_for_decl(entry);
    Vif *vif;
    unsigned long flags;
    char vnetbuf[VNET_ID_BUF];

    vif_read_lock(flags);
    HashTable_for_each(entry, vif_table){
        vif = entry->value;
        printk(KERN_INFO "VIF(vnet=%s vmac=" MACFMT ")\n",
               VnetId_ntoa(&vif->vnet, vnetbuf), MAC6TUPLE(vif->vmac.mac));
    }
    vif_read_unlock(flags);
}

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
    Hashcode h = 0;
    h = VnetId_hash(h, &key->vnet);
    h = Vmac_hash(h, &key->vmac);
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
    return (VnetId_eq(&key1->vnet , &key2->vnet) &&
            Vmac_eq(&key1->vmac, &key2->vmac));
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
int vif_lookup(VnetId *vnet, Vmac *vmac, Vif **vif){
    int err = 0;
    VifKey key = { .vnet = *vnet, .vmac = *vmac };
    HTEntry *entry = NULL;
    unsigned long flags;
    
    vif_read_lock(flags);
    entry = HashTable_get_entry(vif_table, &key);
    if(entry){
        *vif = entry->value;
        vif_incref(*vif);
    } else {
        *vif = NULL;
        err = -ENOENT;
    }
    vif_read_unlock(flags);
    return err;
}

/** Create a new vif.
 *
 * @param vnet vnet id
 * @param mac MAC address
 * @return 0 on success, negative error code otherwise
 */
int vif_add(VnetId *vnet, Vmac *vmac, Vif **val){
    int err = 0;
    Vif *vif = NULL;
    HTEntry *entry;
    unsigned long flags;

    dprintf("> vnet=%d\n", vnet);
    vif = ALLOCATE(Vif);
    if(!vif){
        err = -ENOMEM;
        goto exit;
    }
    atomic_set(&vif->refcount, 1);
    vif->vnet = *vnet;
    vif->vmac = *vmac;
    vif_write_lock(flags);
    entry = HashTable_add(vif_table, vif, vif);
    vif_write_unlock(flags);
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
int vif_remove(VnetId *vnet, Vmac *vmac){
    int err = 0;
    VifKey key = { .vnet = *vnet, .vmac = *vmac };
    unsigned long flags;

    vif_write_lock(flags);
    err = HashTable_remove(vif_table, &key);
    vif_write_unlock(flags);
    return err;
}

void vif_purge(void){
    HashTable_clear(vif_table);
}

int vif_create(VnetId *vnet, Vmac *vmac, Vif **vif){
    int err = 0;

    dprintf(">\n");
    if(vif_lookup(vnet, vmac, vif) == 0){
        vif_decref(*vif);
        err = -EEXIST;
        goto exit;
    }
    err = vif_add(vnet, vmac, vif);
  exit:
    if(err){
        *vif = NULL;
    }
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
    vif_table->key_hash_fn   = vif_key_hash_fn;
    vif_table->key_equal_fn  = vif_key_equal_fn;

  exit:
    if(err < 0) wprintf("< err=%d\n", err);
    dprintf("< err=%d\n", err);
    return err;
}

void vif_exit(void){
    HashTable_free(vif_table);
}
