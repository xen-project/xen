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
#ifndef _VNET_VIF_H_
#define _VNET_VIF_H_

#include <if_varp.h>
struct net_device;

/** Key for entries in the vif table. */
typedef struct VifKey {
    int vnet;
    Vmac vmac;
} VifKey;

typedef struct Vif {
    int vnet;
    Vmac vmac;
    struct net_device *dev;
    atomic_t refcount;
} Vif;

struct HashTable;
extern struct HashTable *vif_table;

extern void vif_decref(Vif *vif);
extern void vif_incref(Vif *vif);

extern int vif_create(int vnet, Vmac *vmac, Vif **vif);

extern int vif_add(int vnet, Vmac *vmac, Vif **vif);
extern int vif_lookup(int vnet, Vmac *vmac, Vif **vif);
extern int vif_remove(int vnet, Vmac *vmac);
extern int vif_find(int vnet, Vmac *vmac, int create, Vif **vif);
extern void vif_purge(void);

extern int vif_init(void);
extern void vif_exit(void);

#endif
