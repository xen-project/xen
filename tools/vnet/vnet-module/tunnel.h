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
#ifndef __VNET_TUNNEL_H__
#define __VNET_TUNNEL_H__

#include <linux/types.h>
#include <linux/slab.h>
#include <asm/atomic.h>

struct sk_buff;
struct Tunnel;

typedef struct TunnelType {
    const char *name;
    int (*open)(struct Tunnel *tunnel);
    int (*send)(struct Tunnel *tunnel, struct sk_buff *skb);
    void (*close)(struct Tunnel *tunnel);
} TunnelType;

typedef struct TunnelStats {
    int bytes;
    int packets;
    int dropped_bytes;
    int dropped_packets;
} TunnelStats;

typedef struct TunnelKey {
    u32 vnet;
    u32 addr;
} TunnelKey;

typedef struct Tunnel {
    /** Key identifying the tunnel. Must be first. */
    struct TunnelKey key;
    /** Reference count. */
    atomic_t refcount;
    /** Tunnel type. */
    struct TunnelType *type;
    /** Statistics. */
    struct TunnelStats send_stats;
    /** Type-dependent state. */
    void *data;
    /** Underlying tunnel (may be null). */
    struct Tunnel *base;
} Tunnel;

extern void Tunnel_print(Tunnel *tunnel);

/** Decrement the reference count, freeing if zero.
 *
 * @param tunnel tunnel (may be null)
 */
static inline void Tunnel_decref(Tunnel *tunnel){
    if(!tunnel) return;
    if(atomic_dec_and_test(&tunnel->refcount)){
        printk("%s> Closing tunnel:\n", __FUNCTION__);
        Tunnel_print(tunnel);
        tunnel->type->close(tunnel);
        Tunnel_decref(tunnel->base);
        kfree(tunnel);
    }
}

/** Increment the reference count.
 *
 * @param tunnel tunnel (may be null)
 */
static inline void Tunnel_incref(Tunnel *tunnel){
    if(!tunnel) return;
    atomic_inc(&tunnel->refcount);
}

extern int Tunnel_init(void);
extern Tunnel * Tunnel_lookup(u32 vnet, u32 addr);
extern int Tunnel_add(Tunnel *tunnel);
extern int Tunnel_del(Tunnel *tunnel);
extern int Tunnel_send(Tunnel *tunnel, struct sk_buff *skb);

extern int Tunnel_create(TunnelType *type, u32 vnet, u32 addr, Tunnel *base, Tunnel **tunnelp);
extern int Tunnel_open(TunnelType *type, u32 vnet, u32 addr, Tunnel *base, Tunnel **tunnelp);

extern int tunnel_module_init(void);
extern void tunnel_module_exit(void);

#endif /* !__VNET_TUNNEL_H__ */
