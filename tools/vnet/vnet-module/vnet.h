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
#ifndef __VNET_VNET_H__
#define __VNET_VNET_H__

#include <asm/atomic.h>
#include <linux/skbuff.h>

#include <tunnel.h>
#include <skb_context.h>

struct Vmac;
struct Vif;
struct net_device;

/** Vnet property record. */
typedef struct Vnet {
    /** Reference count. */
    atomic_t refcount;
    /** Vnet id. */
    struct VnetId vnet;
    /** Security flag. If true the vnet requires ESP. */
    int security;
    char device[IFNAMSIZ];

    struct net_device *dev;
    struct net_device *bridge;
    
    /** Max size of the header. */
    int header_n;
    /** Statistics. */
    struct net_device_stats stats;
    int recursion;
} Vnet;

extern void vnet_print(void);
extern void Vnet_print(Vnet *info);

extern int Vnet_lookup(struct VnetId *vnet, struct Vnet **info);
extern int Vnet_add(struct Vnet *info);
extern int Vnet_del(struct VnetId *vnet);
extern void Vnet_incref(struct Vnet *info);
extern void Vnet_decref(struct Vnet *info);
extern int Vnet_alloc(struct Vnet **info);
extern Vnet *vnet_physical;

extern int skb_xmit(struct sk_buff *skb);
extern int vnet_skb_send(struct sk_buff *skb, struct VnetId *vnet);
extern int vnet_skb_recv(struct sk_buff *skb, struct VnetId *vnet, struct Vmac *vmac);

extern int vnet_check_context(struct VnetId *vnet, SkbContext *context, Vnet **vinfo);

extern int vnet_tunnel_open(struct VnetId *vnet, struct VarpAddr *addr, Tunnel **tunnel);
extern int vnet_tunnel_lookup(struct VnetId *vnet, struct VarpAddr *addr, Tunnel **tunnel);
extern int vnet_tunnel_send(struct VnetId *vnet, struct VarpAddr *addr, struct sk_buff *skb);

extern int vnet_init(void);

extern int vnet_sa_security(u32 spi, int protocol, u32 addr);
struct SAState;
extern int vnet_sa_create(u32 spi, int protocol, u32 addr, struct SAState **sa);

enum {
    VNET_PHYS = 1,
    VNET_VIF = 2,
};

#endif /* !__VNET_VNET_H__ */
