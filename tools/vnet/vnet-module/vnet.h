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

typedef uint32_t vnetid_t;
typedef uint32_t vnetaddr_t;

/** Vnet property record. */
typedef struct Vnet {
    /** Reference count. */
    atomic_t refcount;
    /** Vnet id. */
    vnetid_t vnet;
    /** Security flag. If true the vnet requires ESP. */
    int security;

    struct net_device *dev;
    struct net_device *bridge;
    
    /** Max size of the header. */
    int header_n;
    /** Statistics. */
    struct net_device_stats stats;
    int recursion;
} Vnet;

extern int Vnet_lookup(vnetid_t id, Vnet **vnet);
extern int Vnet_add(Vnet *vnet);
extern int Vnet_del(vnetid_t vnet);
extern void Vnet_incref(Vnet *);
extern void Vnet_decref(Vnet *);
extern int Vnet_alloc(Vnet **vnet);
extern Vnet *vnet_physical;

extern int skb_xmit(struct sk_buff *skb);
extern int vnet_skb_send(struct sk_buff *skb, u32 vnet);
extern int vnet_skb_recv(struct sk_buff *skb, u32 vnet, struct Vmac *vmac);

extern int vnet_check_context(int vnet, SkbContext *context, Vnet **vinfo);

extern int vnet_tunnel_open(vnetid_t vnet, vnetaddr_t addr, Tunnel **tunnel);
extern int vnet_tunnel_lookup(vnetid_t vnet, vnetaddr_t addr, Tunnel **tunnel);
extern int vnet_tunnel_send(vnetid_t vnet, vnetaddr_t addr, struct sk_buff *skb);

extern int vnet_init(void);

enum {
    HANDLE_OK = 1,
    HANDLE_NO = 0,
};

extern int vnet_sa_security(u32 spi, int protocol, u32 addr);
struct SAState;
extern int vnet_sa_create(u32 spi, int protocol, u32 addr, struct SAState **sa);

enum {
    VNET_PHYS = 1,
    VNET_VIF = 2,
};

#endif /* !__VNET_VNET_H__ */
