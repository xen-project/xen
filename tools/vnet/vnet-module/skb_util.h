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
#ifndef _VNET_SKB_UTIL_H_
#define _VNET_SKB_UTIL_H_

#include <net/route.h>
#include <linux/skbuff.h>

struct scatterlist;

extern int skb_make_room(struct sk_buff **pskb, struct sk_buff *skb, int head_n, int tail_n);

extern int skb_put_bits(const struct sk_buff *skb, int offset, void *src, int len);

extern int pskb_put(struct sk_buff *skb, int n);

extern void skb_print_bits(struct sk_buff *skb, int offset, int n);

extern void buf_print(char *buf, int n);

extern void *skb_trim_tail(struct sk_buff *skb, int n);

extern int skb_scatterlist(struct sk_buff *skb, struct scatterlist *sg,
                           int *sg_n, int offset, int len);

extern void print_skb_data(char *msg, int count, struct sk_buff *skb, u8 *data, int len);


/* The mac.ethernet field went away in 2.6 in favour of eth_hdr().
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#else
static inline struct ethhdr *eth_hdr(const struct sk_buff *skb)
{
	return (struct ethhdr *)skb->mac.raw;
}
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

static inline int skb_route(struct sk_buff *skb, struct rtable **prt){
    int err = 0;
    struct flowi fl = {
        .nl_u = {
            .ip4_u = {
                .daddr = skb->nh.iph->daddr,
                .saddr = skb->nh.iph->saddr,
                .tos   = skb->nh.iph->tos,
            }
        }
    };
    
    if(skb->dev){
        fl.oif = skb->dev->ifindex;
    }
    err = ip_route_output_key(prt, &fl);
    return err;
}

#else

static inline int skb_route(struct sk_buff *skb, struct rtable **prt){
    int err = 0;
    struct rt_key key = { };
    key.dst = skb->nh.iph->daddr;
    key.src = skb->nh.iph->saddr;
    key.tos = skb->nh.iph->tos;
    if(skb->dev){
        key.oif = skb->dev->ifindex;
    }
    err = ip_route_output_key(prt, &key);
    return err;
}

#endif

#endif
