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

struct sk_buff;
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


#endif
