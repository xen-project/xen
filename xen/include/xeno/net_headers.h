/*
 * net_headers.h
 *
 * This is a compilation of various network headers, to facilitate
 * access in Xen, which is generally quite simple and doesn't need
 * all the bloat of extra defines and so on.
 *
 * Pretty much everything here is pulled from ip.h, tcp.h, and if_eth.h
 *
 * Reduced, congealed, and otherwise munged by akw. 
 * 
 * Original authors:
 * 
 *    Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG> (ip.h, tcp.h, udp.h)
 *
 *    (if_arp.h):
 *    Original taken from Berkeley UNIX 4.3, (c) UCB 1986-1988
 *    Portions taken from the KA9Q/NOS (v2.00m PA0GRI) source.
 *    Ross Biro, <bir7@leland.Stanford.Edu>
 *    Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *    Florian La Roche,
 *    Jonathan Layes <layes@loran.com>
 *    Arnaldo Carvalho de Melo <acme@conectiva.com.br> ARPHRD_HWX25
 *
 * Original legalese:
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    as published by the Free Software Foundation; either version
 *    2 of the License, or (at your option) any later version.
 */

#ifndef __NET_HEADERS_H__
#define __NET_HEADERS_H__

#include <xeno/types.h>
#include <asm/byteorder.h>
#include <xeno/if_ether.h> 

/* from ip.h */

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;
    __u16   tot_len;
    __u16   id;
    __u16   frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __u32   saddr;
    __u32   daddr;
    /*The options start here. */
};

/* from tcp.h */

struct tcphdr {
    __u16   source;
    __u16   dest;
    __u32   seq;
    __u32   ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __u16   window;
    __u16   check;
    __u16   urg_ptr;
};

/* From udp.h */

struct udphdr {
    __u16   source;
    __u16   dest;
    __u16   len;
    __u16   check;
};

/* from if_arp.h */

struct arphdr
{
    __u16   ar_hrd;                      /* format of hardware address    */
    __u16   ar_pro;                      /* format of protocol address    */
    __u8    ar_hln;                      /* length of hardware address    */
    __u8    ar_pln;                      /* length of protocol address    */
    __u16   ar_op;                       /* ARP opcode (command)          */

    /* This next bit is variable sized, and as coded only allows ETH-IPv4 */
    __u8    ar_sha[ETH_ALEN];            /* sender hardware address       */
    __u32   ar_sip;                      /* sender IP address             */
    __u8    ar_tha[ETH_ALEN];            /* target hardware address       */
    __u32   ar_tip;                      /* target IP address             */
};


#endif /* __NET_HEADERS_H__ */
