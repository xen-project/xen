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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/version.h>

#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>

#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/checksum.h>

#include <etherip.h>
#include <tunnel.h>
#include <vnet.h>
#include <varp.h>
#include <if_varp.h>
#include <skb_util.h>

#define MODULE_NAME "VNET"
//#define DEBUG 1
#undef DEBUG
#include "debug.h"

/** @file Etherip implementation.
 * The etherip protocol is used to transport Ethernet frames in IP packets.
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define MAC_ETH(_skb) ((struct ethhdr *)(_skb)->mac.raw)
#else
#define MAC_ETH(_skb) ((_skb)->mac.ethernet)
#endif

/** Get the vnet label from an etherip header.
 *
 * @param hdr header
 * @return vnet (in host order)
 */
int etheriphdr_get_vnet(struct etheriphdr *hdr){
#ifdef CONFIG_ETHERIP_EXT
    return ntohl(hdr->vnet);
#else
    return hdr->reserved;
#endif
}

/** Set the vnet label in an etherip header.
 * Also sets the etherip version.
 *
 * @param hdr header
 * @param vnet vnet label (in host order)
 */
void etheriphdr_set_vnet(struct etheriphdr *hdr, int vnet){
#ifdef CONFIG_ETHERIP_EXT
    hdr->version = 4;
    hdr->vnet = htonl(vnet);
#else
    hdr->version = 3;
    hdr->reserved = vnet & 0x0fff;
#endif
}

/** Open an etherip tunnel.
 *
 * @param tunnel to open
 * @return 0 on success, error code otherwise
 */
static int etherip_tunnel_open(Tunnel *tunnel){
    return 0;
}

/** Close an etherip tunnel.
 *
 * @param tunnel to close
 */
static void etherip_tunnel_close(Tunnel *tunnel){
}


/** Send a packet via an etherip tunnel.
 * Adds etherip header, new ip header, new ethernet header around
 * ethernet frame.
 *
 * @param tunnel tunnel
 * @param skb packet
 * @return 0 on success, error code otherwise
 */
static int etherip_tunnel_send(Tunnel *tunnel, struct sk_buff *skb){
    int err = 0;
    const int etherip_n = sizeof(struct etheriphdr);
    const int ip_n = sizeof(struct iphdr);
    const int eth_n = ETH_HLEN;
    int head_n = 0;
    int vnet = tunnel->key.vnet;
    struct etheriphdr *etheriph;
    struct ethhdr *ethh;
    u32 saddr = 0;

    dprintf("> skb=%p vnet=%d\n", skb, vnet);
    head_n = etherip_n + ip_n + eth_n;
    err = skb_make_room(&skb, skb, head_n, 0);
    if(err) goto exit;

    //err = vnet_get_device_address(skb->dev, &saddr);
    //if(err) goto exit;
    
    // The original ethernet header.
    ethh = MAC_ETH(skb);
    //print_skb_data(__FUNCTION__, 0, skb, skb->mac.raw, skb->len);
    // Null the pointer as we are pushing a new IP header.
    skb->mac.raw = NULL;

    // Setup the etherip header.
    //dprintf("> push etherip header...\n");
    etheriph = (struct etheriphdr *)skb_push(skb, etherip_n);
    etheriphdr_set_vnet(etheriph, vnet);

    // Setup the IP header.
    //dprintf("> push IP header...\n");
    skb->nh.raw = skb_push(skb, ip_n); 
    skb->nh.iph->version  = 4;			// Standard version.
    skb->nh.iph->ihl      = ip_n / 4;		// IP header length (32-bit words).
    skb->nh.iph->tos      = 0;			// No special type-of-service.
    skb->nh.iph->tot_len  = htons(skb->len);    // Total packet length (bytes).
    skb->nh.iph->id       = 0;			// No flow id (since no frags).
    skb->nh.iph->frag_off = htons(IP_DF);	// Don't fragment - can't handle frags.
    skb->nh.iph->ttl      = 64;			// Linux default time-to-live.
    skb->nh.iph->protocol = IPPROTO_ETHERIP;    // IP protocol number.
    skb->nh.iph->saddr    = saddr;		// Source address.
    skb->nh.iph->daddr    = tunnel->key.addr;	// Destination address.
    skb->nh.iph->check    = 0;

    // Ethernet header will be filled-in by device.
    err = Tunnel_send(tunnel->base, skb);
    skb = NULL;
  exit:
    if(err && skb) dev_kfree_skb(skb);
    //dprintf("< err=%d\n", err);
    return err;
}

/** Tunnel type for etherip.
 */
static TunnelType _etherip_tunnel_type = {
    .name	= "ETHERIP",
    .open	= etherip_tunnel_open,
    .close	= etherip_tunnel_close,
    .send 	= etherip_tunnel_send
};

TunnelType *etherip_tunnel_type = &_etherip_tunnel_type;

/* Defeat compiler warnings about unused functions. */
static void print_str(char *s, int n) __attribute__((unused));

static void print_str(char *s, int n) {
    int i;

    for(i=0; i<n; s++, i++){
        if(i && i % 40 == 0) printk("\n");
        if(('a'<= *s && *s <= 'z') ||
           ('A'<= *s && *s <= 'Z') ||
           ('0'<= *s && *s <= '9')){
            printk("%c", *s);
        } else {
            printk("<%x>", (unsigned)(0xff & *s));
        }
    }
    printk("\n");
}

/** Do etherip receive processing.
 * Strips etherip header to extract the ethernet frame, sets
 * the vnet from the header and re-receives the frame.
 *
 * @param skb packet
 * @return 0 on success, error code otherwise
 */
static int etherip_protocol_recv(struct sk_buff *skb){
    int err = 0;
    int mine = 0;
    const int eth_n = ETH_HLEN;
    int ip_n;
    const int etherip_n = sizeof(struct etheriphdr);
    struct etheriphdr *etheriph;
    struct ethhdr *ethhdr;
    Vnet *vinfo = NULL;
    u32 vnet;

    ethhdr = MAC_ETH(skb);
    if(MULTICAST(skb->nh.iph->daddr) &&
       (skb->nh.iph->daddr != varp_mcast_addr)){
        // Ignore multicast packets not addressed to us.
        dprintf("> dst=%u.%u.%u.%u varp_mcast_addr=%u.%u.%u.%u\n",
                NIPQUAD(skb->nh.iph->daddr),
                NIPQUAD(varp_mcast_addr));
        goto exit;
    }
    ip_n = (skb->nh.iph->ihl << 2);
    if(skb->data == skb->mac.raw){
        // skb->data points at ethernet header.
        //dprintf("> len=%d\n", skb->len);
        if (!pskb_may_pull(skb, eth_n + ip_n)){
            wprintf("> Malformed skb\n");
            err = -EINVAL;
            goto exit;
        }
        skb_pull(skb, eth_n + ip_n);
    }
    // Assume skb->data points at etherip header.
    etheriph = (void*)skb->data;
    if(!pskb_may_pull(skb, etherip_n)){
        wprintf("> Malformed skb\n");
        err = -EINVAL;
        goto exit;
    }
    vnet = etheriphdr_get_vnet(etheriph);
    dprintf("> Rcvd skb=%p vnet=%d\n", skb, vnet);
    // If vnet is secure, context must include IPSEC ESP.
    err = vnet_check_context(vnet, SKB_CONTEXT(skb), &vinfo);
    Vnet_decref(vinfo);
    if(err){
        wprintf("> Failed security check\n");
        goto exit;
    }
    mine = 1;
    // Point at the headers in the contained ethernet frame.
    skb->mac.raw = skb_pull(skb, etherip_n);

    // Know source ip, vnet, vmac, so could update varp cache.
    // But if traffic comes to us over a vnetd tunnel this points the coa
    // at the vnetd rather than the endpoint. So don't do it.
    //varp_update(htonl(vnet), MAC_ETH(skb)->h_source, skb->nh.iph->saddr);

    // Assuming a standard Ethernet frame.
    skb->nh.raw = skb_pull(skb, ETH_HLEN);

#ifdef CONFIG_NETFILTER
#if defined(CONFIG_BRIDGE) || defined(CONFIG_BRIDGE_MODULE)
    // This stops our new pkt header being clobbered by a subsequent
    // call to nf_bridge_maybe_copy_header. Just replicate the
    // corresponding nf_bridge_save_header.
    if(skb->nf_bridge){
        int header_size = 16;
        if(MAC_ETH(skb)->h_proto == __constant_htons(ETH_P_8021Q)) {
            header_size = 18;
        }
        memcpy(skb->nf_bridge->data, skb->data - header_size, header_size);
    }
#endif
#endif
    
    if(1){
	struct ethhdr *eth = MAC_ETH(skb);
        // Devices use eth_type_trans() to set skb->pkt_type and skb->protocol.
        // Set them from contained ethhdr, or leave as received?
        // 'Ware use of hard_header_len in eth_type_trans().

        //skb->protocol = htons(ETH_P_IP);

        if(ntohs(eth->h_proto) >= 1536){
            skb->protocol = eth->h_proto;
        } else {
            skb->protocol = htons(ETH_P_802_2);
        }
        
	if(mac_is_multicast(eth->h_dest)){
            if(mac_is_broadcast(eth->h_dest)){
                skb->pkt_type = PACKET_BROADCAST;
	    } else {
                skb->pkt_type = PACKET_MULTICAST;
            }
        } else {
            skb->pkt_type = PACKET_HOST;
	}

        memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
        if (skb->ip_summed == CHECKSUM_HW){
            skb->ip_summed = CHECKSUM_NONE;
            //skb->csum = csum_sub(skb->csum,
            //                     csum_partial(skb->mac.raw, skb->nh.raw - skb->mac.raw, 0));
        }
        dst_release(skb->dst);
        skb->dst = NULL;
#ifdef CONFIG_NETFILTER
        nf_conntrack_put(skb->nfct);
        skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
        skb->nf_debug = 0;
#endif
#endif
    }

    //print_skb_data(__FUNCTION__, 0, skb, skb->mac.raw, skb->len + ETH_HLEN);

    err = vnet_skb_recv(skb, vnet, (Vmac*)MAC_ETH(skb)->h_dest);
  exit:
    if(mine) err = 1;
    dprintf("< skb=%p err=%d\n", skb, err);
    return err;
}

/** Handle an ICMP error related to etherip.
 *
 * @param skb ICMP error packet
 * @param info
 */
static void etherip_protocol_icmp_err(struct sk_buff *skb, u32 info){
    struct iphdr *iph = (struct iphdr*)skb->data;
    
    wprintf("> ICMP error type=%d code=%d addr=" IPFMT "\n",
            skb->h.icmph->type, skb->h.icmph->code, NIPQUAD(iph->daddr));

    if (skb->h.icmph->type != ICMP_DEST_UNREACH ||
        skb->h.icmph->code != ICMP_FRAG_NEEDED){
        return;
    }
    wprintf("> MTU too big addr= " IPFMT "\n", NIPQUAD(iph->daddr)); 
}

//============================================================================
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
// Code for 2.6 kernel.

/** Etherip protocol. */
static struct net_protocol etherip_protocol = {
    .handler	 = etherip_protocol_recv,
    .err_handler = etherip_protocol_icmp_err,
};

static int etherip_protocol_add(void){
    return inet_add_protocol(&etherip_protocol, IPPROTO_ETHERIP);
}

static int etherip_protocol_del(void){
    return inet_del_protocol(&etherip_protocol, IPPROTO_ETHERIP);
}

//============================================================================
#else
//============================================================================
// Code for 2.4 kernel.

/** Etherip protocol. */
static struct inet_protocol etherip_protocol = {
    .name        = "ETHERIP",
    .protocol    = IPPROTO_ETHERIP,
    .handler	 = etherip_protocol_recv,
    .err_handler = etherip_protocol_icmp_err,
};

static int etherip_protocol_add(void){
    inet_add_protocol(&etherip_protocol);
    return 0;
}

static int etherip_protocol_del(void){
    return inet_del_protocol(&etherip_protocol);
}

#endif
//============================================================================


/** Initialize the etherip module.
 * Registers the etherip protocol.
 *
 * @return 0 on success, error code otherwise
 */
int __init etherip_module_init(void) {
    int err = 0;
    etherip_protocol_add();
    return err;
}

/** Finalize the etherip module.
 * Deregisters the etherip protocol.
 */
void __exit etherip_module_exit(void) {
    if(etherip_protocol_del() < 0){
        printk(KERN_INFO "%s: can't remove etherip protocol\n", __FUNCTION__);
    }
}
