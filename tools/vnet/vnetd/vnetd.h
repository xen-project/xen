/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or  (at your option) any later version. This library is 
 * distributed in the  hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#ifndef _VNET_VNETD_H_
#define _VNET_VNETD_H_

#include <asm/types.h>
#include <linux/if_ether.h>
#include "if_varp.h"

#include "connection.h"
#include "sxpr.h"

/** Vnetd udp port in host order. */
#define VNETD_PORT VARP_PORT

/** Vnetd peer port in host order. */
#define VNETD_PEER_PORT (VARP_PORT + 1)

typedef struct VnetMsgVarp {
    VarpHdr varph;
} VnetMsgVarp;

#define VNET_FWD_MAX (1500 + 200)

typedef struct VnetMsgFwd {
    VnetMsgHdr;
    uint16_t protocol;
    uint16_t len;
    uint8_t data[VNET_FWD_MAX];
} __attribute__((packed)) VnetMsgFwd;

typedef union VnetMsg {
    VnetMsgHdr hdr;
    VnetMsgVarp varp;
    VnetMsgFwd fwd;
} VnetMsg;

enum {
    VNET_VARP_ID = VARP_ID,
    VNET_FWD_ID  = 200,
};

typedef struct Vnetd {
    unsigned long port;
    unsigned long peer_port;
    int verbose;

    int esp_sock;
    int etherip_sock;

    struct sockaddr_in addr;
    struct sockaddr_in mcast_addr;

    Sxpr peers;

    Conn *listen_conn;
    Conn *udp_conn;
    Conn *bcast_conn;
    
    ConnList *connections;

} Vnetd;

extern Vnetd *vnetd;

#endif /* ! _VNET_VNETD_H_ */
