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

#ifndef _VNET_IF_VARP_H
#define _VNET_IF_VARP_H

typedef struct Vmac {
    unsigned char mac[ETH_ALEN];
} Vmac;

enum {
    VARP_ID          = 1,
    VARP_OP_REQUEST  = 1,
    VARP_OP_ANNOUNCE = 2,
};

typedef struct VnetMsgHdr {
    uint16_t id;
    uint16_t opcode;
} __attribute__((packed)) VnetMsgHdr;

typedef struct VarpHdr {
    VnetMsgHdr;
    uint32_t vnet;
    Vmac vmac;
    uint32_t addr;
} __attribute__((packed)) VarpHdr;

/** Default address for varp/vnet broadcasts: 224.10.0.1 */
#define VARP_MCAST_ADDR     0xe00a0001

/** UDP port to use for varp protocol. */
#define VARP_PORT           1798



#endif /* ! _VNET_IF_VARP_H */
