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
#ifndef _VNET_IF_ETHERIP_H_
#define _VNET_IF_ETHERIP_H_
/*----------------------------------------------------------------------------*/
#ifdef CONFIG_ETHERIP_EXT
struct etheriphdr {
    __u8 version;
    __u32 vnet;
} __attribute__ ((packed));

/*----------------------------------------------------------------------------*/
#else
struct etheriphdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16    reserved:12,
             version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u16    version:4,
            reserved:12;
#else
#error  "Please fix <asm/byteorder.h>"
#endif

};
#endif

#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP 97
#endif

/*----------------------------------------------------------------------------*/

#endif /* ! _VNET_IF_ETHERIP_H_ */
