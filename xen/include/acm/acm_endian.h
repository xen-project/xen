/****************************************************************
 * acm_endian.h 
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Stefan Berger <stefanb@watson.ibm.com>
 * 
 * Contributions:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype header file defining endian-dependent functions for the
 * big-endian policy interface
 *
 */
#ifndef _ACM_ENDIAN_H
#define _ACM_ENDIAN_H

/* don't use these functions in performance critical sections! */

/* set during initialization by testing */
extern u8 little_endian;

static inline u32 ntohl(u32 x) 
{
    if (little_endian)
        return 
	    ( (((x) >> 24) & 0xff      )| 
	      (((x) >>  8) & 0xff00    )| 
	      (((x) <<  8) & 0xff0000  )|
	      (((x) << 24) & 0xff000000) );
    else
        return x;
}

static inline u16 ntohs(u16 x) 
{
    if (little_endian)
        return 
	    ( (((x) >> 8) & 0xff   )|
	      (((x) << 8) & 0xff00 ) );
    else
	return x;
}

#define htonl(x) ntohl(x)
#define htons(x) ntohs(x)

static inline void arrcpy16(u16 *dest, const u16 *src, size_t n)
{
    unsigned int i = 0;
    while (i < n) {
       	dest[i] = htons(src[i]);
       	i++;
    }
}

static inline void arrcpy32(u32 *dest, const u32 *src, size_t n)
{
    unsigned int i = 0;
    while (i < n) {
	dest[i] = htonl(src[i]);
	i++;
    }
}

static inline void arrcpy(void *dest, const void *src, unsigned int elsize, size_t n)
{
    switch (elsize) {
    case sizeof(u16):
        arrcpy16((u16 *)dest, (u16 *)src, n);
        break;

    case sizeof(u32):
        arrcpy32((u32 *)dest, (u32 *)src, n);
        break;

    default:
        memcpy(dest, src, elsize*n);
    }
}

#endif
