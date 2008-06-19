#ifndef __OSDEP_H__
#define __OSDEP_H__

#include <byteswap.h>
#define swap32(x) bswap_32(x)
#define swap16(x) bswap_16(x)

#include <machine/endian.h>
#if BYTE_ORDER == BIG_ENDIAN
#define htons(x) (x)
#define ntohs(x) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#else
#define htons(x) swap16(x)
#define ntohs(x) swap16(x)
#define htonl(x) swap32(x)
#define ntohl(x) swap32(x)
#endif

typedef unsigned long Address;

/* ANSI prototyping macro */
#ifdef  __STDC__
#define P(x)	x
#else
#define P(x)	()
#endif

#endif
