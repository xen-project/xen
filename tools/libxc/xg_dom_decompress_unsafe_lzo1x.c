#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <endian.h>
#include <stdint.h>

#include "xg_private.h"
#include "xc_dom_decompress_unsafe.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;

#define likely(a) a
#define noinline
#define unlikely(a) a

static inline u16 be16_to_cpup(const u16 *p)
{
	u16 v = *p;
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((v & 0x00ffU) << 8) |
                ((v & 0xff00U) >> 8));
#else
	return v;
#endif
}

static inline u32 be32_to_cpup(const u32 *p)
{
	u32 v = *p;
#if BYTE_ORDER == LITTLE_ENDIAN
	return (((v & 0x000000ffUL) << 24) |
                ((v & 0x0000ff00UL) <<  8) |
                ((v & 0x00ff0000UL) >>  8) |
                ((v & 0xff000000UL) >> 24));
#else
	return v;
#endif
}

#include "../../xen/common/lzo.c"
#include "../../xen/common/unlzo.c"

int xc_try_lzo1x_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unlzo, dom, blob, size);
}
