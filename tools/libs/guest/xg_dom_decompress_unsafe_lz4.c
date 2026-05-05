#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>

#include INCLUDE_ENDIAN_H

#define XG_NEED_UNALIGNED
#include "xg_private.h"
#include "xg_dom_decompress.h"

#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define likely(a) a
#define unlikely(a) a

static inline uint16_t le16_to_cpu(uint16_t v)
{
#if BYTE_ORDER == BIG_ENDIAN
    return __builtin_bswap16(v);
#else
    return v;
#endif
}

#include "../../xen/include/xen/lz4.h"
#include "../../xen/common/decompress.h"
#include "../../xen/common/unlz4.c"

int xc_try_lz4_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unlz4, dom, blob, size);
}
