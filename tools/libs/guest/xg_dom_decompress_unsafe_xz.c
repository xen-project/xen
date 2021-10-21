#include <stdio.h>
#include INCLUDE_ENDIAN_H
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xg_dom_decompress_unsafe.h"

// TODO
#define XZ_DEC_X86

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint32_t __le32;

static inline uint32_t cpu_to_le32(const uint32_t v)
{
#if BYTE_ORDER == BIG_ENDIAN
	return __builtin_bswap32(v);
#else
	return v;
#endif
}

static inline uint32_t le32_to_cpu(const uint32_t p)
{
#if BYTE_ORDER == BIG_ENDIAN
	return __builtin_bswap32(v);
#else
	return v;
#endif
}

#define __force
#define always_inline

#include "../../xen/common/unxz.c"

int xc_try_xz_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unxz, dom, blob, size);
}
