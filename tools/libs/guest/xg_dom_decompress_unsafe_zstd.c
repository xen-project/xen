#include <stdio.h>
#include INCLUDE_ENDIAN_H
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xg_dom_decompress_unsafe.h"

typedef uint8_t u8;

typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;

typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

#define attr_const
#define __force
#define always_inline
#define noinline
#define __packed __attribute__((__packed__))

#undef ERROR

#define __BYTEORDER_HAS_U64__
#define __TYPES_H__ /* xen/types.h guard */
#include "../../xen/include/xen/byteorder/little_endian.h"
#include "../../xen/include/xen/unaligned.h"
#include "../../xen/include/xen/xxhash.h"
#include "../../xen/lib/xxhash64.c"
#include "../../xen/common/unzstd.c"

int xc_try_zstd_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unzstd, dom, blob, size);
}
