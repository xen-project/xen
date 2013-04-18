#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom_decompress_unsafe.h"

// TODO
#define XZ_DEC_X86

typedef char bool_t;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint32_t __le32;

static inline u32 cpu_to_le32(const u32 v)
{
#if BYTE_ORDER == BIG_ENDIAN
	return (((v & 0x000000ffUL) << 24) |
	        ((v & 0x0000ff00UL) <<  8) |
	        ((v & 0x00ff0000UL) >>  8) |
	        ((v & 0xff000000UL) >> 24));
#else
	return v;
#endif
}

static inline u32 le32_to_cpup(const u32 *p)
{
	return cpu_to_le32(*p);
}

#define min(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x < _y ? _x : _y; })

#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

#define __force
#define always_inline

#include "../../xen/common/unxz.c"

int xc_try_xz_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unxz, dom, blob, size);
}
