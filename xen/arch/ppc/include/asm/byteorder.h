#ifndef _ASM_PPC_BYTEORDER_H
#define _ASM_PPC_BYTEORDER_H

#define __arch__swab16 __builtin_bswap16
#define __arch__swab32 __builtin_bswap32
#define __arch__swab64 __builtin_bswap64

#define __BYTEORDER_HAS_U64__

#include <xen/byteorder/little_endian.h>

#endif /* _ASM_PPC_BYTEORDER_H */
