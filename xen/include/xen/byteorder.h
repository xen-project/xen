/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef XEN_BYTEORDER_H
#define XEN_BYTEORDER_H

#include <xen/byteswap.h>
#include <xen/stdint.h>

#if defined(__LITTLE_ENDIAN)

# define cpu_to_le64(x) ((uint64_t)(x))
# define le64_to_cpu(x) ((uint64_t)(x))
# define cpu_to_le32(x) ((uint32_t)(x))
# define le32_to_cpu(x) ((uint32_t)(x))
# define cpu_to_le16(x) ((uint16_t)(x))
# define le16_to_cpu(x) ((uint16_t)(x))

# define cpu_to_be64(x) bswap64(x)
# define be64_to_cpu(x) bswap64(x)
# define cpu_to_be32(x) bswap32(x)
# define be32_to_cpu(x) bswap32(x)
# define cpu_to_be16(x) bswap16(x)
# define be16_to_cpu(x) bswap16(x)

#elif defined(__BIG_ENDIAN)

# define cpu_to_le64(x) bswap64(x)
# define le64_to_cpu(x) bswap64(x)
# define cpu_to_le32(x) bswap32(x)
# define le32_to_cpu(x) bswap32(x)
# define cpu_to_le16(x) bswap16(x)
# define le16_to_cpu(x) bswap16(x)

# define cpu_to_be64(x) ((uint64_t)(x))
# define be64_to_cpu(x) ((uint64_t)(x))
# define cpu_to_be32(x) ((uint32_t)(x))
# define be32_to_cpu(x) ((uint32_t)(x))
# define cpu_to_be16(x) ((uint16_t)(x))
# define be16_to_cpu(x) ((uint16_t)(x))

#else
# error Unknown Endianness
#endif /* __*_ENDIAN */

#endif /* XEN_BYTEORDER_H */
