#ifndef MINIOS_BYTEORDER_H
#define MINIOS_BYTEORDER_H

#include <mini-os/byteswap.h>
#include <mini-os/endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define be16_to_cpu(v) bswap_16(v)
#define be32_to_cpu(v) bswap_32(v)
#define be64_to_cpu(v) bswap_64(v)

#define le16_to_cpu(v) (v)
#define le32_to_cpu(v) (v)
#define le64_to_cpu(v) (v)

#else /*__BIG_ENDIAN*/
#define be16_to_cpu(v) (v)
#define be32_to_cpu(v) (v)
#define be64_to_cpu(v) (v)

#define le16_to_cpu(v) bswap_16(v)
#define le32_to_cpu(v) bswap_32(v)
#define le64_to_cpu(v) bswap_64(v)

#endif

#define cpu_to_be16(v) be16_to_cpu(v)
#define cpu_to_be32(v) be32_to_cpu(v)
#define cpu_to_be64(v) be64_to_cpu(v)

#define cpu_to_le16(v) le16_to_cpu(v)
#define cpu_to_le32(v) le32_to_cpu(v)
#define cpu_to_le64(v) le64_to_cpu(v)


#endif
