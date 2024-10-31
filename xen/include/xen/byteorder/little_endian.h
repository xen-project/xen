#ifndef __XEN_BYTEORDER_LITTLE_ENDIAN_H__
#define __XEN_BYTEORDER_LITTLE_ENDIAN_H__

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include <xen/types.h>
#include <xen/byteorder/swab.h>

#define __constant_cpu_to_le64(x) ((__force __le64)(uint64_t)(x))
#define __constant_le64_to_cpu(x) ((__force uint64_t)(__le64)(x))
#define __constant_cpu_to_le32(x) ((__force __le32)(uint32_t)(x))
#define __constant_le32_to_cpu(x) ((__force uint32_t)(__le32)(x))
#define __constant_cpu_to_le16(x) ((__force __le16)(uint16_t)(x))
#define __constant_le16_to_cpu(x) ((__force uint16_t)(__le16)(x))
#define __constant_cpu_to_be64(x) ((__force __be64)___constant_swab64((x)))
#define __constant_be64_to_cpu(x) ___constant_swab64((__force uint64_t)(__be64)(x))
#define __constant_cpu_to_be32(x) ((__force __be32)___constant_swab32((x)))
#define __constant_be32_to_cpu(x) ___constant_swab32((__force uint32_t)(__be32)(x))
#define __constant_cpu_to_be16(x) ((__force __be16)___constant_swab16((x)))
#define __constant_be16_to_cpu(x) ___constant_swab16((__force uint16_t)(__be16)(x))
#define __cpu_to_le64(x) ((__force __le64)(uint64_t)(x))
#define __le64_to_cpu(x) ((__force uint64_t)(__le64)(x))
#define __cpu_to_le32(x) ((__force __le32)(uint32_t)(x))
#define __le32_to_cpu(x) ((__force uint32_t)(__le32)(x))
#define __cpu_to_le16(x) ((__force __le16)(uint16_t)(x))
#define __le16_to_cpu(x) ((__force uint16_t)(__le16)(x))
#define __cpu_to_be64(x) ((__force __be64)__swab64((x)))
#define __be64_to_cpu(x) __swab64((__force uint64_t)(__be64)(x))
#define __cpu_to_be32(x) ((__force __be32)__swab32((x)))
#define __be32_to_cpu(x) __swab32((__force uint32_t)(__be32)(x))
#define __cpu_to_be16(x) ((__force __be16)__swab16((x)))
#define __be16_to_cpu(x) __swab16((__force uint16_t)(__be16)(x))

static inline __le64 __cpu_to_le64p(const uint64_t *p)
{
    return (__force __le64)*p;
}
static inline uint64_t __le64_to_cpup(const __le64 *p)
{
    return (__force uint64_t)*p;
}
static inline __le32 __cpu_to_le32p(const uint32_t *p)
{
    return (__force __le32)*p;
}
static inline uint32_t __le32_to_cpup(const __le32 *p)
{
    return (__force uint32_t)*p;
}
static inline __le16 __cpu_to_le16p(const uint16_t *p)
{
    return (__force __le16)*p;
}
static inline uint16_t __le16_to_cpup(const __le16 *p)
{
    return (__force uint16_t)*p;
}
static inline __be64 __cpu_to_be64p(const uint64_t *p)
{
    return (__force __be64)__swab64p(p);
}
static inline uint64_t __be64_to_cpup(const __be64 *p)
{
    return __swab64p((const uint64_t *)p);
}
static inline __be32 __cpu_to_be32p(const uint32_t *p)
{
    return (__force __be32)__swab32p(p);
}
static inline uint32_t __be32_to_cpup(const __be32 *p)
{
    return __swab32p((const uint32_t *)p);
}
static inline __be16 __cpu_to_be16p(const uint16_t *p)
{
    return (__force __be16)__swab16p(p);
}
static inline uint16_t __be16_to_cpup(const __be16 *p)
{
    return __swab16p((const uint16_t *)p);
}
#define __cpu_to_le64s(x) do {} while (0)
#define __le64_to_cpus(x) do {} while (0)
#define __cpu_to_le32s(x) do {} while (0)
#define __le32_to_cpus(x) do {} while (0)
#define __cpu_to_le16s(x) do {} while (0)
#define __le16_to_cpus(x) do {} while (0)
#define __cpu_to_be64s(x) __swab64s((x))
#define __be64_to_cpus(x) __swab64s((x))
#define __cpu_to_be32s(x) __swab32s((x))
#define __be32_to_cpus(x) __swab32s((x))
#define __cpu_to_be16s(x) __swab16s((x))
#define __be16_to_cpus(x) __swab16s((x))

#include <xen/byteorder/generic.h>

#endif /* __XEN_BYTEORDER_LITTLE_ENDIAN_H__ */
