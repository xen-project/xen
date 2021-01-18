/*
 * This header can be used by architectures where unaligned accesses work
 * without faulting, and at least reasonably efficiently.  Other architectures
 * will need to have a custom asm/unaligned.h.
 */
#ifndef __ASM_UNALIGNED_H__
#error "xen/unaligned.h should not be included directly - include asm/unaligned.h instead"
#endif

#ifndef __XEN_UNALIGNED_H__
#define __XEN_UNALIGNED_H__

#include <xen/types.h>
#include <asm/byteorder.h>

#define get_unaligned(p) (*(p))
#define put_unaligned(val, p) (*(p) = (val))

static inline uint16_t get_unaligned_be16(const void *p)
{
	return be16_to_cpup(p);
}

static inline void put_unaligned_be16(uint16_t val, void *p)
{
	*(__force __be16*)p = cpu_to_be16(val);
}

static inline uint32_t get_unaligned_be32(const void *p)
{
	return be32_to_cpup(p);
}

static inline void put_unaligned_be32(uint32_t val, void *p)
{
	*(__force __be32*)p = cpu_to_be32(val);
}

static inline uint64_t get_unaligned_be64(const void *p)
{
	return be64_to_cpup(p);
}

static inline void put_unaligned_be64(uint64_t val, void *p)
{
	*(__force __be64*)p = cpu_to_be64(val);
}

static inline uint16_t get_unaligned_le16(const void *p)
{
	return le16_to_cpup(p);
}

static inline void put_unaligned_le16(uint16_t val, void *p)
{
	*(__force __le16*)p = cpu_to_le16(val);
}

static inline uint32_t get_unaligned_le32(const void *p)
{
	return le32_to_cpup(p);
}

static inline void put_unaligned_le32(uint32_t val, void *p)
{
	*(__force __le32*)p = cpu_to_le32(val);
}

static inline uint64_t get_unaligned_le64(const void *p)
{
	return le64_to_cpup(p);
}

static inline void put_unaligned_le64(uint64_t val, void *p)
{
	*(__force __le64*)p = cpu_to_le64(val);
}

#endif /* __XEN_UNALIGNED_H__ */
