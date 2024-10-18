/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __XEN_UNALIGNED_H__
#define __XEN_UNALIGNED_H__

#ifdef __XEN__
#include <xen/types.h>
#include <asm/byteorder.h>
#endif

/*
 * This is the most generic implementation of unaligned accesses
 * and should work almost anywhere.
 */

#define get_unaligned_t(type, ptr) ({					\
	const struct { type x; } __packed *ptr_ = (typeof(ptr_))(ptr);	\
	ptr_->x;							\
})

#define put_unaligned_t(type, val, ptr) do {				\
	struct { type x; } __packed *ptr_ = (typeof(ptr_))(ptr);	\
	ptr_->x = (val);						\
} while (0)

#define get_unaligned(ptr)	get_unaligned_t(typeof(*(ptr)), ptr)
#define put_unaligned(val, ptr) put_unaligned_t(typeof(*(ptr)), val, ptr)

static inline uint16_t get_unaligned_be16(const void *p)
{
	return be16_to_cpu(get_unaligned_t(__be16, p));
}

static inline void put_unaligned_be16(uint16_t val, void *p)
{
	put_unaligned_t(__be16, cpu_to_be16(val), p);
}

static inline uint32_t get_unaligned_be32(const void *p)
{
	return be32_to_cpu(get_unaligned_t(__be32, p));
}

static inline void put_unaligned_be32(uint32_t val, void *p)
{
	put_unaligned_t(__be32, cpu_to_be32(val), p);
}

static inline uint64_t get_unaligned_be64(const void *p)
{
	return be64_to_cpu(get_unaligned_t(__be64, p));
}

static inline void put_unaligned_be64(uint64_t val, void *p)
{
	put_unaligned_t(__be64, cpu_to_be64(val), p);
}

static inline uint16_t get_unaligned_le16(const void *p)
{
	return le16_to_cpu(get_unaligned_t(__le16, p));
}

static inline void put_unaligned_le16(uint16_t val, void *p)
{
	put_unaligned_t(__le16, cpu_to_le16(val), p);
}

static inline uint32_t get_unaligned_le32(const void *p)
{
	return le32_to_cpu(get_unaligned_t(__le32, p));
}

static inline void put_unaligned_le32(uint32_t val, void *p)
{
	put_unaligned_t(__le32, cpu_to_le32(val), p);
}

static inline uint64_t get_unaligned_le64(const void *p)
{
	return le64_to_cpu(get_unaligned_t(__le64, p));
}

static inline void put_unaligned_le64(uint64_t val, void *p)
{
	put_unaligned_t(__le64, cpu_to_le64(val), p);
}

#endif /* __XEN_UNALIGNED_H__ */
