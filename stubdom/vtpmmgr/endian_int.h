#ifndef __VTPMMGR_ENDIAN_INT_H
#define __VTPMMGR_ENDIAN_INT_H

#include <mini-os/byteorder.h>

/* These wrapper structs force the use of endian-to-CPU conversions */

typedef struct be_int16 {
	uint16_t value;
} be16_t;

typedef struct be_int32 {
	uint32_t value;
} be32_t;

typedef struct le_int32 {
	uint32_t value;
} le32_t;

typedef struct be_int64 {
	uint64_t value;
} be64_t;

static inline uint16_t be16_native(be16_t v)
{
	return be16_to_cpu(v.value);
}

static inline uint32_t le32_native(le32_t v)
{
	return le32_to_cpu(v.value);
}

static inline uint32_t be32_native(be32_t v)
{
	return be32_to_cpu(v.value);
}

static inline uint64_t be64_native(be64_t v)
{
	return be64_to_cpu(v.value);
}

static inline be16_t native_be16(uint16_t v)
{
	be16_t rv;
	rv.value = cpu_to_be16(v);
	return rv;
}

static inline le32_t native_le32(uint32_t v)
{
	le32_t rv;
	rv.value = cpu_to_le32(v);
	return rv;
}

static inline be32_t native_be32(uint32_t v)
{
	be32_t rv;
	rv.value = cpu_to_be32(v);
	return rv;
}

static inline be64_t native_be64(uint64_t v)
{
	be64_t rv;
	rv.value = cpu_to_be64(v);
	return rv;
}

#endif
