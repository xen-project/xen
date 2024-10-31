#ifndef __TYPES_H__
#define __TYPES_H__

#include <xen/stdbool.h>
#include <xen/stdint.h>

/* Linux inherited types which are being phased out */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#include <asm/types.h>

typedef __SIZE_TYPE__ size_t;

typedef signed long ssize_t;

typedef __PTRDIFF_TYPE__ ptrdiff_t;

/*
 * Users of this macro are expected to pass a positive value.
 *
 * XXX: should become an unsigned quantity
 */
#define BITS_TO_LONGS(bits) \
    (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
    unsigned long name[BITS_TO_LONGS(bits)]

#ifndef NULL
#define NULL ((void*)0)
#endif

#define INT8_MIN        (-127-1)
#define INT16_MIN       (-32767-1)
#define INT32_MIN       (-2147483647-1)

#define INT8_MAX        (127)
#define INT16_MAX       (32767)
#define INT32_MAX       (2147483647)

#define UINT8_MAX       (255)
#define UINT16_MAX      (65535)
#define UINT32_MAX      (4294967295U)

#define INT_MAX         ((int)(~0U>>1))
#define INT_MIN         (-INT_MAX - 1)
#define UINT_MAX        (~0U)
#define LONG_MAX        ((long)(~0UL>>1))
#define LONG_MIN        (-LONG_MAX - 1)
#define ULONG_MAX       (~0UL)

typedef uint16_t __le16;
typedef uint16_t __be16;
typedef uint32_t __le32;
typedef uint32_t __be32;
typedef uint64_t __le64;
typedef uint64_t __be64;

typedef unsigned int __attribute__((__mode__(__pointer__))) uintptr_t;

#define test_and_set_bool(b)   xchg(&(b), true)
#define test_and_clear_bool(b) xchg(&(b), false)

#endif /* __TYPES_H__ */
