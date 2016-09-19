#ifndef __TYPES_H__
#define __TYPES_H__

#include <xen/stdbool.h>

#include <asm/types.h>

#define BITS_TO_LONGS(bits) \
    (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
    unsigned long name[BITS_TO_LONGS(bits)]

#ifndef NULL
#define NULL ((void*)0)
#endif

#define INT16_MIN       (-32767-1)
#define INT32_MIN       (-2147483647-1)

#define INT16_MAX       (32767)
#define INT32_MAX       (2147483647)

#define UINT16_MAX      (65535)
#define UINT32_MAX      (4294967295U)

#define INT_MAX         ((int)(~0U>>1))
#define INT_MIN         (-INT_MAX - 1)
#define UINT_MAX        (~0U)
#define LONG_MAX        ((long)(~0UL>>1))
#define LONG_MIN        (-LONG_MAX - 1)
#define ULONG_MAX       (~0UL)

/* bsd */
typedef unsigned char           u_char;
typedef unsigned short          u_short;
typedef unsigned int            u_int;
typedef unsigned long           u_long;

/* sysv */
typedef unsigned char           unchar;
typedef unsigned short          ushort;
typedef unsigned int            uint;
typedef unsigned long           ulong;

typedef         __u8            uint8_t;
typedef         __u8            u_int8_t;
typedef         __s8            int8_t;

typedef         __u16           uint16_t;
typedef         __u16           u_int16_t;
typedef         __s16           int16_t;

typedef         __u32           uint32_t;
typedef         __u32           u_int32_t;
typedef         __s32           int32_t;

typedef         __u64           uint64_t;
typedef         __u64           u_int64_t;
typedef         __s64           int64_t;

struct domain;
struct vcpu;

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

typedef unsigned int __attribute__((__mode__(__pointer__))) uintptr_t;

typedef bool bool_t;
#define test_and_set_bool(b)   xchg(&(b), true)
#define test_and_clear_bool(b) xchg(&(b), false)

#endif /* __TYPES_H__ */
