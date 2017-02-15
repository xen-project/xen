#ifndef __X86_TYPES_H__
#define __X86_TYPES_H__

#ifndef __ASSEMBLY__

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
typedef __signed__ long __s64;
typedef unsigned long __u64;
#endif

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long s64;
typedef unsigned long u64;
typedef unsigned long paddr_t;
#define INVALID_PADDR (~0UL)
#define PRIpaddr "016lx"

#if defined(__SIZE_TYPE__)
typedef __SIZE_TYPE__ size_t;
#else
typedef unsigned long size_t;
#endif
typedef signed long ssize_t;

#endif /* __ASSEMBLY__ */

#endif /* __X86_TYPES_H__ */
