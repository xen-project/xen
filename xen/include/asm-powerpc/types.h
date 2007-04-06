/* from xen/include/asm-x86/types.h */

#ifndef _PPC_TYPES_H
#define _PPC_TYPES_H

#include <xen/config.h>

#if defined(__ppc__)
#define BYTES_PER_LONG 4
#define BITS_PER_LONG 32
#elif defined(__PPC64__)
#define BYTES_PER_LONG 8
#define BITS_PER_LONG 64
#endif

#ifndef __ASSEMBLY__
typedef unsigned short umode_t;

/*
 * __xx is ok: it doesn't pollute the POSIX namespace. Use these in the
 * header files exported to user space
 */

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
#if defined(__ppc__)
typedef __signed__ long long __s64;
typedef unsigned long long __u64;

#elif defined(__PPC64__)
typedef __signed__ long __s64;
typedef unsigned long __u64;
#endif
#endif

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

#if defined(__ppc__)
typedef signed long long s64;
typedef unsigned long long u64;
typedef unsigned int size_t;
#elif defined(__PPC64__)
typedef signed long s64;
typedef unsigned long u64;
typedef unsigned long size_t;
#endif

typedef unsigned long paddr_t;
#define PRIpaddr "08lx"

/* DMA addresses come in generic and 64-bit flavours.  */

typedef unsigned long dma_addr_t;
typedef u64 dma64_addr_t;

typedef unsigned short xmem_bufctl_t;

typedef int bool_t;
#define test_and_set_bool(b)   xchg(&(b), 1)
#define test_and_clear_bool(b) xchg(&(b), 0)

#endif  /* __ASSEMBLY__ */
#endif
