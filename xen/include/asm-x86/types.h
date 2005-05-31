#ifndef _X86_TYPES_H
#define _X86_TYPES_H

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
#if defined(__i386__)
typedef __signed__ long long __s64;
typedef unsigned long long __u64;
#elif defined(__x86_64__)
typedef __signed__ long __s64;
typedef unsigned long __u64;
#endif
#endif

#include <xen/config.h>

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

#if defined(__i386__)
typedef signed long long s64;
typedef unsigned long long u64;
#define BITS_PER_LONG 32
typedef unsigned int size_t;
#if defined(CONFIG_X86_PAE)
typedef u64 physaddr_t;
#else
typedef u32 physaddr_t;
#endif
#elif defined(__x86_64__)
typedef signed long s64;
typedef unsigned long u64;
#define BITS_PER_LONG 64
typedef unsigned long size_t;
typedef u64 physaddr_t;
#endif

/* DMA addresses come in generic and 64-bit flavours.  */

typedef unsigned long dma_addr_t;
typedef u64 dma64_addr_t;

typedef unsigned short xmem_bufctl_t;

#endif
