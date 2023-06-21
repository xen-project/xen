#ifndef __X86_TYPES_H__
#define __X86_TYPES_H__

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

#endif /* __X86_TYPES_H__ */
