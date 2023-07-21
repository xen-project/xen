/* from xen/arch/x86/include/asm/types.h */

#ifndef _ASM_PPC_TYPES_H
#define _ASM_PPC_TYPES_H

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

#endif /* _ASM_PPC_TYPES_H */
