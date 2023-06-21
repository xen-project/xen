/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __RISCV_TYPES_H__
#define __RISCV_TYPES_H__

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

#if defined(CONFIG_RISCV_32)

typedef signed long long s64;
typedef unsigned long long u64;
typedef u32 vaddr_t;
#define PRIvaddr PRIx32
typedef u64 paddr_t;
#define INVALID_PADDR (~0ULL)
#define PRIpaddr "016llx"
typedef u32 register_t;
#define PRIregister "x"

#elif defined (CONFIG_RISCV_64)

typedef signed long s64;
typedef unsigned long u64;
typedef u64 vaddr_t;
#define PRIvaddr PRIx64
typedef u64 paddr_t;
#define INVALID_PADDR (~0UL)
#define PRIpaddr "016lx"
typedef u64 register_t;
#define PRIregister "lx"

#endif

#endif /* __RISCV_TYPES_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
