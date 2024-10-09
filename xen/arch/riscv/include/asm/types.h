/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__TYPES_H
#define ASM__RISCV__TYPES_H

#if defined(CONFIG_RISCV_32)

typedef u32 vaddr_t;
#define PRIvaddr PRIx32
typedef u64 paddr_t;
#define INVALID_PADDR (~0ULL)
#define PRIpaddr "016llx"
typedef u32 register_t;
#define PRIregister "x"

#elif defined (CONFIG_RISCV_64)

typedef u64 vaddr_t;
#define PRIvaddr PRIx64
typedef u64 paddr_t;
#define INVALID_PADDR (~0UL)
#define PRIpaddr "016lx"
typedef u64 register_t;
#define PRIregister "lx"

#endif

#endif /* ASM__RISCV__TYPES_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
