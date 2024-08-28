/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * Copyright (c) 2021-2022 Citrix Systems Ltd.
 */
#ifndef XEN_ASM_ENDBR_H
#define XEN_ASM_ENDBR_H

#include <xen/types.h>

#define ENDBR64_LEN 4

/*
 * In some cases we need to inspect/insert endbr64 instructions.
 *
 * The naive way, mem{cmp,cpy}(ptr, "\xf3\x0f\x1e\xfa", 4), optimises unsafely
 * by placing 0xfa1e0ff3 in an imm32 operand, and marks a legal indirect
 * branch target as far as the CPU is concerned.
 *
 * gen_endbr64() is written deliberately to avoid the problematic operand, and
 * marked __const__ as it is safe for the optimiser to hoist/merge/etc.
 */
static inline uint32_t attr_const gen_endbr64(void)
{
    uint32_t res;

    asm ( "mov $~0xfa1e0ff3, %[res]\n\t"
          "not %[res]\n\t"
          : [res] "=&r" (res) );

    return res;
}

static inline bool is_endbr64(const void *ptr)
{
    return *(const uint32_t *)ptr == gen_endbr64();
}

static inline void place_endbr64(void *ptr)
{
    *(uint32_t *)ptr = gen_endbr64();
}

/*
 * After clobbering ENDBR64, we may need to confirm that the site used to
 * contain an ENDBR64 instruction.  Use an encoding which isn't the default
 * P6_NOP4.  Specifically, nopw (%rcx)
 */
static inline uint32_t attr_const gen_endbr64_poison(void)
{
    uint32_t res;

    asm ( "mov $~0x011f0f66, %[res]\n\t"
          "not %[res]\n\t"
          : [res] "=&r" (res) );

    return res;
}

static inline bool is_endbr64_poison(const void *ptr)
{
    return *(const uint32_t *)ptr == gen_endbr64_poison();
}

static inline void place_endbr64_poison(void *ptr)
{
    *(uint32_t *)ptr = gen_endbr64_poison();
}

#endif /* XEN_ASM_ENDBR_H */
