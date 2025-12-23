/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_MULDIV64_H
#define XEN_MULDIV64_H

#include <xen/stdint.h>

#if __has_include(<asm/muldiv64.h>)
# include <asm/muldiv64.h>
#endif

uint64_t attr_const generic_muldiv64(uint64_t a, uint32_t b, uint32_t c);

/*
 * Calculate a * b / c using at least 96-bit internal precision.  The
 * behaviour is undefined if the end result does not fit in a uint64_t.
 */
static inline uint64_t attr_const muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
#ifdef arch_muldiv64
    return arch_muldiv64(a, b, c);
#else
    return generic_muldiv64(a, b, c);
#endif
}

#endif /* XEN_MULDIV64_H */
