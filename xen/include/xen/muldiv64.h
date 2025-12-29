/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_MULDIV64_H
#define XEN_MULDIV64_H

#include <xen/stdint.h>

uint64_t attr_const generic_muldiv64(uint64_t a, uint32_t b, uint32_t c);

/*
 * Calculate a * b / c using at least 96-bit internal precision.  The
 * behaviour is undefined if the end result does not fit in a uint64_t.
 */
static inline uint64_t attr_const muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
    return generic_muldiv64(a, b, c);
}

#endif /* XEN_MULDIV64_H */
