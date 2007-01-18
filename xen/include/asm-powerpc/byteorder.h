#ifndef _ASM_POWERPC_BYTEORDER_H
#define _ASM_POWERPC_BYTEORDER_H

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <asm/types.h>
#include <xen/compiler.h>

static inline __u16 ld_le16(const volatile __u16 *addr)
{
    __u16 val;

    asm volatile ("lhbrx %0,0,%1" : "=r" (val) : "r" (addr), "m" (*addr));
    return val;
}

static inline void st_le16(volatile __u16 *addr, const __u16 val)
{
    asm volatile ("sthbrx %1,0,%2" : "=m" (*addr) : "r" (val), "r" (addr));
}

static inline __u32 ld_le32(const volatile __u32 *addr)
{
    __u32 val;

    asm volatile ("lwbrx %0,0,%1" : "=r" (val) : "r" (addr), "m" (*addr));
    return val;
}

static inline void st_le32(volatile __u32 *addr, const __u32 val)
{
    asm volatile ("stwbrx %1,0,%2" : "=m" (*addr) : "r" (val), "r" (addr));
}

static inline __attribute_const__ __u16 ___arch__swab16(__u16 value)
{
    __u16 result;

    asm("rlwimi %0,%1,8,16,23"
        : "=r" (result)
        : "r" (value), "0" (value >> 8));
    return result;
}

static inline __attribute_const__ __u32 ___arch__swab32(__u32 value)
{
    __u32 result;

    asm("rlwimi %0,%1,24,16,23\n\t"
        "rlwimi %0,%1,8,8,15\n\t"
        "rlwimi %0,%1,24,0,7"
        : "=r" (result)
        : "r" (value), "0" (value >> 24));
    return result;
}

#define __arch__swab16(x) ___arch__swab16(x)
#define __arch__swab32(x) ___arch__swab32(x)

/* The same, but returns converted value from the location pointer by addr. */
#define __arch__swab16p(addr) ld_le16(addr)
#define __arch__swab32p(addr) ld_le32(addr)

/* The same, but do the conversion in situ, ie. put the value back to addr. */
#define __arch__swab16s(addr) st_le16(addr,*addr)
#define __arch__swab32s(addr) st_le32(addr,*addr)

#define __BYTEORDER_HAS_U64__
#ifndef __powerpc64__
#define __SWAB_64_THRU_32__
#endif /* __powerpc64__ */

#include <xen/byteorder/big_endian.h>

#endif /* _ASM_POWERPC_BYTEORDER_H */
