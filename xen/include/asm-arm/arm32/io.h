/*
 *  Based on linux arch/arm/include/asm/io.h
 *
 *  Copyright (C) 1996-2000 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Modifications:
 *  16-Sep-1996        RMK     Inlined the inx/outx functions & optimised for both
 *                     constant addresses and variable addresses.
 *  04-Dec-1997        RMK     Moved a lot of this stuff to the new architecture
 *                     specific IO header files.
 *  27-Mar-1999        PJB     Second parameter of memcpy_toio is const..
 *  04-Apr-1999        PJB     Added check_signature.
 *  12-Dec-1999        RMK     More cleanups
 *  18-Jun-2000 RMK    Removed virt_to_* and friends definitions
 *  05-Oct-2004 BJD     Moved memory string functions to use void __iomem
 */
#ifndef _ARM_ARM32_IO_H
#define _ARM_ARM32_IO_H

#include <asm/system.h>

static inline uint32_t ioreadl(const volatile void __iomem *addr)
{
    uint32_t val;

    asm volatile("ldr %1, %0"
                 : "+Qo" (*(volatile uint32_t __force *)addr),
                   "=r" (val));
    dsb();

    return val;
}

static inline void iowritel(const volatile void __iomem *addr, uint32_t val)
{
    dsb();
    asm volatile("str %1, %0"
                 : "+Qo" (*(volatile uint32_t __force *)addr)
                 : "r" (val));
}

#endif /* _ARM_ARM32_IO_H */
