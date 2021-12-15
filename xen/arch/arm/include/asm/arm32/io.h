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
#include <asm/byteorder.h>

static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
        asm volatile("strb %1, %0"
                     : "+Qo" (*(volatile u8 __force *)addr)
                     : "r" (val));
}

static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
        asm volatile("strh %1, %0"
                     : "+Q" (*(volatile u16 __force *)addr)
                     : "r" (val));
}

static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
        asm volatile("str %1, %0"
                     : "+Qo" (*(volatile u32 __force *)addr)
                     : "r" (val));
}

static inline u8 __raw_readb(const volatile void __iomem *addr)
{
        u8 val;
        asm volatile("ldrb %1, %0"
                     : "+Qo" (*(volatile u8 __force *)addr),
                       "=r" (val));
        return val;
}

static inline u16 __raw_readw(const volatile void __iomem *addr)
{
        u16 val;
        asm volatile("ldrh %1, %0"
                     : "+Q" (*(volatile u16 __force *)addr),
                       "=r" (val));
        return val;
}

static inline u32 __raw_readl(const volatile void __iomem *addr)
{
        u32 val;
        asm volatile("ldr %1, %0"
                     : "+Qo" (*(volatile u32 __force *)addr),
                       "=r" (val));
        return val;
}

#define __iormb()               rmb()
#define __iowmb()               wmb()

#define readb_relaxed(c) ({ u8  __r = __raw_readb(c); __r; })
#define readw_relaxed(c) ({ u16 __r = le16_to_cpu((__force __le16) \
                                        __raw_readw(c)); __r; })
#define readl_relaxed(c) ({ u32 __r = le32_to_cpu((__force __le32) \
                                        __raw_readl(c)); __r; })

#define writeb_relaxed(v,c)     __raw_writeb(v,c)
#define writew_relaxed(v,c)     __raw_writew((__force u16) cpu_to_le16(v),c)
#define writel_relaxed(v,c)     __raw_writel((__force u32) cpu_to_le32(v),c)

#define readb(c)                ({ u8  __v = readb_relaxed(c); __iormb(); __v; })
#define readw(c)                ({ u16 __v = readw_relaxed(c); __iormb(); __v; })
#define readl(c)                ({ u32 __v = readl_relaxed(c); __iormb(); __v; })

#define writeb(v,c)             ({ __iowmb(); writeb_relaxed(v,c); })
#define writew(v,c)             ({ __iowmb(); writew_relaxed(v,c); })
#define writel(v,c)             ({ __iowmb(); writel_relaxed(v,c); })

#endif /* _ARM_ARM32_IO_H */
