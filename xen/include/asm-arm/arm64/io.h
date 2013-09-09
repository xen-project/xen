/*
 * Based on linux arch/arm64/include/asm/io.h which is in turn
 * Based on arch/arm/include/asm/io.h
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _ARM_ARM64_IO_H
#define _ARM_ARM64_IO_H

#include <asm/byteorder.h>

/*
 * Generic IO read/write.  These perform native-endian accesses.
 */
static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
        asm volatile("strb %w0, [%1]" : : "r" (val), "r" (addr));
}

static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
        asm volatile("strh %w0, [%1]" : : "r" (val), "r" (addr));
}

static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
        asm volatile("str %w0, [%1]" : : "r" (val), "r" (addr));
}

static inline void __raw_writeq(u64 val, volatile void __iomem *addr)
{
        asm volatile("str %0, [%1]" : : "r" (val), "r" (addr));
}

static inline u8 __raw_readb(const volatile void __iomem *addr)
{
        u8 val;
        asm volatile("ldrb %w0, [%1]" : "=r" (val) : "r" (addr));
        return val;
}

static inline u16 __raw_readw(const volatile void __iomem *addr)
{
        u16 val;
        asm volatile("ldrh %w0, [%1]" : "=r" (val) : "r" (addr));
        return val;
}

static inline u32 __raw_readl(const volatile void __iomem *addr)
{
        u32 val;
        asm volatile("ldr %w0, [%1]" : "=r" (val) : "r" (addr));
        return val;
}

static inline u64 __raw_readq(const volatile void __iomem *addr)
{
        u64 val;
        asm volatile("ldr %0, [%1]" : "=r" (val) : "r" (addr));
        return val;
}

/* IO barriers */
#define __iormb()               rmb()
#define __iowmb()               wmb()

#define mmiowb()                do { } while (0)

/*
 * Relaxed I/O memory access primitives. These follow the Device memory
 * ordering rules but do not guarantee any ordering relative to Normal memory
 * accesses.
 */
#define readb_relaxed(c)        ({ u8  __v = __raw_readb(c); __v; })
#define readw_relaxed(c)        ({ u16 __v = le16_to_cpu((__force __le16)__raw_readw(c)); __v; })
#define readl_relaxed(c)        ({ u32 __v = le32_to_cpu((__force __le32)__raw_readl(c)); __v; })
#define readq_relaxed(c)        ({ u64 __v = le64_to_cpu((__force __le64)__raw_readq(c)); __v; })

#define writeb_relaxed(v,c)     ((void)__raw_writeb((v),(c)))
#define writew_relaxed(v,c)     ((void)__raw_writew((__force u16)cpu_to_le16(v),(c)))
#define writel_relaxed(v,c)     ((void)__raw_writel((__force u32)cpu_to_le32(v),(c)))
#define writeq_relaxed(v,c)     ((void)__raw_writeq((__force u64)cpu_to_le64(v),(c)))

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.
 */
#define readb(c)                ({ u8  __v = readb_relaxed(c); __iormb(); __v; })
#define readw(c)                ({ u16 __v = readw_relaxed(c); __iormb(); __v; })
#define readl(c)                ({ u32 __v = readl_relaxed(c); __iormb(); __v; })
#define readq(c)                ({ u64 __v = readq_relaxed(c); __iormb(); __v; })

#define writeb(v,c)             ({ __iowmb(); writeb_relaxed((v),(c)); })
#define writew(v,c)             ({ __iowmb(); writew_relaxed((v),(c)); })
#define writel(v,c)             ({ __iowmb(); writel_relaxed((v),(c)); })
#define writeq(v,c)             ({ __iowmb(); writeq_relaxed((v),(c)); })

#endif /* _ARM_ARM64_IO_H */
