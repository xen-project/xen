/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IO related routines.
 *
 * Copyright (c) 2025 Cloud Software Group
 */
#ifndef XEN_IO_H
#define XEN_IO_H

#include <xen/bug.h>

#include <asm/io.h>

static inline unsigned long read_mmio(const volatile void __iomem *mem,
                                      unsigned int size)
{
    switch ( size )
    {
    case 1:
        return readb(mem);

    case 2:
        return readw(mem);

    case 4:
        return readl(mem);

#ifdef CONFIG_64BIT
    case 8:
        return readq(mem);
#endif

    default:
        ASSERT_UNREACHABLE();
        return ~0UL;
    }
}

static inline bool write_mmio(volatile void __iomem *mem, unsigned long data,
                              unsigned int size)
{
    switch ( size )
    {
    case 1:
        writeb(data, mem);
        break;

    case 2:
        writew(data, mem);
        break;

    case 4:
        writel(data, mem);
        break;

#ifdef CONFIG_64BIT
    case 8:
        writeq(data, mem);
        break;
#endif

    default:
        ASSERT_UNREACHABLE();
        return false;
    }

    return true;
}

#endif /* XEN_IO_H */
