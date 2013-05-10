/*
 * Based on linux arch/arm64/include/asm/io.h
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

static inline uint32_t ioreadl(const volatile void __iomem *addr)
{
    uint32_t val;

    asm volatile("ldr %w0, [%1]" : "=r" (val) : "r" (addr));
    dsb();

    return val;
}

static inline void iowritel(const volatile void __iomem *addr, uint32_t val)
{
    dsb();
    asm volatile("str %w0, [%1]" : : "r" (val), "r" (addr));
}

#endif /* _ARM_ARM64_IO_H */
