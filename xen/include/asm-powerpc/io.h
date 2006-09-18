/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#ifndef _ASM_IO_H_
#define _ASM_IO_H_

#include <xen/types.h>
#include <asm/processor.h>

#define IO_SPACE_LIMIT 0xffff

extern unsigned int watchdog_on;
extern ulong isa_io_base;

#define inb(port)       in_8((void *)((ulong)(port) + isa_io_base))
#define outb(val, port) out_8((void *)((ulong)(port) + isa_io_base), val)
#define inw(port)       in_le16((void *)((ulong)(port) + isa_io_base))
#define outw(val, port) out_le16((void *)((ulong)(port) + isa_io_base), val)
#define inl(port)       in_le32((void *)((ulong)(port) + isa_io_base))
#define outl(val, port) out_le32((void *)((ulong)(port) + isa_io_base), val)

#define ioremap(x,l) (void __iomem *)(x)
#define readb(port) in_8((void *)(port))
#define writeb(val, port) out_8((void *)(port), val)

extern char *vgabase;
#define vga_writeb(val, port) out_8((void *)((ulong)(port) + vgabase), val)

extern u8 in_8(const volatile u8 *addr);
extern void out_8(volatile u8 *addr, int val);
extern u32 in_32(const volatile u32 *addr);
extern void out_32(volatile u32 *addr, int val);
extern int in_le16(const volatile unsigned short *addr);
extern void out_le16(volatile unsigned short *addr, int val);
extern unsigned in_le32(const volatile unsigned *addr);
extern void out_le32(volatile unsigned *addr, int val);

#define in_be8 in_8
#define in_be16 in_16
#define in_be32 in_32
#define out_be8 out_8
#define out_be16 out_16
#define out_be32 out_32

#define readw(port) in_le16((void *)(port))
#define readl(port) in_le32((void *)(port))
#define writew(val, port) out_le16((void *)(port), val)
#define writel(val, port) out_le32((void *)(port), val)

#define barrier() __asm__ __volatile__("": : :"memory")

#endif
