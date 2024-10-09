/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  The header taken form Linux 6.4.0-rc1 and is based on
 *  arch/riscv/include/asm/mmio.h with the following changes:
 *   - drop forcing of endianess for read*(), write*() functions as
 *     no matter what CPU endianness, what endianness a particular device
 *     (and hence its MMIO region(s)) is using is entirely independent.
 *     Hence conversion, where necessary, needs to occur at a layer up.
 *     Another one reason to drop endianess conversion is:
 *     https://patchwork.kernel.org/project/linux-riscv/patch/20190411115623.5749-3-hch@lst.de/
 *     One of the answers of the author of the commit:
 *       And we don't know if Linux will be around if that ever changes.
 *       The point is:
 *        a) the current RISC-V spec is LE only
 *        b) the current linux port is LE only except for this little bit
 *       There is no point in leaving just this bitrotting code around.  It
 *       just confuses developers, (very very slightly) slows down compiles
 *      and will bitrot.  It also won't be any significant help to a future
 *       developer down the road doing a hypothetical BE RISC-V Linux port.
 *   - drop unused argument of __io_ar() macros.
 *   - drop "#define _raw_{read,write}{b,w,l,q} _raw_{read,write}{b,w,l,q}"
 *     as they are unnecessary.
 *   - Adopt the Xen code style for this header, considering that significant
 *     changes are not anticipated in the future.
 *     In the event of any issues, adapting them to Xen style should be easily
 *     manageable.
 *   - drop unnecessary __r variables in macros read*_cpu()
 *   - update inline assembler constraints for addr argument for
 *     __raw_read{b,w,l,q} and __raw_write{b,w,l,q} to tell a compiler that
 *     *addr will be accessed.
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2014 Regents of the University of California
 * Copyright (C) 2024 Vates
 */

#ifndef ASM__RISCV__IO_H
#define ASM__RISCV__IO_H

#include <asm/byteorder.h>

/*
 * The RISC-V ISA doesn't yet specify how to query or modify PMAs, so we can't
 * change the properties of memory regions.  This should be fixed by the
 * upcoming platform spec.
 */
#define ioremap_nocache(addr, size) ioremap(addr, size)
#define ioremap_wc(addr, size) ioremap(addr, size)
#define ioremap_wt(addr, size) ioremap(addr, size)

/* Generic IO read/write.  These perform native-endian accesses. */
static inline void __raw_writeb(uint8_t val, volatile void __iomem *addr)
{
    asm volatile ( "sb %1, %0"
                   : "=m" (*(volatile uint8_t __force *)addr) : "r" (val) );
}

static inline void __raw_writew(uint16_t val, volatile void __iomem *addr)
{
    asm volatile ( "sh %1, %0"
                   : "=m" (*(volatile uint16_t __force *)addr) : "r" (val) );
}

static inline void __raw_writel(uint32_t val, volatile void __iomem *addr)
{
    asm volatile ( "sw %1, %0"
                   : "=m" (*(volatile uint32_t __force *)addr) : "r" (val) );
}

static inline void __raw_writeq(uint64_t val, volatile void __iomem *addr)
{
#ifdef CONFIG_RISCV_32
    BUILD_BUG_ON("unimplemented");
#else
    asm volatile ( "sd %1, %0"
                   : "=m" (*(volatile uint64_t __force *)addr) : "r" (val) );
#endif
}

static inline uint8_t __raw_readb(const volatile void __iomem *addr)
{
    uint8_t val;

    asm volatile ( "lb %0, %1" : "=r" (val)
                   : "m" (*(const volatile uint8_t __force *)addr) );
    return val;
}

static inline uint16_t __raw_readw(const volatile void __iomem *addr)
{
    uint16_t val;

    asm volatile ( "lh %0, %1" : "=r" (val)
                   : "m" (*(const volatile uint16_t __force *)addr) );
    return val;
}

static inline uint32_t __raw_readl(const volatile void __iomem *addr)
{
    uint32_t val;

    asm volatile ( "lw %0, %1" : "=r" (val)
                   : "m" (*(const volatile uint32_t __force *)addr) );
    return val;
}

static inline uint64_t __raw_readq(const volatile void __iomem *addr)
{
    uint64_t val;

#ifdef CONFIG_RISCV_32
    BUILD_BUG_ON("unimplemented");
#else
    asm volatile ( "ld %0, %1" : "=r" (val)
                   : "m" (*(const volatile uint64_t __force *)addr) );
#endif

    return val;
}


/*
 * Unordered I/O memory access primitives.  These are even more relaxed than
 * the relaxed versions, as they don't even order accesses between successive
 * operations to the I/O regions.
 */
#define readb_cpu(c)        __raw_readb(c)
#define readw_cpu(c)        __raw_readw(c)
#define readl_cpu(c)        __raw_readl(c)
#define readq_cpu(c)        __raw_readq(c)

#define writeb_cpu(v, c)    __raw_writeb(v, c)
#define writew_cpu(v, c)    __raw_writew(v, c)
#define writel_cpu(v, c)    __raw_writel(v, c)
#define writeq_cpu(v, c)    __raw_writeq(v, c)

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.  The memory barriers here are necessary as RISC-V
 * doesn't define any ordering between the memory space and the I/O space.
 */
#define __io_br()   do { } while (0)
#define __io_ar()   asm volatile ( "fence i,r" : : : "memory" );
#define __io_bw()   asm volatile ( "fence w,o" : : : "memory" );
#define __io_aw()   do { } while (0)

#define readb(c) ({ uint8_t  v_; __io_br(); v_ = readb_cpu(c); __io_ar(); v_; })
#define readw(c) ({ uint16_t v_; __io_br(); v_ = readw_cpu(c); __io_ar(); v_; })
#define readl(c) ({ uint32_t v_; __io_br(); v_ = readl_cpu(c); __io_ar(); v_; })
#define readq(c) ({ uint64_t v_; __io_br(); v_ = readq_cpu(c); __io_ar(); v_; })

#define writeb(v, c)    ({ __io_bw(); writeb_cpu(v, c); __io_aw(); })
#define writew(v, c)    ({ __io_bw(); writew_cpu(v, c); __io_aw(); })
#define writel(v, c)    ({ __io_bw(); writel_cpu(v, c); __io_aw(); })
#define writeq(v, c)    ({ __io_bw(); writeq_cpu(v, c); __io_aw(); })

#endif /* ASM__RISCV__IO_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
