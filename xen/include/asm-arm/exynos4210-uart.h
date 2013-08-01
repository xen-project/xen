/*
 * xen/include/asm-arm/exynos4210-uart.h
 *
 * Common constant definition between early printk and the UART driver
 * for the exynos 4210 UART
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2013 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ASM_ARM_EXYNOS4210_H
#define __ASM_ARM_EXYNOS4210_H


/*
 * this value is only valid for UART 2 and UART 3
 * XXX: define per UART
 */
#define FIFO_MAX_SIZE 16

/* register addresses */
#define ULCON     (0x00)
#define UCON      (0x04)
#define UFCON     (0x08)
#define UMCON     (0x0c)
#define UTRSTAT   (0x10)
#define UERSTAT   (0x14)
#define UFSTAT    (0x18)
#define UMSTAT    (0x1c)
#define UTXH      (0x20)
#define URXH      (0x24)
#define UBRDIV    (0x28)
#define UFRACVAL  (0x2c)
#define UINTP     (0x30)
#define UINTS     (0x34)
#define UINTM     (0x38)

/* UCON */
#define UCON_RX_IRQ         (1 << 0)
#define UCON_TX_IRQ         (1 << 2)
#define UCON_RX_TIMEOUT     (1 << 7)

/*
 * FIXME: IRQ_LEVEL should be 1 << n but with this value, the IRQ
 * handler will never end...
 */
#define UCON_RX_IRQ_LEVEL   (0 << 8)
#define UCON_TX_IRQ_LEVEL   (0 << 9)

/* ULCON */
#define ULCON_STOPB_SHIFT 2
#define ULCON_PARITY_SHIFT 3

/* UFCON */
#define UFCON_FIFO_TX_RESET     (1 << 2)
#define UFCON_FIFO_RX_RESET     (1 << 1)
#define UFCON_FIFO_RESET        (UFCON_FIFO_TX_RESET | UFCON_FIFO_RX_RESET)
#define UFCON_FIFO_EN           (1 << 0)

#define UFCON_FIFO_TX_TRIGGER   (0x6 << 8)

/* UMCON */
#define UMCON_INT_EN            (1 << 3)

/* UERSTAT */
#define UERSTAT_OVERRUN (1 << 0)
#define UERSTAT_PARITY  (1 << 1)
#define UERSTAT_FRAME   (1 << 2)
#define UERSTAT_BREAK   (1 << 3)

/* UFSTAT */
#define UFSTAT_TX_FULL          (1 << 24)
#define UFSTAT_TX_COUNT_SHIFT   (16)
#define UFSTAT_TX_COUNT_MASK    (0xff << UFSTAT_TX_COUNT_SHIFT)
#define UFSTAT_RX_FULL          (1 << 8)
#define UFSTAT_RX_COUNT_SHIFT   (0)
#define UFSTAT_RX_COUNT_MASK    (0xff << UFSTAT_RX_COUNT_SHIFT)

/* UTRSTAT */
#define UTRSTAT_TXFE            (1 << 1)
#define UTRSTAT_TXE             (1 << 2)

/* URHX */
#define URXH_DATA_MASK  (0xff)

/* Interrupt bits (UINTP, UINTS, UINTM) */
#define UINTM_MODEM     (1 << 3)
#define UINTM_TXD       (1 << 2)
#define UINTM_ERROR     (1 << 1)
#define UINTM_RXD       (1 << 0)
#define UINTM_ALLI      (UINTM_MODEM | UINTM_TXD | UINTM_ERROR | UINTM_RXD)

#endif /* __ASM_ARM_EXYNOS4210_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
