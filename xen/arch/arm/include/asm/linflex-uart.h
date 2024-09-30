/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/include/asm/linflex-uart.h
 *
 * Common constant definition between early printk and the UART driver
 * for NXP LINFlexD UART.
 *
 * Andrei Cherechesu <andrei.cherechesu@nxp.com>
 * Copyright 2018, 2021, 2024 NXP
 */

#ifndef __ASM_ARM_LINFLEX_UART_H
#define __ASM_ARM_LINFLEX_UART_H

/* 32-bit register offsets */
#define LINCR1          (0x0)
#define LINIER          (0x4)
#define LINSR           (0x8)
#define UARTCR          (0x10)
#define UARTSR          (0x14)
#define LINFBRR         (0x24)
#define LINIBRR         (0x28)
#define BDRL            (0x38)
#define BDRM            (0x3C)
#define UARTPTO         (0x50)

#define LINCR1_INIT         BIT(0, U)
#define LINCR1_MME          BIT(4, U)
#define LINCR1_BF           BIT(7, U)

#define LINSR_LINS          GENMASK(15, 12)
#define LINSR_LINS_INIT     BIT(12, U)

#define LINIER_DRIE         BIT(2, U)
#define LINIER_DTIE         BIT(1, U)

#define UARTCR_UART         BIT(0, U)
#define UARTCR_WL0          BIT(1, U)
#define UARTCR_PC0          BIT(3, U)
#define UARTCR_TXEN         BIT(4, U)
#define UARTCR_RXEN         BIT(5, U)
#define UARTCR_PC1          BIT(6, U)
#define UARTCR_TFBM         BIT(8, U)
#define UARTCR_RFBM         BIT(9, U)
#define UARTCR_RDFLRFC      GENMASK(12, 10)
#define UARTCR_TDFLTFC      GENMASK(15, 13)
#define UARTCR_ROSE         BIT(23, U)
#define UARTCR_OSR_SHIFT    (24)
#define UARTCR_OSR          GENMASK(27, UARTCR_OSR_SHIFT)

#define UARTSR_DTFTFF       BIT(1, U)
#define UARTSR_DRFRFE       BIT(2, U)

#endif /* __ASM_ARM_LINFLEX_UART_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
