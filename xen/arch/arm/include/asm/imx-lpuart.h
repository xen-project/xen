/*
 * xen/arch/arm/include/asm/imx-lpuart.h
 *
 * Common constant definition between early printk and the LPUART driver
 *
 * Peng Fan <peng.fan@nxp.com>
 * Copyright 2022 NXP
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

#ifndef __ASM_ARM_IMX_LPUART_H__
#define __ASM_ARM_IMX_LPUART_H__

/* 32-bit register definition */
#define UARTBAUD          (0x10)
#define UARTSTAT          (0x14)
#define UARTCTRL          (0x18)
#define UARTDATA          (0x1C)
#define UARTMATCH         (0x20)
#define UARTMODIR         (0x24)
#define UARTFIFO          (0x28)
#define UARTWATER         (0x2c)

#define UARTSTAT_TDRE     BIT(23, UL)
#define UARTSTAT_TC       BIT(22, UL)
#define UARTSTAT_RDRF     BIT(21, UL)
#define UARTSTAT_OR       BIT(19, UL)

#define UARTBAUD_OSR_SHIFT    (24)
#define UARTBAUD_OSR_MASK     (0x1f)
#define UARTBAUD_SBR_MASK     (0x1fff)
#define UARTBAUD_BOTHEDGE     (0x00020000)
#define UARTBAUD_TDMAE        (0x00800000)
#define UARTBAUD_RDMAE        (0x00200000)

#define UARTCTRL_TIE      BIT(23, UL)
#define UARTCTRL_TCIE     BIT(22, UL)
#define UARTCTRL_RIE      BIT(21, UL)
#define UARTCTRL_ILIE     BIT(20, UL)
#define UARTCTRL_TE       BIT(19, UL)
#define UARTCTRL_RE       BIT(18, UL)
#define UARTCTRL_M        BIT(4, UL)

#define UARTWATER_RXCNT_OFF     24

#endif /* __ASM_ARM_IMX_LPUART_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
