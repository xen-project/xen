/*
 * xen/arch/arm/arm64/debug-imx-lpuart.inc
 *
 * i.MX8QM specific debug code
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

#include <asm/imx-lpuart.h>

/*
 * Wait LPUART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register
 */
.macro early_uart_ready xb, c
1:
        ldr   w\c, [\xb, #UARTSTAT]   /* <- Flag register */
        tst   w\c, #UARTSTAT_TDRE     /* Check FIFO EMPTY bit */
        beq   1b                      /* Wait for the UART to be ready */
.endm

/*
 * LPUART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit
 */
.macro early_uart_transmit xb, wt
        str   \wt, [\xb, #UARTDATA]  /* -> Data Register */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
