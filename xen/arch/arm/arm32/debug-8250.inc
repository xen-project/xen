/*
 * xen/arch/arm/arm32/debug-8250.inc
 *
 * 8250 specific debug code
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

#include <xen/8250-uart.h>

/* 8250 UART wait UART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register */
.macro early_uart_ready rb rc
1:
        ldr     \rc, [\rb, #(UART_LSR << EARLY_UART_REG_SHIFT)] /* Read LSR */
        tst     \rc, #UART_LSR_THRE     /* Check Xmit holding register flag */
        beq     1b                         /* Wait for the UART to be ready */
.endm

/* 8250 UART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit */
.macro early_uart_transmit rb rt
        str   \rt, [\rb, #UART_THR]      /* Write Transmit buffer */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
