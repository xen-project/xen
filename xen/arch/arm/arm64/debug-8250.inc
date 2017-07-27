/*
 * xen/arch/arm/arm64/debug-8250.inc
 *
 * 8250 specific debug code
 *
 * Copyright (c) 2013 Applied Micro.
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

/*
 * UART wait UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register
 */
.macro early_uart_ready xb c
1:
       ldrb  w\c, [\xb, #UART_LSR << EARLY_UART_REG_SHIFT]
       and w\c, w\c, #UART_LSR_THRE
       cmp w\c, #UART_LSR_THRE
       b.ne 1b
.endm

/*
 * UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb wt
        /* UART_THR  transmit holding */
        strb   \wt, [\xb, #UART_THR << EARLY_UART_REG_SHIFT]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
