/*
 * xen/arch/arm/arm64/debug-pl011.inc
 *
 * PL011 specific debug code
 *
 * Copyright (c) 2013 Citrix Systems.
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

 #include <asm/pl011-uart.h>

/*
 * PL011 UART initialization
 * xb: register which containts the UART base address
 * c: scratch register number
 */
.macro early_uart_init xb, c
        mov   x\c, #(7372800 / CONFIG_EARLY_UART_PL011_BAUD_RATE % 16)
        PL011_STRB  w\c, [\xb, #FBRD]  /* -> UARTFBRD (Baud divisor fraction) */
        mov   x\c, #(7372800 / CONFIG_EARLY_UART_PL011_BAUD_RATE / 16)
        PL011_STRH  w\c, [\xb, #IBRD]  /* -> UARTIBRD (Baud divisor integer) */
        mov   x\c, #WLEN_8           /* 8n1 */
        PL011_STRB  w\c, [\xb, #LCR_H] /* -> UARTLCR_H (Line control) */
        ldr   x\c, =(RXE | TXE | UARTEN)
        PL011_STRH  w\c, [\xb, #CR]    /* -> UARTCR (Control Register) */
.endm

/*
 * PL011 UART wait UART to be ready to transmit
 * xb: register which contains the UART base address
 * c: scratch register number
 */
.macro early_uart_ready xb, c
1:
        PL011_LDRH  w\c, [\xb, #FR]  /* <- UARTFR (Flag register) */
        tst   w\c, #BUSY             /* Check BUSY bit */
        b.ne  1b                     /* Wait for the UART to be ready */
.endm

/*
 * PL011 UART transmit character
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb, wt
        PL011_STRB  \wt, [\xb, #DR]  /* -> UARTDR (Data Register) */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
