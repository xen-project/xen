/*
 * xen/arch/arm/arm32/debug-pl011.inc
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

/* PL011 UART initialization
 * rb: register which contains the UART base address
 * rc: scratch register 1
 * rd: scratch register 2 (unused here) */
.macro early_uart_init rb, rc, rd
        mov   \rc, #(7372800 / EARLY_PRINTK_BAUD % 16)
        str   \rc, [\rb, #FBRD]     /* -> UARTFBRD (Baud divisor fraction) */
        mov   \rc, #(7372800 / EARLY_PRINTK_BAUD / 16)
        str   \rc, [\rb, #IBRD]     /* -> UARTIBRD (Baud divisor integer) */
        mov   \rc, #0x60            /* 8n1 */
        str   \rc, [\rb, #LCR_H]     /* -> UARTLCR_H (Line control) */
        ldr   \rc, =(RXE | TXE | UARTEN)      /* RXE | TXE | UARTEN */
        str   \rc, [\rb, #CR]     /* -> UARTCR (Control Register) */
.endm

/* PL011 UART wait UART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register */
.macro early_uart_ready rb, rc
1:
        ldr   \rc, [\rb, #FR]       /* <- UARTFR (Flag register) */
        tst   \rc, #BUSY             /* Check BUSY bit */
        bne   1b                    /* Wait for the UART to be ready */
.endm

/* PL011 UART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit */
.macro early_uart_transmit rb, rt
        str   \rt, [\rb, #DR]            /* -> UARTDR (Data Register) */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
