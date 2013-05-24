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

/* PL011 UART initialization
 * rb: register which contains the UART base address
 * rc: scratch register 1
 * rd: scratch register 2 (unused here) */
.macro early_uart_init rb, rc, rd
        mov   \rc, #(7372800 / EARLY_PRINTK_BAUD % 16)
        str   \rc, [\rb, #0x28]     /* -> UARTFBRD (Baud divisor fraction) */
        mov   \rc, #(7372800 / EARLY_PRINTK_BAUD / 16)
        str   \rc, [\rb, #0x24]     /* -> UARTIBRD (Baud divisor integer) */
        mov   \rc, #0x60            /* 8n1 */
        str   \rc, [\rb, #0x2C]     /* -> UARTLCR_H (Line control) */
        ldr   \rc, =0x00000301      /* RXE | TXE | UARTEN */
        str   \rc, [\rb, #0x30]     /* -> UARTCR (Control Register) */
.endm

/* PL011 UART wait UART to be ready to transmit
 * rb: register which contains the UART base address
 * rc: scratch register */
.macro early_uart_ready rb, rc
1:
        ldr   \rc, [\rb, #0x18]     /* <- UARTFR (Flag register) */
        tst   \rc, #0x8             /* Check BUSY bit */
        bne   1b                    /* Wait for the UART to be ready */
.endm

/* PL011 UART transmit character
 * rb: register which contains the UART base address
 * rt: register which contains the character to transmit */
.macro early_uart_transmit rb, rt
        str   \rt, [\rb]            /* -> UARTDR (Data Register) */
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
